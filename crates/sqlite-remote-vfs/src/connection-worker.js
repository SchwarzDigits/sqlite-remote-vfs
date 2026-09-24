// Connection worker: holds the WebSocket and the IndexedDB local copy, and serves requests from the SQLite worker.
//
// The SQLite worker runs inside synchronous SQLite calls and cannot await anything. It writes a request to shared
// memory, sets the REQUEST slot and blocks in Atomics.wait until this worker has written the answer. Together, the
// shared memory and the slots form the bridge between the two workers.
//
// Requests are signalled only through the REQUEST slot, as SQLite's OPFS VFS does, never with postMessage. In Chrome,
// a message posted by a worker that then blocks in Atomics.wait is not delivered.
//
// This worker waits on the REQUEST slot with Atomics.waitAsync, which does not block its event loop. The WebSocket
// needs that event loop. Browsers without Atomics.waitAsync (e.g. Firefox 140 ESR) poll the slot every millisecond.
//
// Shared memory layout: the control slots, then a request region and an answer region of equal size. This worker only
// reads the request region and only writes the answer region. A frame from the server can arrive while the SQLite
// worker is still writing a request, so the two cannot share one region.
"use strict";

const STATE = 0; // connection state: 0 connecting, 1 open, 2 failed
const ANSWER = 1; // answer counter; the SQLite worker waits for it to change
const KIND = 2; // type of the answer (KIND_*)
const LENGTH = 3; // number of answer bytes in the answer region
const REQUEST = 4; // set to 1 by the SQLite worker when a request is ready; cleared by this worker
const OP = 5; // requested operation (OP_*)
const REQUEST_LENGTH = 6; // number of request bytes in the request region

const STATE_OPEN = 1;
const STATE_FAILED = 2;
const KIND_FRAME = 1;
const KIND_ERROR = 2;
const KIND_DONE = 3;
const KIND_NOTHING = 4; // the local copy does not have the requested data

const OP_SEND = 1;
const OP_RECEIVE = 2;
const OP_REOPEN = 3;
const OP_CLOSE = 4;
// Local copy operations. The local copy is kept in this worker because IndexedDB is asynchronous, like the
// WebSocket, and the SQLite worker cannot await.
const OP_COPY_HEAD = 5;
const OP_COPY_READ = 6;
const OP_COPY_WRITE = 7;
const OP_COPY_CLEAR = 8;
const OP_COPY_FORGET = 9;
const OP_COPY_SELECT = 10;

const encoder = new TextEncoder();

let control = null;
let request = null;
let answer = null;
let url = null;
let socket = null;
let closed = false;

// Local copy: one IndexedDB database per database name, named copyPrefix + "/" + name, with a "blocks" store keyed
// by block index and a "head" store. Both are written in one transaction, so the head always matches the blocks.
// OP_COPY_SELECT chooses the database the other operations work on.
let copyPrefix = null;
let copyName = null;
let copy = null;
let pending = [];
let chain = Promise.resolve();
// Copies for which clearing after a failed write also failed. They are never read again.
const givenUp = new Set();

// Frames received before the SQLite worker asked for them, and the first connection error, which is returned for
// every later request.
let queued = [];
let waiting = false;
let failure = null;

function put(kind, bytes) {
  const length = bytes === null ? 0 : Math.min(bytes.length, answer.length);
  if (length > 0) {
    answer.set(bytes.subarray(0, length));
  }
  Atomics.store(control, LENGTH, length);
  Atomics.store(control, KIND, kind);
  Atomics.add(control, ANSWER, 1);
  Atomics.notify(control, ANSWER);
}

// If the SQLite worker is waiting, answers with the next queued frame or with the connection error. Called when a
// frame arrives and when a receive request comes in, because either can happen first.
function deliver() {
  if (!waiting) {
    return;
  }
  if (queued.length > 0) {
    waiting = false;
    put(KIND_FRAME, queued.shift());
  } else if (failure !== null) {
    waiting = false;
    put(KIND_ERROR, encoder.encode(failure));
  }
}

function fail(message) {
  if (closed) {
    return;
  }
  if (failure === null) {
    failure = message;
  }
  // A failure before the connection is open must end the SQLite worker's wait on the STATE slot.
  if (Atomics.load(control, STATE) === 0) {
    const bytes = encoder.encode(failure);
    const length = Math.min(bytes.length, answer.length);
    answer.set(bytes.subarray(0, length));
    Atomics.store(control, LENGTH, length);
    Atomics.store(control, STATE, STATE_FAILED);
    Atomics.notify(control, STATE);
    return;
  }
  deliver();
}

function connect() {
  queued = [];
  failure = null;
  Atomics.store(control, STATE, 0);
  try {
    socket = new WebSocket(url);
  } catch (error) {
    fail("cannot open " + url + ": " + error);
    return;
  }
  socket.binaryType = "arraybuffer";
  socket.onopen = () => {
    Atomics.store(control, STATE, STATE_OPEN);
    Atomics.notify(control, STATE);
  };
  socket.onmessage = (event) => {
    queued.push(new Uint8Array(event.data));
    deliver();
  };
  socket.onerror = () => fail("the connection failed");
  socket.onclose = (event) => fail("connection closed: " + event.code + " " + event.reason);
}

function drop() {
  if (socket !== null) {
    socket.onclose = null;
    socket.onerror = null;
    socket.onmessage = null;
    socket.close();
    socket = null;
  }
}

function work() {
  const op = Atomics.load(control, OP);
  switch (op) {
    case OP_SEND:
      if (socket === null || socket.readyState !== WebSocket.OPEN) {
        put(KIND_ERROR, encoder.encode(failure === null ? "not connected" : failure));
        break;
      }
      try {
        // slice() copies the bytes: WebSocket.send does not accept a view on shared memory.
        socket.send(request.slice(0, Atomics.load(control, REQUEST_LENGTH)));
        put(KIND_DONE, null);
      } catch (error) {
        put(KIND_ERROR, encoder.encode("send failed: " + error));
      }
      break;

    case OP_RECEIVE:
      waiting = true;
      deliver();
      break;

    case OP_REOPEN:
      drop();
      connect();
      put(KIND_DONE, null);
      break;

    case OP_CLOSE:
      closed = true;
      waiting = false;
      drop();
      put(KIND_DONE, null);
      break;

    // Local copy operations run one after another in request order, so a read never overtakes an earlier write.
    case OP_COPY_HEAD:
      queue(async () => {
        const head = await copyHead();
        put(head === null ? KIND_NOTHING : KIND_FRAME, head === null ? null : headBytes(head));
      });
      break;

    case OP_COPY_READ: {
      const view = new DataView(request.buffer, request.byteOffset, 16);
      const first = Number(view.getBigUint64(0, true));
      const count = Number(view.getBigUint64(8, true));
      queue(async () => {
        // The result can contain fewer blocks than requested. It starts with the block size, followed by the blocks.
        const blocks = await copyRead(first, count);
        if (blocks.length === 0) {
          put(KIND_NOTHING, null);
          return;
        }
        const size = blocks[0].length;
        const bytes = new Uint8Array(4 + size * blocks.length);
        new DataView(bytes.buffer).setUint32(0, size, true);
        let at = 4;
        for (const block of blocks) {
          bytes.set(block, at);
          at += size;
        }
        put(KIND_FRAME, bytes);
      });
      break;
    }

    case OP_COPY_WRITE: {
      // The blocks are copied out of shared memory and the answer is sent at once. They are written to IndexedDB
      // afterwards: the server has already acknowledged them, so nothing waits for the disk. A large write arrives in
      // several chunks. The first field of the last chunk is 1.
      const length = Atomics.load(control, REQUEST_LENGTH);
      const chunk = request.slice(0, length);
      const view = new DataView(chunk.buffer);
      const last = view.getUint32(0, true) === 1;
      const headLength = view.getUint32(4, true);
      const head = headFrom(chunk.subarray(8, 8 + headLength));
      let at = 8 + headLength;
      const count = view.getUint32(at, true);
      at += 4;
      for (let i = 0; i < count; i++) {
        const index = Number(view.getBigUint64(at, true));
        at += 8;
        const size = view.getUint32(at, true);
        at += 4;
        pending.push([index, chunk.slice(at, at + size)]);
        at += size;
      }
      put(KIND_DONE, null);
      if (last) {
        const blocks = pending;
        pending = [];
        queue(async () => {
          try {
            await copyWrite(head, blocks);
          } catch (error) {
            // Clear the local copy. The server has every block, so nothing is lost, and the next open loads from the
            // server. If clearing fails too, never read the copy again: it could return blocks older than its head
            // claims.
            const name = copyName;
            await copyClear().catch(() => {
              givenUp.add(name);
            });
          }
        });
      }
      break;
    }

    case OP_COPY_FORGET: {
      const length = Atomics.load(control, REQUEST_LENGTH);
      const chunk = request.slice(0, length);
      const view = new DataView(chunk.buffer);
      const headLength = view.getUint32(0, true);
      const head = headFrom(chunk.subarray(4, 4 + headLength));
      let at = 4 + headLength;
      const count = view.getUint32(at, true);
      at += 4;
      const blocks = [];
      for (let i = 0; i < count; i++) {
        blocks.push(Number(view.getBigUint64(at, true)));
        at += 8;
      }
      queue(async () => {
        await copyForget(head, blocks);
        put(KIND_DONE, null);
      });
      break;
    }

    case OP_COPY_CLEAR:
      pending = [];
      queue(async () => {
        await copyClear();
        put(KIND_DONE, null);
      });
      break;

    case OP_COPY_SELECT: {
      const name = new TextDecoder().decode(request.slice(0, Atomics.load(control, REQUEST_LENGTH)));
      queue(async () => {
        if (copy !== null) {
          (await copy).close();
          copy = null;
        }
        copyName = copyPrefix + "/" + name;
        put(KIND_DONE, null);
      });
      break;
    }
  }
}

// Runs local copy jobs one after another, in request order.
function queue(job) {
  chain = chain.then(job).catch((error) => {
    // Answer with an error unless the last answer already was one. Write jobs answer before they run and handle
    // their own errors.
    if (Atomics.load(control, KIND) !== KIND_ERROR) {
      put(KIND_ERROR, encoder.encode("local copy failed: " + error));
    }
  });
}

// ---------------------------------------------------------------------------------------------------------------
// Local copy (IndexedDB)
// ---------------------------------------------------------------------------------------------------------------

function openCopy() {
  if (copy !== null) {
    return copy;
  }
  if (copyName === null) {
    return Promise.reject(new Error("no database selected"));
  }
  copy = new Promise((resolve, reject) => {
    const request = indexedDB.open(copyName, 1);
    request.onupgradeneeded = () => {
      const database = request.result;
      if (!database.objectStoreNames.contains("blocks")) {
        database.createObjectStore("blocks");
      }
      if (!database.objectStoreNames.contains("head")) {
        database.createObjectStore("head");
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
  return copy;
}

function finished(transaction) {
  return new Promise((resolve, reject) => {
    transaction.oncomplete = () => resolve();
    transaction.onabort = () => reject(transaction.error);
    transaction.onerror = () => reject(transaction.error);
  });
}

function got(request) {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

// Encodes the head for the SQLite worker, little-endian: page size (u32), page count (u64), version (u64), subject
// length (u16), database id length (u16), subject, database id.
function headBytes(head) {
  const subject = encoder.encode(head.subject);
  const dbId = encoder.encode(head.dbId);
  const bytes = new Uint8Array(24 + subject.length + dbId.length);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, head.pageSize, true);
  view.setBigUint64(4, BigInt(head.pageCount), true);
  view.setBigUint64(12, BigInt(head.version), true);
  view.setUint16(20, subject.length, true);
  view.setUint16(22, dbId.length, true);
  bytes.set(subject, 24);
  bytes.set(dbId, 24 + subject.length);
  return bytes;
}

function headFrom(bytes) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const subjectLength = view.getUint16(20, true);
  const dbIdLength = view.getUint16(22, true);
  const decoder = new TextDecoder();
  return {
    pageSize: view.getUint32(0, true),
    pageCount: Number(view.getBigUint64(4, true)),
    version: Number(view.getBigUint64(12, true)),
    subject: decoder.decode(bytes.subarray(24, 24 + subjectLength)),
    dbId: decoder.decode(bytes.subarray(24 + subjectLength, 24 + subjectLength + dbIdLength)),
  };
}

async function copyHead() {
  if (givenUp.has(copyName)) {
    return null;
  }
  const database = await openCopy();
  const transaction = database.transaction("head", "readonly");
  const head = await got(transaction.objectStore("head").get("head"));
  return head ?? null;
}

// Returns the blocks from `first` on, at most `count`, up to the first missing block.
async function copyRead(first, count) {
  const head = await copyHead();
  if (head === null) {
    return [];
  }
  const last = Math.min(first + count, head.pageCount) - 1;
  if (last < first) {
    return [];
  }
  const database = await openCopy();
  const transaction = database.transaction("blocks", "readonly");
  const store = transaction.objectStore("blocks");
  // One getAll request instead of one get per block: per-block requests dominated the time to open a database from
  // the local copy. The keys are needed to detect gaps, so that a missing block is not replaced by the next one.
  // Both requests are issued before either is awaited. An IndexedDB transaction closes when no request is pending,
  // so a request issued after an await can find it closed.
  const range = IDBKeyRange.bound(first, last);
  const wanted = store.getAll(range);
  const names = store.getAllKeys(range);
  const blocks = await got(wanted);
  const keys = await got(names);
  let run = 0;
  while (run < keys.length && keys[run] === first + run) {
    run++;
  }
  return blocks.slice(0, run).map((block) => new Uint8Array(block));
}

// Writes blocks and head in one transaction, so a crash leaves either the old or the new state.
async function copyWrite(head, blocks) {
  if (givenUp.has(copyName)) {
    return;
  }
  const database = await openCopy();
  const transaction = database.transaction(["blocks", "head"], "readwrite");
  const store = transaction.objectStore("blocks");
  for (const [index, data] of blocks) {
    store.put(data, index);
  }
  // Delete blocks beyond the new end of the database.
  store.delete(IDBKeyRange.lowerBound(head.pageCount));
  transaction.objectStore("head").put(head, "head");
  await finished(transaction);
}

// Catches up the local copy: deletes the given blocks and sets the new head, in one transaction. All other blocks
// are unchanged in the new version.
async function copyForget(head, blocks) {
  if (givenUp.has(copyName)) {
    return;
  }
  const database = await openCopy();
  const transaction = database.transaction(["blocks", "head"], "readwrite");
  const store = transaction.objectStore("blocks");
  for (const index of blocks) {
    store.delete(index);
  }
  // Delete blocks beyond the new end of the database.
  store.delete(IDBKeyRange.lowerBound(head.pageCount));
  transaction.objectStore("head").put(head, "head");
  await finished(transaction);
}

async function copyClear() {
  if (copyName === null) {
    return;
  }
  if (copy !== null) {
    (await copy).close();
    copy = null;
  }
  await new Promise((resolve, reject) => {
    const request = indexedDB.deleteDatabase(copyName);
    request.onsuccess = () => resolve();
    request.onerror = () => reject(request.error);
    request.onblocked = () => resolve();
  });
}

function take() {
  if (Atomics.exchange(control, REQUEST, 0) === 1) {
    work();
  }
}

// Waits on the REQUEST slot with Atomics.waitAsync and handles each request, until the worker is closed.
function serve() {
  if (closed) {
    return;
  }
  const waited = Atomics.waitAsync(control, REQUEST, 0);
  const next = () => {
    take();
    serve();
  };
  if (waited.async) {
    waited.value.then(next);
  } else {
    next();
  }
}

// Fallback without Atomics.waitAsync: checks the REQUEST slot every millisecond.
function poll() {
  if (closed) {
    return;
  }
  take();
  setTimeout(poll, 1);
}

self.onmessage = (event) => {
  const message = event.data;
  if (message.op !== "start") {
    return;
  }
  const dataStart = message.controlSlots * 4;
  control = new Int32Array(message.buffer, 0, message.controlSlots);
  request = new Uint8Array(message.buffer, dataStart, message.capacity);
  answer = new Uint8Array(message.buffer, dataStart + message.capacity, message.capacity);
  url = message.url;
  copyPrefix = message.copyPrefix;
  connect();
  if (typeof Atomics.waitAsync === "function") {
    serve();
  } else {
    poll();
  }
  // The SQLite worker may block from now on: shared memory is set up and the REQUEST slot is being watched.
  self.postMessage("ready");
};
