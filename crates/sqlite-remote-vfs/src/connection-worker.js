// Connection worker: holds the WebSocket and the IndexedDB local copy, or the local databases of a VFS without a server,
// and serves requests from the SQLite worker.
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
const REACHABLE = 7; // set to 1 when a background connection after OP_PROBE succeeded

const STATE_OPEN = 1;
const STATE_FAILED = 2;
const KIND_FRAME = 1;
const KIND_ERROR = 2;
const KIND_DONE = 3;
const KIND_NOTHING = 4; // the local copy does not have the requested data, or the local database does not exist
const KIND_BUSY = 5; // another instance holds the local database or has taken it over
const KIND_FULL = 6; // the browser's storage quota is exhausted

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
const OP_COPY_FLUSH = 16;
// Tries to connect in the background until the server accepts a connection, then sets REACHABLE. A database that
// broke because the server could not be reached recovers only then, so its SQLite calls never wait for an
// unreachable server.
const OP_PROBE = 17;
const PROBE_PAUSE_MS = 500;
const PROBE_MAX_PAUSE_MS = 10000;
// Local database operations, for a VFS without a server.
const OP_LOCAL_OPEN = 11;
const OP_LOCAL_READ = 12;
const OP_LOCAL_COMMIT = 13;
const OP_LOCAL_CLOSE = 14;
const OP_LOCAL_DELETE = 15;

const encoder = new TextEncoder();

let control = null;
let request = null;
let answer = null;
let url = null;
let socket = null;
let closed = false;
let probing = false;

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

// Local databases: one IndexedDB database per database, named localPrefix + "/" + name, with a "blocks" store and a
// "head" store. The head holds page size, page count and epoch. A Web Lock of the same name keeps other instances out.
// Opening increments the epoch, and every commit checks it in the transaction that writes the blocks, so an instance
// whose lock was taken over cannot commit, even before it learns that it lost the lock.
let localPrefix = null;
// The open local database: { name, database, pageSize, epoch, lock, closed }.
let local = null;
// Blocks of a local commit that arrives in several pieces.
let localPending = [];

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

// Opens a separate connection and closes it again once it is open. Retries with growing pauses until then.
function probe(pause) {
  if (closed) {
    probing = false;
    return;
  }
  let attempt;
  try {
    attempt = new WebSocket(url);
  } catch (error) {
    setTimeout(() => probe(Math.min(pause * 2, PROBE_MAX_PAUSE_MS)), pause);
    return;
  }
  attempt.onopen = () => {
    attempt.onclose = null;
    attempt.close();
    probing = false;
    Atomics.store(control, REACHABLE, 1);
  };
  // A failed connection is always followed by a close event.
  attempt.onclose = () => setTimeout(() => probe(Math.min(pause * 2, PROBE_MAX_PAUSE_MS)), pause);
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

    case OP_PROBE:
      if (!probing) {
        probing = true;
        Atomics.store(control, REACHABLE, 0);
        probe(PROBE_PAUSE_MS);
      }
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
        // The SQLite worker asks for no more than fits the answer region. Should it ask for more, return fewer
        // blocks instead of cutting the last one off.
        const size = blocks[0].length;
        const fit = blocks.slice(0, Math.max(1, Math.floor((answer.length - 4) / size)));
        const bytes = new Uint8Array(4 + size * fit.length);
        new DataView(bytes.buffer).setUint32(0, size, true);
        let at = 4;
        for (const block of fit) {
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

    // Answers when all earlier local copy jobs, including the writes answered in advance, are done.
    case OP_COPY_FLUSH:
      queue(async () => put(KIND_DONE, null));
      break;

    // Request: flags (u32: 1 create, 2 take over), page size (u32), name. Answer: page size (u32), page count (u64),
    // epoch (u64).
    case OP_LOCAL_OPEN: {
      const chunk = request.slice(0, Atomics.load(control, REQUEST_LENGTH));
      const view = new DataView(chunk.buffer);
      const flags = view.getUint32(0, true);
      const pageSize = view.getUint32(4, true);
      const name = new TextDecoder().decode(chunk.subarray(8));
      answerLocal(async () => {
        const opened = await localOpen(name, pageSize, (flags & 1) !== 0, (flags & 2) !== 0);
        if (opened === KIND_BUSY || opened === KIND_NOTHING) {
          put(opened, null);
          return;
        }
        const bytes = new Uint8Array(20);
        const out = new DataView(bytes.buffer);
        out.setUint32(0, opened.pageSize, true);
        out.setBigUint64(4, BigInt(opened.pageCount), true);
        out.setBigUint64(12, BigInt(opened.epoch), true);
        put(KIND_FRAME, bytes);
      });
      break;
    }

    // Request: first block (u64), count (u64). Answer: block size (u32), then exactly `count` blocks. Blocks that
    // were never written are zeros.
    case OP_LOCAL_READ: {
      const view = new DataView(request.buffer, request.byteOffset, 16);
      const first = Number(view.getBigUint64(0, true));
      const count = Number(view.getBigUint64(8, true));
      answerLocal(async () => {
        const bytes = await localRead(first, count);
        put(bytes === KIND_BUSY ? KIND_BUSY : KIND_FRAME, bytes === KIND_BUSY ? null : bytes);
      });
      break;
    }

    // A commit arrives in one or more pieces. Each piece: flags (u32: 1 first piece, 2 last piece), epoch (u64),
    // page count (u64), number of blocks (u32), then per block its index (u64), length (u32) and data. The pieces
    // before the last are answered at once. The last is answered when the transaction is complete.
    case OP_LOCAL_COMMIT: {
      const chunk = request.slice(0, Atomics.load(control, REQUEST_LENGTH));
      const view = new DataView(chunk.buffer);
      const flags = view.getUint32(0, true);
      const epoch = Number(view.getBigUint64(4, true));
      const pageCount = Number(view.getBigUint64(12, true));
      const count = view.getUint32(20, true);
      if ((flags & 1) !== 0) {
        localPending = [];
      }
      let at = 24;
      for (let i = 0; i < count; i++) {
        const index = Number(view.getBigUint64(at, true));
        at += 8;
        const size = view.getUint32(at, true);
        at += 4;
        localPending.push([index, chunk.slice(at, at + size)]);
        at += size;
      }
      if ((flags & 2) === 0) {
        put(KIND_DONE, null);
        break;
      }
      const blocks = localPending;
      localPending = [];
      answerLocal(async () => put(await localCommit(epoch, pageCount, blocks), null));
      break;
    }

    case OP_LOCAL_CLOSE:
      answerLocal(async () => {
        localClose();
        put(KIND_DONE, null);
      });
      break;

    // Request: flags (u32: 2 take over), name.
    case OP_LOCAL_DELETE: {
      const chunk = request.slice(0, Atomics.load(control, REQUEST_LENGTH));
      const flags = new DataView(chunk.buffer).getUint32(0, true);
      const name = new TextDecoder().decode(chunk.subarray(4));
      answerLocal(async () => put(await localDelete(name, (flags & 2) !== 0), null));
      break;
    }
  }
}

// Runs a local database job in the queue and answers with its error if it fails. A full storage quota is reported as
// such, so that SQLite returns SQLITE_FULL.
function answerLocal(job) {
  queue(async () => {
    try {
      await job();
    } catch (error) {
      const kind = error !== null && error.name === "QuotaExceededError" ? KIND_FULL : KIND_ERROR;
      put(kind, encoder.encode("local database: " + error));
    }
  });
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
    request.onsuccess = () => {
      const database = request.result;
      // Another instance deletes this copy. Close, so that the deletion is not blocked. The next operation opens the
      // copy again.
      const opened = copy;
      database.onversionchange = () => {
        database.close();
        if (copy === opened) {
          copy = null;
        }
      };
      resolve(database);
    };
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

// ---------------------------------------------------------------------------------------------------------------
// Local databases (IndexedDB, Web Locks)
// ---------------------------------------------------------------------------------------------------------------

// Takes the Web Lock `name`. Resolves with the held lock, or with null if another instance holds it and `steal` is
// false. The lock is held until `release` is called or this worker ends. If another instance steals it, `lost` is set.
function acquire(name, steal) {
  if (typeof navigator.locks === "undefined") {
    return Promise.reject(new Error("Web Locks are not available; the page must be a secure context"));
  }
  return new Promise((resolve, reject) => {
    const held = { release: null, lost: false };
    let granted = false;
    navigator.locks
      .request(name, steal ? { steal: true } : { ifAvailable: true }, (lock) => {
        if (lock === null) {
          resolve(null);
          return undefined;
        }
        granted = true;
        return new Promise((release) => {
          held.release = release;
          resolve(held);
        });
      })
      .catch((error) => {
        // The request is rejected with an AbortError when another instance steals the lock.
        held.lost = true;
        if (!granted) {
          reject(error);
        }
      });
  });
}

function openLocal(name) {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(name, 1);
    request.onupgradeneeded = () => {
      request.result.createObjectStore("blocks");
      request.result.createObjectStore("head");
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

// Deletes an IndexedDB database. While another connection is open, the deletion waits; that connection closes on its
// versionchange event.
function deleteIndexedDb(name) {
  return new Promise((resolve, reject) => {
    const request = indexedDB.deleteDatabase(name);
    request.onsuccess = () => resolve();
    request.onerror = () => reject(request.error);
  });
}

// Opens local database `name`: takes its lock, then increments the epoch in the head, in one transaction. Returns the
// head, KIND_BUSY if another instance holds the lock, or KIND_NOTHING if the database does not exist and `create` is
// false.
async function localOpen(name, pageSize, create, takeover) {
  if (local !== null) {
    throw new Error(local.name + " is already open");
  }
  const fullName = localPrefix + "/" + name;
  const lock = await acquire(fullName, takeover);
  if (lock === null) {
    return KIND_BUSY;
  }
  let database = null;
  try {
    database = await openLocal(fullName);
    const opened = database;
    opened.onversionchange = () => {
      // Another instance deletes this database. It must have taken the lock first, so this instance can no longer
      // commit anyway.
      opened.close();
      if (local !== null && local.database === opened) {
        local.closed = true;
      }
    };
    opened.onclose = () => {
      // Closed by the browser, for example because the user deleted the site data.
      if (local !== null && local.database === opened) {
        local.closed = true;
      }
    };
    let head = null;
    const transaction = database.transaction("head", "readwrite", { durability: "strict" });
    const store = transaction.objectStore("head");
    const get = store.get("head");
    get.onsuccess = () => {
      const found = get.result;
      if (found === undefined && !create) {
        return;
      }
      const base = found ?? { pageSize, pageCount: 0, epoch: 0 };
      head = { pageSize: base.pageSize, pageCount: base.pageCount, epoch: base.epoch + 1 };
      store.put(head, "head");
    };
    await finished(transaction);
    if (head === null) {
      // Do not leave the empty database behind that opening created.
      database.close();
      database = null;
      await deleteIndexedDb(fullName);
      lock.release();
      return KIND_NOTHING;
    }
    local = { name, database, pageSize: head.pageSize, epoch: head.epoch, lock, closed: false };
    return head;
  } catch (error) {
    if (database !== null) {
      database.close();
    }
    lock.release();
    throw error;
  }
}

// The open local database, or null if this instance lost it: its lock was taken over or its connection closed.
function localDatabase() {
  if (local === null) {
    throw new Error("no local database is open");
  }
  return local.lock.lost || local.closed ? null : local.database;
}

// Returns the answer to OP_LOCAL_READ, or KIND_BUSY if another instance has taken over.
async function localRead(first, count) {
  const database = localDatabase();
  if (database === null) {
    return KIND_BUSY;
  }
  const size = local.pageSize;
  const transaction = database.transaction("blocks", "readonly");
  const store = transaction.objectStore("blocks");
  // Both requests are issued before either is awaited, as in copyRead.
  const range = IDBKeyRange.bound(first, first + count - 1);
  const wanted = store.getAll(range);
  const names = store.getAllKeys(range);
  const blocks = await got(wanted);
  const keys = await got(names);
  // Blocks that were never written stay zero.
  const bytes = new Uint8Array(4 + size * count);
  new DataView(bytes.buffer).setUint32(0, size, true);
  for (let i = 0; i < keys.length; i++) {
    const block = new Uint8Array(blocks[i]);
    if (block.length !== size) {
      throw new Error("block " + keys[i] + " has " + block.length + " bytes, expected " + size);
    }
    bytes.set(block, 4 + (keys[i] - first) * size);
  }
  return bytes;
}

// Writes the blocks and the new page count in one transaction, if the epoch in the head is still this instance's.
// Returns KIND_DONE, or KIND_BUSY if another instance has taken over. Failures reject, and the transaction leaves the
// stored database unchanged.
function localCommit(epoch, pageCount, blocks) {
  const database = localDatabase();
  if (database === null) {
    return Promise.resolve(KIND_BUSY);
  }
  return new Promise((resolve, reject) => {
    const transaction = database.transaction(["blocks", "head"], "readwrite", { durability: "strict" });
    const heads = transaction.objectStore("head");
    let fenced = false;
    const get = heads.get("head");
    get.onsuccess = () => {
      const head = get.result;
      if (head === undefined || head.epoch !== epoch) {
        fenced = true;
        transaction.abort();
        return;
      }
      const store = transaction.objectStore("blocks");
      for (const [index, data] of blocks) {
        store.put(data, index);
      }
      // Delete blocks beyond the new end of the database.
      store.delete(IDBKeyRange.lowerBound(pageCount));
      heads.put({ pageSize: head.pageSize, pageCount, epoch }, "head");
    };
    transaction.oncomplete = () => resolve(KIND_DONE);
    transaction.onabort = () => {
      if (fenced) {
        resolve(KIND_BUSY);
      } else {
        reject(transaction.error ?? new Error("the transaction was aborted"));
      }
    };
  });
}

function localClose() {
  if (local === null) {
    return;
  }
  local.database.close();
  if (local.lock.release !== null) {
    local.lock.release();
  }
  local = null;
}

// Deletes local database `name` under its lock. Returns KIND_DONE, or KIND_BUSY if another instance holds it and
// `takeover` is false.
async function localDelete(name, takeover) {
  if (local !== null && local.name === name) {
    throw new Error(name + " is open");
  }
  const fullName = localPrefix + "/" + name;
  const lock = await acquire(fullName, takeover);
  if (lock === null) {
    return KIND_BUSY;
  }
  try {
    await deleteIndexedDb(fullName);
  } finally {
    lock.release();
  }
  return KIND_DONE;
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
  url = message.url ?? null;
  copyPrefix = message.copyPrefix ?? null;
  localPrefix = message.localPrefix ?? null;
  // Without a URL, the VFS keeps its databases only in this browser and there is no connection.
  if (url !== null) {
    connect();
  }
  if (typeof Atomics.waitAsync === "function") {
    serve();
  } else {
    poll();
  }
  // The SQLite worker may block from now on: shared memory is set up and the REQUEST slot is being watched.
  self.postMessage("ready");
};
