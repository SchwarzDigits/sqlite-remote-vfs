"""TCP relay in front of the page server, for the browser tests that make the server unreachable.

Usage: python3 relay.py <server host:port> <relay port> <control port>

The browser tests connect through the relay port. A GET request to /stop on the control port closes all relayed
connections and closes new ones right away, as if the server were gone. /resume relays new connections again. The
control port answers with Access-Control-Allow-Origin: *, so that a test page on another port can call it.
"""

import asyncio
import sys

server_host, server_port = sys.argv[1].rsplit(":", 1)
relay_port = int(sys.argv[2])
control_port = int(sys.argv[3])

stopped = False
open_writers = set()


async def pipe(reader, writer):
    try:
        while data := await reader.read(65536):
            writer.write(data)
            await writer.drain()
    except ConnectionError:
        pass
    finally:
        writer.close()


async def relay(client_reader, client_writer):
    if stopped:
        client_writer.close()
        return
    try:
        server_reader, server_writer = await asyncio.open_connection(server_host, int(server_port))
    except OSError:
        client_writer.close()
        return
    pair = {client_writer, server_writer}
    open_writers.update(pair)
    try:
        await asyncio.gather(pipe(client_reader, server_writer), pipe(server_reader, client_writer))
    finally:
        open_writers.difference_update(pair)


async def control(reader, writer):
    global stopped
    words = (await reader.readline()).split()
    path = words[1].decode() if len(words) > 1 else ""
    while (await reader.readline()) not in (b"\r\n", b""):
        pass
    status = "200 OK"
    if path == "/stop":
        stopped = True
        for open_writer in list(open_writers):
            open_writer.close()
    elif path == "/resume":
        stopped = False
    else:
        status = "404 Not Found"
    writer.write(
        f"HTTP/1.1 {status}\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".encode()
    )
    await writer.drain()
    writer.close()


async def main():
    relay_server = await asyncio.start_server(relay, "127.0.0.1", relay_port)
    control_server = await asyncio.start_server(control, "127.0.0.1", control_port)
    async with relay_server, control_server:
        await asyncio.gather(relay_server.serve_forever(), control_server.serve_forever())


asyncio.run(main())
