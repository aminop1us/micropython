# Test asyncio TCP server and client with TLS-PSK, using set_psk_sever_callback() and set_psk_client_callback().

try:
    import asyncio
    import tls
except ImportError:
    print("SKIP")
    raise SystemExit

PORT = 8000


async def handle_connection(reader, writer):
    # Test that peername exists (but don't check its value, it changes)
    writer.get_extra_info("peername")

    data = await reader.read(100)
    print("echo:", data)
    writer.write(data)
    await writer.drain()

    print("close")
    writer.close()
    await writer.wait_closed()

    print("done")
    ev.set()


async def tcp_server():
    global ev

    server_ctx = tls.SSLContext(tls.PROTOCOL_TLS_SERVER)

    def psk_server_callback(identity):
        psk_dict = {
            b"PSK-Identity-1" : bytes.fromhex( "c0ffee" ),
            b"PSK-Identity-2" : bytes.fromhex( "facade" ),
        }
        return psk_dict[identity]

    server_ctx.set_psk_server_callback(psk_server_callback)

    ev = asyncio.Event()
    server = await asyncio.start_server(handle_connection, "0.0.0.0", PORT, ssl=server_ctx)
    print("server running")
    multitest.next()
    async with server:
        await asyncio.wait_for(ev.wait(), 10)


async def tcp_client(message):
    client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

    def psk_client_callback(identity):
        return (b"PSK-Identity-1", bytes.fromhex("c0ffee"))

    ctx.set_psk_client_callback(psk_client_callback)

    reader, writer = await asyncio.open_connection(IP, PORT, ssl=client_ctx)
    print("write:", message)
    writer.write(message)
    await writer.drain()
    data = await reader.read(100)
    print("read:", data)


def instance0():
    multitest.globals(IP=multitest.get_network_ip())
    asyncio.run(tcp_server())


def instance1():
    multitest.next()
    asyncio.run(tcp_client(b"client data"))
