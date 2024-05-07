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

    server_ctx = tls.SSLContext( tls.PROTOCOL_TLS_SERVER )
    def psk_server_callback( identity ):
        return bytes.fromhex( "c0ffee" )
    server_ctx.set_psk_server_callback( psk_server_callback )

    ev = asyncio.Event()
    server = await asyncio.start_server(handle_connection, "0.0.0.0", PORT, ssl=server_ctx)
    print("server running")
    multitest.next()
    async with server:
        await asyncio.wait_for(ev.wait(), 10)


async def tcp_client(message):
    client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    def psk_client_callback( identity ):
        return (  b"PSK-Identity-1", bytes.fromhex( "c0ffee" ) )
    ctx.set_psk_client_callback( psk_client_callback )

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









import asyncio
import tls
import time

# define server listening address
server_host = "0.0.0.0"
server_port = 8124

# define dict for mapping PSK identity and key
psk_dict = {
    b"PSK-Identity-1" : bytes.fromhex( "c0ffee" ),
    b"PSK-Identity-2" : bytes.fromhex( "facade" ),
}

# create a ssl context
ctx = tls.SSLContext( tls.PROTOCOL_TLS_SERVER )

print( ctx.get_ciphers() )

ctx.set_ciphers( [ 'TLS-PSK-WITH-AES-128-CBC-SHA256' ] )
print( dir( ctx ) )

# define psk callback
def psk_server_callback( identity ):
    key = psk_dict.get( identity )
    print( f"[DEBUG] psk_server_callback( identity = {identity} )" )
    print( f"[DEBUG]    key = {key}" )
    return key

# set psk callback function
ctx.set_psk_server_callback( psk_server_callback )

# for handling connection from the client
async def server_handle( reader, writer ):
    print( "=====" * 10 )
    
    client_addr = writer.get_extra_info( "peername" )
    print( f"Client connected from {client_addr}" )
    
    try:
        # write packets to the client
        data = f"\n>>> Server message ( time {time.time()} ms. )"
        send_bytes = len( data ) 
        writer.write( data.encode() )
        await writer.drain()
        #print( f"[DEBUG] Sent to client {send_bytes} bytes." )
        
        # read packets from the client
        data = await reader.read( 1024 )
        print( data.decode() )
        
    # catch exception in this scope
    #    if psk-key not matched the raise "(-29056, 'MBEDTLS_ERR_SSL_INVALID_MAC')"
    #    if psk-identity not matched the raise "(-27776, 'MBEDTLS_ERR_SSL_UNKNOWN_IDENTITY')"
    except Exception as ex:
        print( "Error :", ex )
    
    writer.close()
    await writer.wait_closed()
    print('Connection closed.')

async def run_server():
    server = await asyncio.start_server(
        server_handle,
        server_host,
        server_port,
        ssl = ctx
    )
    
    print( 'Waiting for a remote connection ...' )
    while True:
        await asyncio.sleep( 100 )

asyncio.run( run_server() )


