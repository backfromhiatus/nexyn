import asyncio
import struct
import logging
import ssl
from enum import IntEnum
from typing import Dict, Optional
from aiohttp import web
import aiohttp

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


class PacketType(IntEnum):
    CONNECT = 0x01
    DATA = 0x02
    CONTINUE = 0x03
    CLOSE = 0x04


class StreamType(IntEnum):
    TCP = 0x01
    UDP = 0x02
    TLS = 0x03  


class CloseReason(IntEnum):
    UNKNOWN = 0x01
    VOLUNTARY = 0x02
    NETWORK_ERROR = 0x03
    
    INVALID_INFO = 0x41
    UNREACHABLE = 0x42
    TIMEOUT = 0x43
    REFUSED = 0x44
    TIMEOUT_DATA = 0x47
    BLOCKED = 0x48
    THROTTLED = 0x49
    
    CLIENT_ERROR = 0x81


class WispPacket:
    def __init__(self, packet_type: int, stream_id: int, payload: bytes):
        self.packet_type = packet_type
        self.stream_id = stream_id
        self.payload = payload
    
    def encode(self) -> bytes:
        header = struct.pack('<BI', self.packet_type, self.stream_id)
        return header + self.payload
    
    @staticmethod
    def decode(data: bytes) -> 'WispPacket':
        if len(data) < 5:
            raise ValueError("Packet too short")
        
        packet_type, stream_id = struct.unpack('<BI', data[:5])
        payload = data[5:]
        
        logger.debug(f"Decoded packet: type={packet_type}, stream_id={stream_id}, payload_size={len(payload)}")
        return WispPacket(packet_type, stream_id, payload)


class WispStream:
    def __init__(self, stream_id: int, stream_type: int, host: str, port: int, buffer_size: int):
        self.stream_id = stream_id
        self.stream_type = stream_type
        self.host = host
        self.port = port
        self.buffer_size = buffer_size
        self.buffer_remaining = buffer_size
        
        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None
        self.transport: Optional[asyncio.DatagramTransport] = None
        self.protocol: Optional[asyncio.DatagramProtocol] = None
        
        self.send_queue = asyncio.Queue()
        self.closed = False
        self.read_task: Optional[asyncio.Task] = None
        self.write_task: Optional[asyncio.Task] = None
        
        logger.info(f"Created WispStream: id={stream_id}, type={'TCP' if stream_type == StreamType.TCP else 'TLS' if stream_type == StreamType.TLS else 'UDP'}, target={host}:{port}, buffer_size={buffer_size}")


class WispUDPProtocol(asyncio.DatagramProtocol):
    def __init__(self, stream: WispStream, ws_send_callback):
        self.stream = stream
        self.ws_send_callback = ws_send_callback
        logger.info(f"UDP protocol initialized for stream {stream.stream_id}")
    
    def datagram_received(self, data: bytes, addr):
        if not self.stream.closed:
            logger.debug(f"UDP data received on stream {self.stream.stream_id}: {len(data)} bytes from {addr}")
            packet = WispPacket(PacketType.DATA, self.stream.stream_id, data)
            asyncio.create_task(self.ws_send_callback(packet.encode()))
        else:
            logger.warning(f"UDP data received on closed stream {self.stream.stream_id}")
    
    def error_received(self, exc):
        logger.error(f"UDP protocol error on stream {self.stream.stream_id}: {exc}")
    
    def connection_lost(self, exc):
        logger.info(f"UDP connection lost for stream {self.stream.stream_id}: {exc}")


class WispServer:
    def __init__(self, buffer_size: int = 256):
        self.buffer_size = buffer_size
        self.streams: Dict[int, WispStream] = {}
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE
        logger.info(f"WispServer initialized with buffer_size={buffer_size}")
    
    async def handle_websocket(self, request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        
        client_ip = request.remote
        logger.info(f"New WebSocket connection from {client_ip}")
        
        initial_packet = WispPacket(
            PacketType.CONTINUE,
            0,
            struct.pack('<I', self.buffer_size)
        )
        await ws.send_bytes(initial_packet.encode())
        logger.debug(f"Sent initial CONTINUE packet to {client_ip} with buffer_size={self.buffer_size}")
        
        try:
            async for msg in ws:
                if msg.type == aiohttp.WSMsgType.BINARY:
                    logger.debug(f"Received binary message from {client_ip}: {len(msg.data)} bytes")
                    await self.handle_packet(ws, msg.data)
                elif msg.type == aiohttp.WSMsgType.TEXT:
                    logger.warning(f"Received unexpected text message from {client_ip}: {msg.data}")
                elif msg.type == aiohttp.WSMsgType.ERROR:
                    logger.error(f"WebSocket error from {client_ip}: {ws.exception()}")
                    break
                elif msg.type == aiohttp.WSMsgType.CLOSE:
                    logger.info(f"WebSocket connection closed by client {client_ip}")
                    break
        except Exception as e:
            logger.error(f"WebSocket handler error for {client_ip}: {e}")
        finally:
            await self.cleanup_connection(ws, client_ip)
        
        return ws
    
    async def handle_packet(self, ws: web.WebSocketResponse, data: bytes):
        try:
            packet = WispPacket.decode(data)
            logger.debug(f"Processing packet: type={packet.packet_type}, stream_id={packet.stream_id}, payload_size={len(packet.payload)}")
            
            if packet.packet_type == PacketType.CONNECT:
                logger.info(f"CONNECT packet received for stream {packet.stream_id}")
                await self.handle_connect(ws, packet)
            elif packet.packet_type == PacketType.DATA:
                logger.debug(f"DATA packet received for stream {packet.stream_id}: {len(packet.payload)} bytes")
                await self.handle_data(ws, packet)
            elif packet.packet_type == PacketType.CONTINUE:
                logger.debug(f"CONTINUE packet received for stream {packet.stream_id}")
            elif packet.packet_type == PacketType.CLOSE:
                logger.info(f"CLOSE packet received for stream {packet.stream_id}")
                await self.handle_close(ws, packet)
            else:
                logger.warning(f"Unknown packet type: {packet.packet_type} for stream {packet.stream_id}")
        
        except Exception as e:
            logger.error(f"Error handling packet: {e}")
    
    async def handle_connect(self, ws: web.WebSocketResponse, packet: WispPacket):
        try:
            if len(packet.payload) < 3:
                logger.warning(f"CONNECT packet too short for stream {packet.stream_id}")
                await self.send_close(ws, packet.stream_id, CloseReason.INVALID_INFO)
                return
            
            stream_type = packet.payload[0]
            port = struct.unpack('<H', packet.payload[1:3])[0]
            hostname = packet.payload[3:].decode('utf-8')
            
            logger.info(f"CONNECT request: stream_id={packet.stream_id}, type={'TCP' if stream_type == StreamType.TCP else 'TLS' if stream_type == StreamType.TLS else 'UDP'}, host={hostname}, port={port}")
            
            if stream_type not in (StreamType.TCP, StreamType.UDP, StreamType.TLS):
                logger.warning(f"Invalid stream type {stream_type} for stream {packet.stream_id}")
                await self.send_close(ws, packet.stream_id, CloseReason.INVALID_INFO)
                return
            
            if port <= 0 or port > 65535:
                logger.warning(f"Invalid port {port} for stream {packet.stream_id}")
                await self.send_close(ws, packet.stream_id, CloseReason.INVALID_INFO)
                return
            
            if packet.stream_id in self.streams:
                logger.warning(f"Stream ID {packet.stream_id} already exists")
                await self.send_close(ws, packet.stream_id, CloseReason.INVALID_INFO)
                return
            
            stream = WispStream(packet.stream_id, stream_type, hostname, port, self.buffer_size)
            self.streams[packet.stream_id] = stream
            
            if stream_type == StreamType.TCP:
                await self.connect_tcp(ws, stream)
            elif stream_type == StreamType.TLS:
                await self.connect_tls(ws, stream)
            else:
                await self.connect_udp(ws, stream)
        
        except UnicodeDecodeError:
            logger.error(f"Failed to decode hostname for stream {packet.stream_id}")
            await self.send_close(ws, packet.stream_id, CloseReason.INVALID_INFO)
        except Exception as e:
            logger.error(f"Error in handle_connect for stream {packet.stream_id}: {e}")
            await self.send_close(ws, packet.stream_id, CloseReason.NETWORK_ERROR)
    
    async def connect_tcp(self, ws: web.WebSocketResponse, stream: WispStream):
        try:
            logger.info(f"Attempting TCP connection for stream {stream.stream_id} to {stream.host}:{stream.port}")
            
            stream.reader, stream.writer = await asyncio.wait_for(
                asyncio.open_connection(stream.host, stream.port),
                timeout=30.0 
            )
            
            logger.info(f"TCP connection established for stream {stream.stream_id} to {stream.host}:{stream.port}")
            
            continue_packet = WispPacket(
                PacketType.CONTINUE,
                stream.stream_id,
                struct.pack('<I', self.buffer_size)
            )
            await ws.send_bytes(continue_packet.encode())
            logger.debug(f"Sent CONTINUE packet for TCP stream {stream.stream_id}")
            
            stream.read_task = asyncio.create_task(self.tcp_read_loop(ws, stream))
            stream.write_task = asyncio.create_task(self.tcp_write_loop(stream))
            
            logger.info(f"Started TCP read/write tasks for stream {stream.stream_id}")
            
        except asyncio.TimeoutError:
            logger.error(f"TCP connection timeout for stream {stream.stream_id} to {stream.host}:{stream.port}")
            await self.send_close(ws, stream.stream_id, CloseReason.TIMEOUT)
            self.streams.pop(stream.stream_id, None)
        except ConnectionRefusedError:
            logger.error(f"TCP connection refused for stream {stream.stream_id} to {stream.host}:{stream.port}")
            await self.send_close(ws, stream.stream_id, CloseReason.REFUSED)
            self.streams.pop(stream.stream_id, None)
        except Exception as e:
            logger.error(f"TCP connection error for stream {stream.stream_id} to {stream.host}:{stream.port}: {e}")
            await self.send_close(ws, stream.stream_id, CloseReason.UNREACHABLE)
            self.streams.pop(stream.stream_id, None)
    
    async def connect_tls(self, ws: web.WebSocketResponse, stream: WispStream):
        try:
            logger.info(f"Attempting TLS connection for stream {stream.stream_id} to {stream.host}:{stream.port}")
            
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            
            stream.reader, stream.writer = await asyncio.wait_for(
                asyncio.open_connection(stream.host, stream.port, ssl=ssl_context),
                timeout=30.0
            )
            
            logger.info(f"TLS connection established for stream {stream.stream_id} to {stream.host}:{stream.port}")
            
            continue_packet = WispPacket(
                PacketType.CONTINUE,
                stream.stream_id,
                struct.pack('<I', self.buffer_size)
            )
            await ws.send_bytes(continue_packet.encode())
            logger.debug(f"Sent CONTINUE packet for TLS stream {stream.stream_id}")
            
            stream.read_task = asyncio.create_task(self.tcp_read_loop(ws, stream))
            stream.write_task = asyncio.create_task(self.tcp_write_loop(stream))
            
            logger.info(f"Started TLS read/write tasks for stream {stream.stream_id}")
            
        except asyncio.TimeoutError:
            logger.error(f"TLS connection timeout for stream {stream.stream_id} to {stream.host}:{stream.port}")
            await self.send_close(ws, stream.stream_id, CloseReason.TIMEOUT)
            self.streams.pop(stream.stream_id, None)
        except ConnectionRefusedError:
            logger.error(f"TLS connection refused for stream {stream.stream_id} to {stream.host}:{stream.port}")
            await self.send_close(ws, stream.stream_id, CloseReason.REFUSED)
            self.streams.pop(stream.stream_id, None)
        except Exception as e:
            logger.error(f"TLS connection error for stream {stream.stream_id} to {stream.host}:{stream.port}: {e}")
            await self.send_close(ws, stream.stream_id, CloseReason.UNREACHABLE)
            self.streams.pop(stream.stream_id, None)
    
    async def connect_udp(self, ws: web.WebSocketResponse, stream: WispStream):
        try:
            logger.info(f"Attempting UDP connection for stream {stream.stream_id} to {stream.host}:{stream.port}")
            
            loop = asyncio.get_event_loop()
            
            transport, protocol = await loop.create_datagram_endpoint(
                lambda: WispUDPProtocol(stream, ws.send_bytes),
                remote_addr=(stream.host, stream.port)
            )
            
            stream.transport = transport
            stream.protocol = protocol
            
            logger.info(f"UDP connection established for stream {stream.stream_id} to {stream.host}:{stream.port}")
            
            stream.write_task = asyncio.create_task(self.udp_write_loop(stream))
            logger.info(f"Started UDP write task for stream {stream.stream_id}")
            
        except Exception as e:
            logger.error(f"UDP connection error for stream {stream.stream_id}: {e}")
            await self.send_close(ws, stream.stream_id, CloseReason.UNREACHABLE)
            self.streams.pop(stream.stream_id, None)
    
    async def tcp_read_loop(self, ws: web.WebSocketResponse, stream: WispStream):
        logger.info(f"Starting TCP read loop for stream {stream.stream_id}")
        total_bytes_read = 0
        
        try:
            while not stream.closed and stream.reader:
                data = await stream.reader.read(4096)
                if not data:
                    logger.info(f"TCP connection closed by remote for stream {stream.stream_id}")
                    break
                
                total_bytes_read += len(data)
                logger.debug(f"TCP read {len(data)} bytes from stream {stream.stream_id} (total: {total_bytes_read})")
                
                packet = WispPacket(PacketType.DATA, stream.stream_id, data)
                await ws.send_bytes(packet.encode())
                logger.debug(f"Sent DATA packet for stream {stream.stream_id}: {len(data)} bytes")
        
        except asyncio.CancelledError:
            logger.info(f"TCP read loop cancelled for stream {stream.stream_id}")
        except Exception as e:
            logger.error(f"TCP read error for stream {stream.stream_id}: {e}")
        finally:
            logger.info(f"TCP read loop ended for stream {stream.stream_id}, total bytes read: {total_bytes_read}")
            if not stream.closed:
                await self.send_close(ws, stream.stream_id, CloseReason.VOLUNTARY)
            await self.close_stream(stream)
    
    async def tcp_write_loop(self, stream: WispStream):
        logger.info(f"Starting TCP write loop for stream {stream.stream_id}")
        packets_sent = 0
        total_bytes_sent = 0
        
        try:
            while not stream.closed and stream.writer:
                data = await stream.send_queue.get()
                
                stream.writer.write(data)
                await stream.writer.drain()
                
                packets_sent += 1
                total_bytes_sent += len(data)
                logger.debug(f"TCP wrote {len(data)} bytes to stream {stream.stream_id} (packet {packets_sent}, total: {total_bytes_sent})")
                
                if packets_sent >= self.buffer_size:
                    logger.debug(f"Reset packet counter for stream {stream.stream_id} after {packets_sent} packets")
                    packets_sent = 0
        
        except asyncio.CancelledError:
            logger.info(f"TCP write loop cancelled for stream {stream.stream_id}")
        except Exception as e:
            logger.error(f"TCP write error for stream {stream.stream_id}: {e}")
        finally:
            logger.info(f"TCP write loop ended for stream {stream.stream_id}, total bytes sent: {total_bytes_sent}")
            await self.close_stream(stream)
    
    async def udp_write_loop(self, stream: WispStream):
        logger.info(f"Starting UDP write loop for stream {stream.stream_id}")
        packets_sent = 0
        total_bytes_sent = 0
        
        try:
            while not stream.closed and stream.transport:
                data = await stream.send_queue.get()
                stream.transport.sendto(data)
                
                packets_sent += 1
                total_bytes_sent += len(data)
                logger.debug(f"UDP sent {len(data)} bytes for stream {stream.stream_id} (packet {packets_sent}, total: {total_bytes_sent})")
        
        except asyncio.CancelledError:
            logger.info(f"UDP write loop cancelled for stream {stream.stream_id}")
        except Exception as e:
            logger.error(f"UDP write error for stream {stream.stream_id}: {e}")
        finally:
            logger.info(f"UDP write loop ended for stream {stream.stream_id}, total bytes sent: {total_bytes_sent}")
            await self.close_stream(stream)
    
    async def handle_data(self, ws: web.WebSocketResponse, packet: WispPacket):
        stream = self.streams.get(packet.stream_id)
        if not stream:
            logger.warning(f"DATA packet for unknown stream {packet.stream_id}")
            return
        
        if stream.closed:
            logger.warning(f"DATA packet for closed stream {packet.stream_id}")
            return
        
        if stream.stream_type in (StreamType.TCP, StreamType.TLS):
            stream.buffer_remaining -= 1
            await stream.send_queue.put(packet.payload)
            logger.debug(f"Queued TCP/TLS data for stream {packet.stream_id}: {len(packet.payload)} bytes, buffer_remaining={stream.buffer_remaining}")
            
            if stream.buffer_remaining <= self.buffer_size // 2:
                logger.debug(f"Buffer half-empty for stream {packet.stream_id}, sending CONTINUE")
                stream.buffer_remaining = self.buffer_size
                continue_packet = WispPacket(
                    PacketType.CONTINUE,
                    stream.stream_id,
                    struct.pack('<I', self.buffer_size)
                )
                await ws.send_bytes(continue_packet.encode())
        
        elif stream.stream_type == StreamType.UDP:
            await stream.send_queue.put(packet.payload)
            logger.debug(f"Queued UDP data for stream {packet.stream_id}: {len(packet.payload)} bytes")
    
    async def handle_close(self, ws: web.WebSocketResponse, packet: WispPacket):
        stream = self.streams.get(packet.stream_id)
        if stream:
            reason_code = packet.payload[0] if packet.payload else 0
            reason_name = CloseReason(reason_code).name if reason_code in CloseReason._value2member_map_ else f"UNKNOWN({reason_code})"
            logger.info(f"CLOSE request: stream_id={packet.stream_id}, reason={reason_name}")
            await self.close_stream(stream)
        else:
            logger.warning(f"CLOSE packet for unknown stream {packet.stream_id}")
    
    async def send_close(self, ws: web.WebSocketResponse, stream_id: int, reason: CloseReason):
        logger.info(f"Sending CLOSE packet for stream {stream_id}, reason={reason.name}")
        packet = WispPacket(PacketType.CLOSE, stream_id, bytes([reason]))
        await ws.send_bytes(packet.encode())
    
    async def close_stream(self, stream: WispStream):
        if stream.closed:
            return
        
        logger.info(f"Closing stream {stream.stream_id}")
        stream.closed = True
        
        if stream.read_task:
            stream.read_task.cancel()
            logger.debug(f"Cancelled read task for stream {stream.stream_id}")
        
        if stream.write_task:
            stream.write_task.cancel()
            logger.debug(f"Cancelled write task for stream {stream.stream_id}")
        
        if stream.writer:
            stream.writer.close()
            try:
                await stream.writer.wait_closed()
                logger.debug(f"TCP/TLS writer closed for stream {stream.stream_id}")
            except Exception as e:
                logger.debug(f"Error closing TCP/TLS writer for stream {stream.stream_id}: {e}")
        
        if stream.transport:
            stream.transport.close()
            logger.debug(f"UDP transport closed for stream {stream.stream_id}")
        
        self.streams.pop(stream.stream_id, None)
        logger.info(f"Stream {stream.stream_id} fully closed and removed")
    
    async def cleanup_connection(self, ws: web.WebSocketResponse, client_ip: str = "unknown"):
        stream_count = len(self.streams)
        logger.info(f"WebSocket connection closed from {client_ip}, cleaning up {stream_count} streams")
        
        for stream_id, stream in list(self.streams.items()):
            logger.info(f"Cleaning up stream {stream_id} during connection cleanup")
            await self.close_stream(stream)
        
        logger.info(f"Cleanup completed for WebSocket connection from {client_ip}")


async def init_app():
    app = web.Application()
    server = WispServer(buffer_size=256)
    
    app.router.add_get('/', server.handle_websocket)
    
    logger.info("Wisp server application initialized")
    return app


if __name__ == '__main__':
    logger.info("Starting Wisp server...")
    
    try:
        web.run_app(asyncio.run(init_app()), host='127.0.0.1', port=8080)
        logger.info("Wisp server running on ws://127.0.0.1:8080/")
    except KeyboardInterrupt:
        logger.info("Wisp server stopped by user")
    except Exception as e:
        logger.error(f"Failed to start Wisp server: {e}")