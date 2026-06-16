"""LobbyServer – TCP acceptor and main() entry point."""

import asyncio
from collections import defaultdict
import logging
import argparse
import os
from pathlib import Path
import time

from dotenv import load_dotenv
from hqnet.admin import AdminServer
from hqnet.protocol import PacketCodec, MIN_PACKET_SIZE
from hqnet.world import WorldState
from hqnet.session import ClientSession
from hqnet.chat import ChatHandler
from hqnet.metrics import Metrics, env_metrics_enabled, env_metrics_host, env_metrics_port

log = logging.getLogger('hqnet')
MAX_ACTIVE_CONNECTIONS = 512
MAX_CONNECTIONS_PER_IP = 16
ENV_PATH = Path(__file__).resolve().parent.parent / '.env'
DEFAULT_BAD_PACKET_WINDOW_SEC = 10
DEFAULT_BAD_PACKET_IP_LIMIT = 3
DEFAULT_BAD_PACKET_BAN_BASE_SEC = 60
DEFAULT_BAD_PACKET_BAN_MAX_SEC = 3600
DEFAULT_ADMIN_HOST = '127.0.0.1'
DEFAULT_ADMIN_PORT = 9110


class LobbyServer:
    def __init__(self, host: str = '127.0.0.1', port: int = 6112,
                 metrics_enabled: bool = False,
                 metrics_host: str = '127.0.0.1',
                 metrics_port: int = 9108,
                 admin_enabled: bool = False,
                 admin_host: str = DEFAULT_ADMIN_HOST,
                 admin_port: int = DEFAULT_ADMIN_PORT,
                 admin_token: str = '',
                 bad_packet_window_sec: int = DEFAULT_BAD_PACKET_WINDOW_SEC,
                 bad_packet_ip_limit: int = DEFAULT_BAD_PACKET_IP_LIMIT,
                 bad_packet_ban_base_sec: int = DEFAULT_BAD_PACKET_BAN_BASE_SEC,
                 bad_packet_ban_max_sec: int = DEFAULT_BAD_PACKET_BAN_MAX_SEC):
        self.host = host
        self.port = port
        self.started_at = time.monotonic()
        self.metrics = Metrics(metrics_enabled, metrics_host, metrics_port)
        self.world = WorldState(
            metrics=self.metrics,
            bad_packet_window_sec=bad_packet_window_sec,
            bad_packet_ip_limit=bad_packet_ip_limit,
            bad_packet_ban_base_sec=bad_packet_ban_base_sec,
            bad_packet_ban_max_sec=bad_packet_ban_max_sec,
        )
        self.active_connections = 0
        self.active_lobby_connections = 0
        self.active_chat_connections = 0
        self.active_connections_by_ip: dict[str, int] = defaultdict(int)
        if admin_enabled and not admin_token:
            log.warning('Admin server requested but HQNET_ADMIN_TOKEN is empty; admin server disabled')
        self.admin_enabled = admin_enabled and bool(admin_token)
        self.admin = (
            AdminServer(self, admin_host, admin_port, admin_token)
            if self.admin_enabled else None
        )

    @staticmethod
    def _peer_ip(addr) -> str:
        if isinstance(addr, tuple) and addr:
            return str(addr[0])
        return 'unknown'

    async def _close_writer(self, writer: asyncio.StreamWriter):
        try:
            writer.close()
            await writer.wait_closed()
        except (ConnectionError, OSError):
            pass

    async def _handle(self, reader: asyncio.StreamReader,
                      writer: asyncio.StreamWriter):
        addr = writer.get_extra_info('peername')
        peer_ip = self._peer_ip(addr)
        conn_type = ''
        blocked_for = self.world.get_bad_packet_block_remaining(peer_ip)
        if blocked_for > 0:
            if blocked_for == float('inf'):
                log.warning('Rejecting connection from %s: packet ban active (permanent)',
                            addr)
            else:
                log.warning('Rejecting connection from %s: packet ban active (%.1fs remaining)',
                            addr, blocked_for)
            self.metrics.inc_connection_rejected('packet_ban')
            await self._close_writer(writer)
            return
        if self.active_connections >= MAX_ACTIVE_CONNECTIONS:
            log.warning('Rejecting connection from %s: global cap reached (%d)',
                        addr, MAX_ACTIVE_CONNECTIONS)
            self.metrics.inc_connection_rejected('global_cap')
            await self._close_writer(writer)
            return
        if self.active_connections_by_ip[peer_ip] >= MAX_CONNECTIONS_PER_IP:
            log.warning('Rejecting connection from %s: per-IP cap reached (%d)',
                        addr, MAX_CONNECTIONS_PER_IP)
            self.metrics.inc_connection_rejected('per_ip_cap')
            await self._close_writer(writer)
            return

        self.active_connections += 1
        self.active_connections_by_ip[peer_ip] += 1
        self.metrics.inc_connection_accepted()
        self.metrics.set_active_connections(
            self.active_connections,
            self.active_lobby_connections,
            self.active_chat_connections,
        )
        log.info('New connection from %s', addr)
        try:
            # Read until we have at least one full packet
            buf = bytearray()
            while len(buf) < MIN_PACKET_SIZE:
                chunk = await asyncio.wait_for(reader.read(8192), timeout=30)
                if not chunk:
                    await self._close_writer(writer)
                    return
                buf.extend(chunk)

            payload, consumed = PacketCodec.parse_stream(buf)
            if payload is None:
                log.warning('Bad first packet from %s', addr)
                self.metrics.inc_packet_parse_failure('first_packet')
                self.metrics.inc_connection_rejected('bad_first_packet')
                ban = self.world.record_bad_packet(peer_ip, 'bad_first_packet')
                if ban["is_permanent"]:
                    log.warning(
                        'Applied packet ban ip=%s duration=permanent count=%d reason=%s',
                        peer_ip,
                        ban["ban_count"],
                        ban["reason"],
                    )
                elif ban["ban_duration_sec"] > 0:
                    log.warning(
                        'Applied packet ban ip=%s duration=%ss count=%d reason=%s blocked_until=%s',
                        peer_ip,
                        ban["ban_duration_sec"],
                        ban["ban_count"],
                        ban["reason"],
                        ban["blocked_until"],
                    )
                await self._close_writer(writer)
                return

            remaining = bytes(buf[consumed:])
            # Handshake payload: [0x00][0x0F][ver_hi][ver_lo]
            is_lobby = (len(payload) >= 2 and payload[0] == 0x00
                        and payload[1] == 0x0F)
            log.info('First packet from %s: len=%d lobby=%s',
                     addr, len(payload), is_lobby)

            if is_lobby:
                conn_type = 'lobby'
                self.active_lobby_connections += 1
                self.metrics.set_active_connections(
                    self.active_connections,
                    self.active_lobby_connections,
                    self.active_chat_connections,
                )
                session = ClientSession(reader, writer, self.world)
                session.buf.extend(remaining)
                await session.run(payload)
            else:
                conn_type = 'chat'
                self.active_chat_connections += 1
                self.metrics.set_active_connections(
                    self.active_connections,
                    self.active_lobby_connections,
                    self.active_chat_connections,
                )
                handler = ChatHandler(reader, writer, self.world)
                handler.buf.extend(remaining)
                await handler.run(payload)

        except asyncio.TimeoutError:
            log.warning('Timeout from %s', addr)
            self.metrics.inc_connection_rejected('timeout')
            await self._close_writer(writer)
        except (ConnectionError, OSError) as exc:
            log.debug('Connection error from %s: %s', addr, exc)
        finally:
            if conn_type == 'lobby':
                self.active_lobby_connections = max(0, self.active_lobby_connections - 1)
            elif conn_type == 'chat':
                self.active_chat_connections = max(0, self.active_chat_connections - 1)
            self.active_connections = max(0, self.active_connections - 1)
            if self.active_connections_by_ip[peer_ip] > 0:
                self.active_connections_by_ip[peer_ip] -= 1
            if self.active_connections_by_ip[peer_ip] <= 0:
                self.active_connections_by_ip.pop(peer_ip, None)
            self.metrics.set_active_connections(
                self.active_connections,
                self.active_lobby_connections,
                self.active_chat_connections,
            )

    async def start(self):
        if self.host == '0.0.0.0':
            log.warning('Binding to 0.0.0.0 exposes the server to the network; use a protected transport layer')
        self.metrics.start()
        if self.admin_enabled:
            log.info('Admin server enabled on %s:%d', self.admin.host, self.admin.port)
        elif os.getenv('HQNET_ADMIN_ENABLED', 'false').lower() in ('1', 'true', 'yes', 'on'):
            log.warning('Admin server remains disabled because configuration is incomplete')
        else:
            log.info('Admin server disabled')
        srv = await asyncio.start_server(self._handle, self.host, self.port)
        admin_srv = await self.admin.start() if self.admin else None
        log.info('HQNET Lobby Server listening on %s:%d', self.host, self.port)
        if admin_srv:
            async with srv, admin_srv:
                await asyncio.gather(srv.serve_forever(), admin_srv.serve_forever())
        else:
            async with srv:
                await srv.serve_forever()


def main():
    load_dotenv(ENV_PATH)
    ap = argparse.ArgumentParser(description='HQNET Lobby Server')
    ap.add_argument('--host', default=os.getenv('HQNET_HOST', '127.0.0.1'))
    ap.add_argument('--port', type=int, default=int(os.getenv('HQNET_PORT', '6112')))
    ap.add_argument('--debug', action='store_true')
    ap.add_argument('--metrics-enabled', action='store_true',
                    default=env_metrics_enabled(False))
    ap.add_argument('--metrics-host', default=env_metrics_host('127.0.0.1'))
    ap.add_argument('--metrics-port', type=int, default=env_metrics_port(9108))
    ap.add_argument('--admin-enabled', action='store_true',
                    default=os.getenv('HQNET_ADMIN_ENABLED', 'false').lower() in ('1', 'true', 'yes', 'on'))
    ap.add_argument('--admin-host', default=os.getenv('HQNET_ADMIN_HOST', DEFAULT_ADMIN_HOST))
    ap.add_argument('--admin-port', type=int, default=int(os.getenv('HQNET_ADMIN_PORT', str(DEFAULT_ADMIN_PORT))))
    ap.add_argument('--admin-token', default=os.getenv('HQNET_ADMIN_TOKEN', ''))
    args = ap.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format='%(asctime)s [%(name)s] %(levelname)s: %(message)s',
    )
    asyncio.run(LobbyServer(args.host, args.port,
                             metrics_enabled=args.metrics_enabled,
                             metrics_host=args.metrics_host,
                             metrics_port=args.metrics_port,
                             admin_enabled=args.admin_enabled,
                             admin_host=args.admin_host,
                             admin_port=args.admin_port,
                             admin_token=args.admin_token,
                             bad_packet_window_sec=int(os.getenv(
                                 'HQNET_BAD_PACKET_WINDOW_SEC',
                                 str(DEFAULT_BAD_PACKET_WINDOW_SEC),
                             )),
                             bad_packet_ip_limit=int(os.getenv(
                                 'HQNET_BAD_PACKET_IP_LIMIT',
                                 str(DEFAULT_BAD_PACKET_IP_LIMIT),
                             )),
                             bad_packet_ban_base_sec=int(os.getenv(
                                 'HQNET_BAD_PACKET_BAN_BASE_SEC',
                                 str(DEFAULT_BAD_PACKET_BAN_BASE_SEC),
                             )),
                             bad_packet_ban_max_sec=int(os.getenv(
                                 'HQNET_BAD_PACKET_BAN_MAX_SEC',
                                 str(DEFAULT_BAD_PACKET_BAN_MAX_SEC),
                             ))).start())
