"""ChatHandler – one per chat TCP connection."""

import asyncio
from collections import defaultdict, deque
import struct
import logging
import time

from hqnet.protocol import ENCODING, PacketCodec, decode_fixed
from hqnet.models import UserInfo
from hqnet.packets import pkt_chat_msg
from hqnet.world import WorldState

IDLE_CHAT_TIMEOUT_SEC = 180.0
CHAT_WINDOW_SEC = 5.0
CHAT_MESSAGES_PER_WINDOW = 8
CHAT_MAX_MESSAGE_BYTES = 512
CHAT_RATE_LIMIT_COUNTS: dict[str, int] = defaultdict(int)
SECURITY_LOG = logging.getLogger('hqnet.security')


class ChatHandler:
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                 world: WorldState):
        self.reader = reader
        self.writer = writer
        self.world = world
        self.buf = bytearray()
        self.user: UserInfo | None = None
        self._closed = False
        self._send_lock = asyncio.Lock()
        self.addr = writer.get_extra_info('peername')
        self._log = logging.getLogger(f'Chat[{self.addr}]')

    def _security_event(self, message: str, *args):
        event = message.split(' ', 1)[0]
        self.world.metrics.inc_security_event(event)
        SECURITY_LOG.warning('chat addr=%s ' + message, self.addr, *args)

    @staticmethod
    def _peer_ip(addr) -> str:
        if isinstance(addr, tuple) and addr:
            return str(addr[0])
        return ''

    async def _handle_bad_packet(self, reason: str):
        peer_ip = self._peer_ip(self.addr)
        ban = self.world.record_bad_packet(peer_ip, reason)
        self._log.warning('Bad chat packet from %s: %s', peer_ip or '?', reason)
        duration = 'permanent' if ban["is_permanent"] else str(ban["ban_duration_sec"])
        self._security_event(
            'bad_packet peer_ip=%s reason=%s duration=%s permanent=%d count=%d blocked_until=%s',
            peer_ip or '',
            reason,
            duration,
            int(ban["is_permanent"]),
            ban["ban_count"],
            ban["blocked_until"] or '',
        )
        self._closed = True

    async def _close_transport(self):
        self._closed = True
        try:
            self.writer.close()
            await self.writer.wait_closed()
        except (ConnectionError, OSError):
            pass

    async def send_payload(self, payload: bytes, *, drain: bool = True):
        if self._closed:
            return
        try:
            async with self._send_lock:
                self.writer.write(PacketCodec.build_packet(payload))
                if payload:
                    self.world.metrics.inc_packet_sent('chat', payload[0])
                if drain:
                    await self.writer.drain()
        except (ConnectionError, OSError):
            self.world.metrics.inc_send_failure('chat')
            self._closed = True

    async def send_payloads(self, payloads: list[bytes]):
        if not payloads or self._closed:
            return
        try:
            async with self._send_lock:
                for payload in payloads:
                    self.writer.write(PacketCodec.build_packet(payload))
                    if payload:
                        self.world.metrics.inc_packet_sent('chat', payload[0])
                await self.writer.drain()
        except (ConnectionError, OSError):
            self.world.metrics.inc_send_failure('chat')
            self._closed = True

    async def run(self, first_payload: bytes):
        try:
            # First packet is a small handshake byte – just consume it
            self._log.debug('Chat hello len=%d', len(first_payload))

            # Wait for identification packet  [0x12][username(21)]
            await self._identify()
            if not self.user:
                self._log.warning('Chat: identification failed')
                return

            self._log.info('Chat linked to user %s', self.user.name)

            # Main chat loop
            while not self._closed:
                data = await asyncio.wait_for(
                    self.reader.read(8192),
                    timeout=IDLE_CHAT_TIMEOUT_SEC,
                )
                if not data:
                    break
                self.buf.extend(data)
                while True:
                    payload, consumed = PacketCodec.parse_stream(self.buf)
                    if consumed == 0:
                        break
                    del self.buf[:consumed]
                    if payload is not None:
                        await self._on_chat(payload)
                    else:
                        self.world.metrics.inc_packet_parse_failure('chat_stream')
                        await self._handle_bad_packet('parse_failure')
                        break
        except asyncio.TimeoutError:
            self._log.warning('Idle timeout after %.0fs', IDLE_CHAT_TIMEOUT_SEC)
            self.world.metrics.inc_idle_timeout('chat')
            self._security_event('idle_timeout seconds=%.0f', IDLE_CHAT_TIMEOUT_SEC)
        except (ConnectionError, asyncio.CancelledError):
            pass
        finally:
            await self._cleanup()

    async def _identify(self):
        """Read packets until we get [0x12][name(21)]."""
        chat_ip = self._peer_ip(self.addr)
        while not self._closed:
            # Drain existing buffer first (identification may already be
            # here if hello + identify arrived in the same TCP read).
            while True:
                payload, consumed = PacketCodec.parse_stream(self.buf)
                if consumed == 0:
                    break
                del self.buf[:consumed]
                if payload is not None and len(payload) >= 22 and payload[0] == 0x12:
                    self.world.metrics.inc_packet_received('chat', payload[0])
                    uname = decode_fixed(payload[1:22])
                    u = self.world.users.get(uname)
                    if not u or not u.session or u.session._closed:
                        self._log.warning('Chat bind rejected for %r: no active lobby session', uname)
                        self._security_event('bind_rejected username=%r reason=no_active_lobby', uname)
                        return

                    lobby_ip = self._peer_ip(u.session.addr)
                    if lobby_ip and chat_ip and lobby_ip != chat_ip:
                        self._log.warning(
                            'Chat bind rejected for %s: lobby_ip=%s chat_ip=%s',
                            uname, lobby_ip, chat_ip)
                        self._security_event(
                            'bind_rejected username=%s reason=ip_mismatch lobby_ip=%s chat_ip=%s',
                            uname, lobby_ip, chat_ip)
                        return

                    existing = u.chat_handler
                    if existing and existing is not self and not existing._closed:
                        existing_ip = self._peer_ip(existing.addr)
                        if existing_ip and chat_ip and existing_ip != chat_ip:
                            self._log.warning(
                                'Chat rebind rejected for %s: existing_ip=%s chat_ip=%s',
                                uname, existing_ip, chat_ip)
                            self._security_event(
                                'rebind_rejected username=%s reason=existing_ip_mismatch existing_ip=%s chat_ip=%s',
                                uname, existing_ip, chat_ip)
                            return
                        existing._closed = True
                        self._security_event(
                            'rebind_replace username=%s existing_addr=%s new_addr=%s',
                            uname, existing.addr, self.addr)
                        try:
                            existing.writer.close()
                        except (ConnectionError, OSError):
                            pass

                    self.user = u
                    u.chat_handler = self
                    return
            # Need more data
            data = await asyncio.wait_for(self.reader.read(8192), timeout=30)
            if not data:
                return
            self.buf.extend(data)

    @staticmethod
    def _prune_timestamps(timestamps: deque[float], now: float):
        while timestamps and now - timestamps[0] > CHAT_WINDOW_SEC:
            timestamps.popleft()

    def _allow_chat_message(self) -> bool:
        if not self.user:
            return False
        now = time.monotonic()
        timestamps = getattr(self.world, 'chat_message_times', None)
        if timestamps is None:
            timestamps = self.world.chat_message_times = defaultdict(deque)
        user_timestamps = timestamps[self.user.name]
        self._prune_timestamps(user_timestamps, now)
        if len(user_timestamps) >= CHAT_MESSAGES_PER_WINDOW:
            CHAT_RATE_LIMIT_COUNTS[self.user.name] += 1
            self.world.metrics.inc_chat_rate_limited()
            self._log.warning('Chat rate limit hit for %s count=%d',
                              self.user.name, CHAT_RATE_LIMIT_COUNTS[self.user.name])
            self._security_event('rate_limit username=%s count=%d',
                                 self.user.name, CHAT_RATE_LIMIT_COUNTS[self.user.name])
            return False
        user_timestamps.append(now)
        return True

    async def _on_chat(self, payload: bytes):
        """Client sends: [0x02][len(2,BE)][sub_type][data...]
        sub_type 0x02 = normal chat: data = message bytes
        sub_type 0x03 = whisper:     data = [target(21)][message bytes]
        """
        if not payload or payload[0] != 0x02 or len(payload) < 4:
            return
        self.world.metrics.inc_packet_received('chat', payload[0])
        msg_len = struct.unpack('>H', payload[1:3])[0]
        if len(payload) < 3 + msg_len or msg_len < 1:
            return
        sub_type = payload[3]
        data = payload[4:3 + msg_len]

        if sub_type == 0x02:
            # Normal chat message
            if len(data) > CHAT_MAX_MESSAGE_BYTES or not self._allow_chat_message():
                return
            self.world.metrics.inc_chat_message('channel')
            message = data.decode(ENCODING, errors='replace')
            self._log.debug('Chat from %s len=%d',
                            self.user.name if self.user else '?', len(message))
            # Delegate slash commands to lobby session handler
            if message.startswith('/') and self.user and self.user.session:
                self.world.metrics.inc_chat_message('slash')
                cmd = message.split()[0].upper()
                if cmd in ('/GUILD', '/길드'):
                    await self.user.session.handle_guild_command(message)
                    return
            if self.user and self.user.channel:
                out = pkt_chat_msg(0, self.user.name, message)
                await self.world.broadcast_chat(self.user.channel, out,
                                                sender=self.user.name)
                self.world.db.log_chat(self.user.channel, self.user.name, message)
        elif sub_type == 0x03:
            # Whisper: [target(21)][message]
            if len(data) < 22:
                return
            if len(data) > CHAT_MAX_MESSAGE_BYTES or not self._allow_chat_message():
                return
            self.world.metrics.inc_chat_message('whisper')
            target = decode_fixed(data[0:21])
            message = data[21:].decode(ENCODING, errors='replace')
            self._log.debug('Whisper from %s to %s len=%d',
                            self.user.name if self.user else '?', target, len(message))
            if self.user and target:
                tu = self.world.users.get(target)
                if tu and tu.chat_handler:
                    await tu.chat_handler.send_payload(
                        pkt_chat_msg(1, self.user.name, message))
                    self.world.db.log_chat(
                        self.user.channel or '', self.user.name, message,
                        kind='whisper', target=target)

    async def _cleanup(self):
        self._closed = True
        self.world.metrics.inc_disconnect('chat')
        if self.user and self.user.chat_handler is self:
            self.user.chat_handler = None
        await self._close_transport()
