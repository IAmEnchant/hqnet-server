"""ClientSession – one per lobby TCP connection."""

import asyncio
from collections import defaultdict
import logging
import socket
import struct
import time

from hqnet.protocol import PacketCodec, decode_fixed
from hqnet.models import UserInfo, GameInfo, State
from hqnet.packets import (
    pkt_ack1, pkt_ack2, pkt_proceed, pkt_grade, pkt_auth_ok,
    pkt_login_ok, pkt_login_fail,
    pkt_channel_list, pkt_user_list, pkt_user_details,
    pkt_user_add, pkt_user_remove,
    pkt_user_detail_add, pkt_user_detail_remove, pkt_game_room_details,
    pkt_game_list, pkt_game_remove, pkt_user_add_76,
    pkt_game_options,
    pkt_game_create_ok, pkt_game_create_fail,
    pkt_join_ok, pkt_join_fail,
    pkt_p2p_ok,
    pkt_char_select_ok,
    pkt_chat_server_info,
    pkt_guild_screen,
    pkt_guild_info_result, pkt_channel_info,
    pkt_password_change,
    pkt_heartbeat_ack,
    pkt_disconnect,
    pkt_chat_msg,
    pkt_name_change,
    pkt_account_check,
)
from hqnet.world import WorldState

# Client→server opcodes that arrive periodically and need no response.
_HEARTBEAT_OPCODES = frozenset({
    0x07,   # General heartbeat/ping – sent from many client states
})
SLOW_LOBBY_BUILD_MS = 10.0
SLOW_LOBBY_BUILD_COUNTS: dict[str, int] = defaultdict(int)
IDLE_SESSION_TIMEOUT_SEC = 180.0
MIN_GAME_RESULT_SECONDS = 20.0
PUBLIC_LOGIN_FAIL_CODE = 4
SECURITY_LOG = logging.getLogger('hqnet.security')

# All previously-ignored opcodes are now handled in the dispatch table.
_LOGGED_IN_HANDLER_NAMES = {
    0x02: '_on_lobby_chat',
    0x16: '_on_account_manage',
    0x18: '_on_channel_switch',
    0x19: '_on_game_create',
    0x20: '_on_game_join',
    0x21: '_on_p2p_setup',
    0x22: '_on_heartbeat',
    0x23: '_on_p2p_state',
    0x25: '_on_game_room_init',
    0x26: '_on_lobby_ready',
    0x27: '_on_game_list_resync',
    0x28: '_on_user_list_resync',
    0x29: '_on_game_room_ready',
    0x31: '_on_player_stats',
    0x36: '_on_player_info',
    0x37: '_on_guild_register',
    0x40: '_on_char_select_confirm',
    0x41: '_on_inquiry',
}

class ClientSession:
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                 world: WorldState):
        self.reader = reader
        self.writer = writer
        self.world = world
        self.state = State.AWAIT_HANDSHAKE
        self.buf = bytearray()
        self.user: UserInfo | None = None
        self.addr = writer.get_extra_info('peername')
        self._closed = False
        self._lobby_entered = False   # True after first 0x26 (lobby ready)
        self._send_lock = asyncio.Lock()
        self._logged_in_handlers = {
            op: getattr(self, handler_name)
            for op, handler_name in _LOGGED_IN_HANDLER_NAMES.items()
        }
        self._log = logging.getLogger(f'Lobby[{self.addr}]')

    @staticmethod
    def _peer_ip(addr) -> str:
        if isinstance(addr, tuple) and addr:
            return str(addr[0])
        return ''

    def _security_event(self, message: str, *args):
        event = message.split(' ', 1)[0]
        self.world.metrics.inc_security_event(event)
        SECURITY_LOG.warning('session addr=%s user=%s ' + message,
                             self.addr, self.user.name if self.user else '',
                             *args)

    async def _handle_bad_packet(self, reason: str):
        peer_ip = self._peer_ip(self.addr)
        ban = self.world.record_bad_packet(peer_ip, reason)
        self._log.warning('Bad lobby packet from %s: %s', peer_ip or '?', reason)
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

    # ── I/O ──────────────────────────────────────────────────────────────────

    async def send_payload(self, payload: bytes, *, drain: bool = True):
        if self._closed:
            return
        try:
            async with self._send_lock:
                self.writer.write(PacketCodec.build_packet(payload))
                if payload:
                    self.world.metrics.inc_packet_sent('lobby', payload[0])
                if drain:
                    await self.writer.drain()
        except (ConnectionError, OSError):
            self.world.metrics.inc_send_failure('lobby')
            self._closed = True

    async def send_payloads(self, payloads: list[bytes]):
        if not payloads or self._closed:
            return
        try:
            async with self._send_lock:
                for payload in payloads:
                    self.writer.write(PacketCodec.build_packet(payload))
                    if payload:
                        self.world.metrics.inc_packet_sent('lobby', payload[0])
                await self.writer.drain()
        except (ConnectionError, OSError):
            self.world.metrics.inc_send_failure('lobby')
            self._closed = True

    # ── main loop ─────────────────────────────────────────────────────────────

    async def run(self, first_payload: bytes):
        try:
            await self._on_payload(first_payload)
            while not self._closed:
                data = await asyncio.wait_for(
                    self.reader.read(8192),
                    timeout=IDLE_SESSION_TIMEOUT_SEC,
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
                        await self._on_payload(payload)
                    else:
                        self.world.metrics.inc_packet_parse_failure('lobby_stream')
                        await self._handle_bad_packet('parse_failure')
                        break
        except asyncio.TimeoutError:
            self._log.warning('Idle timeout after %.0fs', IDLE_SESSION_TIMEOUT_SEC)
            self.world.metrics.inc_idle_timeout('lobby')
            self._security_event('idle_timeout seconds=%.0f', IDLE_SESSION_TIMEOUT_SEC)
        except (ConnectionError, asyncio.CancelledError):
            pass
        finally:
            await self._cleanup()

    # ── payload dispatcher ────────────────────────────────────────────────────

    async def _on_payload(self, payload: bytes):
        if not payload:
            return
        op = payload[0]
        self.world.metrics.inc_packet_received('lobby', op)
        self._log.debug('state=%s op=0x%02X len=%d', self.state.name, op, len(payload))

        if self.state == State.AWAIT_HANDSHAKE:
            # [0x00][0x0F][ver_hi][ver_lo]
            if op == 0x00 and len(payload) >= 2 and payload[1] == 0x0F:
                self._log.info('Handshake 0x0F (ver=%s)',
                               payload[2:4].hex() if len(payload) >= 4 else '?')
                await self.send_payload(pkt_ack1())
                self.state = State.SENT_ACK1

        elif self.state == State.SENT_ACK1:
            if op == 0x01:
                self._log.info('ACK1 echo')
                await self.send_payload(pkt_ack2())
                self.state = State.SENT_ACK2

        elif self.state == State.SENT_ACK2:
            # Client echoes [0x03][00 00 00 00] – accept any opcode here
            self._log.info('ACK2 echo (op=0x%02X)', op)
            await self.send_payload(pkt_proceed())
            self.state = State.AWAIT_AUTH

        elif self.state == State.AWAIT_AUTH:
            if op == 0x42:   # [42][token(16)]
                self._log.info('Auth token (%d bytes)', len(payload) - 1)
                # Send empty grade to suppress a spurious chat-log entry on the client
                await self.send_payloads([
                    pkt_grade(0, '', ''),
                    pkt_auth_ok(),
                ])
                self.state = State.AWAIT_LOGIN

        elif self.state == State.AWAIT_LOGIN:
            if op == 0x14:   # [14][id(21)][pw(21)] – register
                await self._do_register(payload)
            elif op == 0x12:  # [12][id(21)][pw(21)] – login
                await self._do_login(payload)
            elif op == 0x16:  # [16][id(21)][pw(21)][name(20)][pad(1)] – password change
                await self._on_account_manage_prelogin(payload)

        elif self.state == State.LOGGED_IN:
            await self._dispatch(op, payload)

    # ── credentials ───────────────────────────────────────────────────────────

    def _parse_credentials(self, payload: bytes) -> tuple[str, str]:
        """Parse [id(21)][pw(21)] starting at offset 1."""
        username = decode_fixed(payload[1:22])
        password = decode_fixed(payload[22:43])
        return username, password

    # ── register ──────────────────────────────────────────────────────────────

    async def _do_register(self, payload: bytes):
        if len(payload) < 43:
            self._log.warning('Register packet too short (%d)', len(payload))
            return
        username, password = self._parse_credentials(payload)
        if not self.world.is_valid_account_name(username):
            self._log.warning('Register rejected: invalid username %r', username)
            self.world.metrics.inc_register_attempt('invalid')
            await self.send_payload(pkt_account_check(2))
            return
        self._log.info('Register user=%s', username)
        if not self.world.db.register(username, password):
            self._log.warning('Register failed (duplicate): %s', username)
            self.world.metrics.inc_register_attempt('duplicate')
            await self.send_payload(pkt_account_check(1))
            return
        self.world.metrics.inc_register_attempt('success')
        peer_ip = self.addr[0] if self.addr else 'unknown'
        self.world.db.log_connection('register', username, peer_ip)
        # 0x14 registration returns to the login screen through 0x64 sub 0.
        await self.send_payload(pkt_account_check(0))

    # ── login ─────────────────────────────────────────────────────────────────

    async def _do_login(self, payload: bytes):
        if len(payload) < 43:
            self._log.warning('Login packet too short (%d)', len(payload))
            return
        username, password = self._parse_credentials(payload)
        peer_ip = self.addr[0] if self.addr else 'unknown'
        self._log.info('Login user=%s', username)
        blocked_for = self.world.get_auth_block_remaining(peer_ip, username)
        if blocked_for > 0:
            self._log.warning('Login throttled for %s from %s (%.1fs remaining)',
                              username, peer_ip, blocked_for)
            self.world.metrics.inc_login_attempt('throttled')
            self._security_event('login_throttled username=%s peer_ip=%s remaining=%.1f',
                                 username, peer_ip, blocked_for)
            await self.send_payload(pkt_login_fail(4))
            return
        result = self.world.db.authenticate(username, password)
        if result != 0:
            self.world.record_auth_failure(peer_ip, username)
            self.world.metrics.inc_login_attempt('fail')
            self._log.warning('Login failed for %s (reason=%d)', username, result)
            self._security_event('login_failed username=%s peer_ip=%s reason=%d',
                                 username, peer_ip, result)
            self.world.db.log_connection('login_fail', username, peer_ip,
                                          detail=f'reason={result}')
            await self.send_payload(pkt_login_fail(PUBLIC_LOGIN_FAIL_CODE))
            return
        self.world.clear_auth_failures(peer_ip, username)
        self.world.metrics.inc_login_attempt('success')
        self.world.db.log_connection('login', username, peer_ip)
        await self._enter_lobby(username)

    # ── lobby entry ───────────────────────────────────────────────────────────

    async def _enter_lobby(self, username: str):
        # Kick any existing session for this username
        if username in self.world.users:
            old = self.world.users[username]
            if old.session:
                self._security_event('session_replaced username=%s old_addr=%s new_addr=%s',
                                     username, old.session.addr, self.addr)
                await old.session.send_payload(pkt_disconnect())
                old.session._closed = True
            self.world.remove_user(username)

        peer_ip = self.addr[0] if self.addr else '127.0.0.1'
        self.user = self.world.add_user(username, username, peer_ip=peer_ip)
        self.user.session = self

        ch_name = 'General'
        self.world.join_channel(username, ch_name)

        # 0x62 sub 0 – the only value that makes the client enter the lobby (CRITICAL)
        payloads = [pkt_login_ok()]

        # Lobby data sent immediately after login_ok (buffered in TCP)
        payloads.extend(self._build_lobby_payloads(ch_name))
        await self.send_payloads(payloads)

        self.state = State.LOGGED_IN
        self._log.info('User %s logged in (channel=%s)', username, ch_name)

    # ── lobby data helper ─────────────────────────────────────────────────────

    def _build_lobby_payloads(self, ch_name: str) -> list[bytes]:
        started = time.perf_counter()
        """Send 0x04 → 0x74 → 0x75 → 0x76 for the given channel.
        Widget separation:
        - 0x74 → 대화방 설정 (chat-room settings) widget
        - 0x76 → lobby participant list widget
        0x74/0x75 use a SEPARATE widget NOT wiped by 0x76.
        So channel names go into 0x74 (for 대화방 설정) and user entries
        go into 0x76 (for lobby participant list).
        """
        ch = self.world.channels.get(ch_name)
        if not ch:
            return []

        # Send sub-2 removes for games removed during this server session.
        payloads = [pkt_game_remove(gname) for gname in ch.stale_game_removes]

        ch_names = list(self.world.channels.keys())
        payloads.append(pkt_channel_list(ch_names))
        # 0x74: channel names → 대화방 설정 widget reads this
        payloads.append(pkt_user_list(ch_names))
        self.world.refresh_channel_profiles(ch_name)
        infos = self.world.get_channel_users(ch_name)
        payloads.append(pkt_user_details(infos))
        # 0x76: users only → lobby reads this
        payloads.append(pkt_game_list([], infos))

        self._log.debug('Lobby data: ch=%s users=%d channels=%d',
                        ch_name, len(ch.users), len(ch_names))
        elapsed_ms = (time.perf_counter() - started) * 1000
        self.world.metrics.observe_lobby_build(
            elapsed_ms, slow=elapsed_ms >= SLOW_LOBBY_BUILD_MS
        )
        if elapsed_ms >= SLOW_LOBBY_BUILD_MS:
            SLOW_LOBBY_BUILD_COUNTS[ch_name] += 1
            self._log.debug('Slow lobby payload build %.2fms ch=%s users=%d channels=%d count=%d',
                            elapsed_ms, ch_name, len(ch.users), len(ch_names),
                            SLOW_LOBBY_BUILD_COUNTS[ch_name])
        return payloads

    async def _send_lobby_data(self, ch_name: str):
        payloads = self._build_lobby_payloads(ch_name)
        if payloads:
            await self.send_payloads(payloads)

    # ── logged-in dispatch ────────────────────────────────────────────────────

    async def _dispatch(self, op: int, payload: bytes):
        if op in _HEARTBEAT_OPCODES:
            return  # periodic heartbeat – no response needed

        handler = self._logged_in_handlers.get(op)

        if handler:
            await handler(payload)
        else:
            self._log.debug('Unhandled opcode 0x%02X (%d bytes)', op, len(payload))

    # ── 0x16 – account management (password change) ────────────────────────

    async def _on_account_manage_prelogin(self, payload: bytes):
        """0x16 in AWAIT_LOGIN state — password change before login.
        Format: [16][id(21)][old_pw(21)][new_pw(20)][pad(1)] = 64 bytes.
        Field mapping:
          param_1=[1:22]  username
          param_2=[22:43] current password (21 bytes)
          param_3=[43:63] new password (20 bytes)
          param_4=NOT SENT (confirm, compared with param_3 client-side)
        Response: 0x66 sub 0 (success) or sub 1 (fail). No 0x64 needed.
        """
        if len(payload) < 64:
            return
        uid = decode_fixed(payload[1:22])
        old_pw = decode_fixed(payload[22:43])
        new_pw = decode_fixed(payload[43:63])
        peer_ip = self.addr[0] if self.addr else 'unknown'
        self._log.info('Password change (prelogin) for uid=%s', uid)
        if not uid or not new_pw:
            await self.send_payload(pkt_password_change(1))
            return
        blocked_for = self.world.get_password_change_block_remaining(peer_ip, uid)
        if blocked_for > 0:
            self._log.warning('Password change throttled for %s from %s (%.1fs remaining)',
                              uid, peer_ip, blocked_for)
            self._security_event('password_change_throttled username=%s peer_ip=%s remaining=%.1f',
                                 uid, peer_ip, blocked_for)
            await self.send_payload(pkt_password_change(1))
            return
        # Verify current password
        auth = self.world.db.authenticate(uid, old_pw)
        if auth != 0:
            self.world.record_password_change_failure(peer_ip, uid)
            self._log.warning('Password change failed: bad credentials for %s (reason=%d)',
                              uid, auth)
            self._security_event('password_change_failed username=%s peer_ip=%s reason=%d',
                                 uid, peer_ip, auth)
            await self.send_payload(pkt_password_change(1))
            return
        if not self.world.db.set_password(uid, new_pw):
            self._log.warning('Password change failed: account not found %s', uid)
            await self.send_payload(pkt_password_change(1))
            return
        self.world.clear_password_change_failures(peer_ip, uid)
        self.world.db.log_connection('password_change', uid, peer_ip)
        await self.send_payload(pkt_password_change(0))
        self._log.info('Password changed for %s', uid)

    async def _on_account_manage(self, payload: bytes):
        """0x16 in LOGGED_IN state — password change after login.
        Same format: [16][id(21)][old_pw(21)][new_pw(20)][pad(1)].
        """
        if len(payload) < 64:
            return
        if not self.user:
            await self.send_payload(pkt_password_change(1))
            return
        uid = decode_fixed(payload[1:22])
        old_pw = decode_fixed(payload[22:43])
        new_pw = decode_fixed(payload[43:63])
        peer_ip = self.addr[0] if self.addr else 'unknown'
        self._log.info('Account manage (0x16) from %s: uid=%s', self.user.name, uid)
        if not uid or not new_pw:
            await self.send_payload(pkt_password_change(1))
            return
        if uid != self.user.name:
            self._log.warning('Password change rejected: %s tried to change %s',
                              self.user.name, uid)
            await self.send_payload(pkt_password_change(1))
            return
        blocked_for = self.world.get_password_change_block_remaining(peer_ip, uid)
        if blocked_for > 0:
            self._log.warning('Password change throttled for %s from %s (%.1fs remaining)',
                              uid, peer_ip, blocked_for)
            self._security_event('password_change_throttled username=%s peer_ip=%s remaining=%.1f',
                                 uid, peer_ip, blocked_for)
            await self.send_payload(pkt_password_change(1))
            return
        auth = self.world.db.authenticate(uid, old_pw)
        if auth != 0:
            self.world.record_password_change_failure(peer_ip, uid)
            self._log.warning('Password change rejected: bad current password for %s', uid)
            self._security_event('password_change_failed username=%s peer_ip=%s reason=%d',
                                 uid, peer_ip, auth)
            await self.send_payload(pkt_password_change(1))
            return
        if not self.world.db.set_password(uid, new_pw):
            self._log.warning('Password change: no DB row for %s', uid)
            await self.send_payload(pkt_password_change(1))
            return
        self.world.clear_password_change_failures(peer_ip, uid)
        self.world.db.log_connection('password_change', uid, peer_ip)
        await self.send_payload(pkt_password_change(0))
        self._log.info('Password changed for %s', uid)

    # ── 0x22 – interval heartbeat ───────────────────────────────────────────

    async def _on_heartbeat(self, _p: bytes):
        """0x22 – interval heartbeat (every ~2s). Respond with 0x72 sub 0 ACK."""
        await self.send_payload(pkt_heartbeat_ack())

    # ── 0x23 – P2P game state signal ────────────────────────────────────────

    async def _on_p2p_state(self, payload: bytes):
        """0x23 – P2P game result signal from the game room.
        Format: [23][sub(1)][value(4,BE)] = 6 bytes.
        Sent after P2P game ends. Client retries until 0x71 response received.
        sub=1, value=0 observed after WIN. Need more data for loss/draw.
        Response: 0x71 sub 0 → clean return to lobby.
        """
        if not self.user or len(payload) < 6:
            return
        sub = payload[1]
        value = struct.unpack('>I', payload[2:6])[0]
        self._log.info('P2P result from %s: sub=%d value=%d',
                        self.user.name, sub, value)
        game = self.world.get_game_for_player(self.user.name)
        if not game or self.user.name not in game.players:
            self._log.warning('Rejected game result from %s: no active game', self.user.name)
            self._security_event('game_result_rejected reason=no_active_game sub=%d', sub)
            await self.send_payload(pkt_p2p_ok())
            return
        if len(game.players) < 2:
            self._log.warning('Rejected game result from %s: player_count=%d',
                              self.user.name, len(game.players))
            self._security_event('game_result_rejected reason=not_enough_players sub=%d players=%d',
                                 sub, len(game.players))
            await self.send_payload(pkt_p2p_ok())
            return
        if game.created_at and (time.monotonic() - game.created_at) < MIN_GAME_RESULT_SECONDS:
            elapsed = time.monotonic() - game.created_at
            self._log.warning('Rejected game result from %s: too fast (%.1fs)',
                              self.user.name, elapsed)
            self._security_event('game_result_rejected reason=too_fast sub=%d elapsed=%.1f',
                                 sub, elapsed)
            await self.send_payload(pkt_p2p_ok())
            return
        if self.user.name in game.result_submissions:
            self._log.warning('Rejected duplicate game result from %s', self.user.name)
            self._security_event('game_result_rejected reason=duplicate sub=%d', sub)
            await self.send_payload(pkt_p2p_ok())
            return
        game.result_submissions.add(self.user.name)
        # Snapshot players on first result so we can infer missing results later
        if not game.all_players_snapshot:
            game.all_players_snapshot = list(game.players)

        # Clean up game room
        ch_name = self.user.channel
        if ch_name:
            await self._cleanup_games(ch_name)

        # Update stats: sub=1=WIN, sub=2=LOSS, sub=3=DRAW (value always 0)
        if sub == 1:
            self.user.wins += 1
            self.world.metrics.inc_match_result('win')
        elif sub == 2:
            self.user.losses += 1
            self.world.metrics.inc_match_result('loss')
        elif sub == 3:
            self.user.draws += 1
            self.world.metrics.inc_match_result('draw')
        else:
            self.world.metrics.inc_match_result('unknown')
        prev_rank = self.user.rank
        prev_grade = self.user.grade
        self.world.metrics.inc_rank_recalculation()
        self.user.rank, self.user.grade = self.world.db.calculate_progression(
            self.user.wins,
            self.user.losses,
            self.user.draws,
        )
        self._log.info('Game result for %s: sub=%d → W%d/L%d/D%d',
                       self.user.name, sub, self.user.wins, self.user.losses, self.user.draws)
        self.world.db.update_stats(
            self.user.name,
            wins=self.user.wins, losses=self.user.losses, draws=self.user.draws,
            rank=self.user.rank,
        )
        self.world.db.record_match_result(self.user.name, sub)
        result_label = {1: 'win', 2: 'loss', 3: 'draw'}.get(sub, f'unknown({sub})')
        self.world.db.log_game_event(
            'result', self.user.name,
            channel=ch_name or '',
            room_name=game.name if game else '',
            map_name=game.map_name if game else '',
            detail=result_label,
        )
        self.world.refresh_user_profile(self.user.name)
        if self.user.rank != prev_rank or self.user.grade != prev_grade:
            self._log.info('Progression updated for %s: rank=%d grade=%s',
                           self.user.name, self.user.rank, self.user.grade)

        # Infer opposite result for opponents who haven't reported
        self.world.apply_inferred_result(game, self.user.name, sub)

        # Send 0x71 sub 0 → client returns to lobby cleanly
        await self.send_payload(pkt_p2p_ok())

    # ── 0x18 – channel switch ──────────────────────────────────────────────────

    async def _on_channel_switch(self, payload: bytes):
        """0x18 – channel switch [18][channel_name(20)] = 21 bytes.
        Client confirms the channel-switch dialog → this packet.
        Response: 0x68 sub 0 → client returns to the lobby and re-enters via 0x26.
        """
        if not self.user or len(payload) < 21:
            return
        new_ch = decode_fixed(payload[1:21])
        if not new_ch or not self.world.is_valid_channel_name(new_ch):
            return

        old_ch = self.user.channel
        if old_ch == new_ch:
            await self.send_payload(pkt_name_change(0))
            return

        self._log.info('Channel switch: %s → %s → %s', self.user.name, old_ch, new_ch)
        peer_ip = self.addr[0] if self.addr else ''
        self.world.db.log_connection('channel_switch', self.user.name, peer_ip,
                                      detail=f'{old_ch} -> {new_ch}')

        # 1) Clean up game rooms in old channel
        if old_ch:
            await self._cleanup_games(old_ch)

        # 2) Broadcast departure to old channel
        if old_ch:
            await self.world.broadcast_lobby_payloads(
                old_ch,
                [
                    pkt_user_remove(self.user.name),
                    pkt_user_detail_remove(self.user.name, self.user.user_id),
                    pkt_game_remove(self.user.name),
                ],
                exclude=self.user.name,
            )

        # 3) Switch channel (world state)
        self.world.switch_channel(self.user.name, new_ch)

        # 4) Refresh the lobby header channel name immediately.
        # Some clients keep the previous 0x63 header field after channel switch.
        await self.send_payload(pkt_chat_server_info(self.user, new_ch))

        # 5) Reset lobby_entered so next 0x26 broadcasts arrival to new channel
        self._lobby_entered = False

        # 5) 0x68 sub 0 → client returns to lobby → sends 0x26
        await self.send_payload(pkt_name_change(0))

    # ── 0x26 – lobby ready ────────────────────────────────────────────────────

    async def _on_lobby_ready(self, _p: bytes):
        """0x26 – sent after lobby screen init.
        Called on first login AND on every return from a game.
        Cleans up stale game state, refreshes lobby data, and opens the chat socket.
        """
        if not self.user:
            return
        ch_name = self.user.channel
        if not ch_name:
            return

        self._log.info('Lobby ready for %s (ch=%s)', self.user.name, ch_name)

        # Clean up any stale game state from a finished/failed game.
        # After a normal game end, client returns to the lobby without sending 0x21,
        # so the server must clean up here.
        await self._cleanup_games(ch_name)

        # Refresh: 0x04 → 0x74 → 0x75 → 0x76
        await self._send_lobby_data(ch_name)

        # 0x63 – triggers client to open the chat TCP socket
        # name field → rendered as "[ %s ]" in the lobby header
        # Pass channel name so header shows "[ General ]" instead of username
        await self.send_payload(pkt_chat_server_info(self.user, ch_name))
        self.world.refresh_channel_profiles(ch_name)
        infos = self.world.get_channel_users(ch_name)
        await self.send_payloads([
            pkt_user_details(infos),
            pkt_game_list([], infos),
        ])

        if not self._lobby_entered:
            # First 0x26 after login: broadcast full arrival to others
            self._lobby_entered = True
            await self.world.broadcast_lobby_payloads(
                ch_name,
                [
                    pkt_user_add(self.user.name),
                    pkt_user_detail_add(self.user),
                    pkt_user_add_76(self.user),
                ],
                exclude=self.user.name,
            )
        else:
            # Subsequent 0x26 (return from game): only broadcast status update.
            # User is already in others' 0x74/0x76 lists; sending sub-1 again
            # would create duplicates.  0x75 sub-1 refreshes the user's state.
            await self.world.broadcast_lobby(
                ch_name, pkt_user_detail_add(self.user), exclude=self.user.name)

    # ── 0x19 – create game room ───────────────────────────────────────────────

    async def _on_game_create(self, payload: bytes):
        """0x19 – create game room (CREATE path).
        Format: [19][name(20)][map(21)][room_mode(1)] = 43 bytes.
        room_mode is the create UI selection: 1=1:1, 2=2:2, 3=3:3, 4=4:4.
        Client retries every 2s until it receives the response.

        Response: 0x69 sub 0 → client opens the DirectPlay session in CREATE mode.
        Creator becomes DP HOST: binds port 2560 and listens for joiner connection.
        """
        if not self.user or len(payload) < 43:
            await self.send_payload(pkt_game_create_fail())
            return

        gname     = decode_fixed(payload[1:21])   # name:  20 bytes, no null
        map_name  = decode_fixed(payload[21:42])  # map:   21 bytes, null-terminated
        room_mode = payload[42]

        if not gname:
            await self.send_payload(pkt_game_create_fail())
            return

        ch_name = self.user.channel or 'General'

        # Remove any stale room from a previous failed create attempt by this host
        # (client retries 0x19 every 2s until it gets a response)
        old = self.world.games.get(gname)
        if old:
            self.world.remove_game(gname, ch_name=ch_name)

        # Register the game in world state.
        # Encode host IP for the 0x75 packet: inet_aton gives network byte order,
        # reversed for the big-endian packet encoding the x86 client reads as a
        # uint32 and decodes back to a dotted IP.
        peer_ip = self.addr[0] if self.addr else '127.0.0.1'
        host_ip = socket.inet_aton(peer_ip)[::-1]
        team_size = room_mode if 1 <= room_mode <= 4 else 1
        g = GameInfo(
            name=gname,
            map_name=map_name,
            host=self.user.name,
            host_ip=host_ip,
            max_players=team_size * 2,
            team_size=team_size,
        )
        g.created_at = time.monotonic()
        g.players.append(self.user.name)
        self.world.add_game(g, ch_name)
        self.world.metrics.inc_game_create()

        # Keep user_type=0 during game setup (설정중).
        # 0x75 type byte controls join button enablement on the client:
        #   grade != 0 AND type == 0 → button enabled (joinable)
        #   type != 0 → button disabled ("[게임중]", not joinable)
        # Setting type=1 here would prevent anyone from joining the room.
        # type=1 should only be set when the game is actively playing,
        # but that signal travels via P2P and doesn't reach the server.

        self._log.info(
            'Game created: %s map=%s host=%s mode=%d:%d max_players=%d',
            gname,
            map_name,
            self.user.name,
            team_size,
            team_size,
            g.max_players,
        )
        self.world.db.log_game_event(
            'create', self.user.name, channel=ch_name,
            room_name=gname, map_name=map_name,
            detail=f'mode={team_size}v{team_size}',
        )
        await self.send_payload(pkt_game_create_ok())

    # ── 0x20 – join game room ─────────────────────────────────────────────────

    async def _on_game_join(self, payload: bytes):
        """0x20 – join game room (JOIN path).
        Format: [20][name(20)][map(21)][ip_addr(4)] = 46 bytes.
        ip_addr is the creator's IP (taken from the join dialog).
        Client retries every 2s until it receives the response.

        Response: 0x70 sub 0 → client enumerates sessions and opens in JOIN mode.
        Joiner becomes DP CLIENT: connects to creator's DP session on port 2560.
        """
        if not self.user or len(payload) < 46:
            self.world.metrics.inc_game_join('fail')
            await self.send_payload(pkt_join_fail())
            return

        gname = decode_fixed(payload[1:21])   # name: 20 bytes, no null
        game  = self.world.games.get(gname)
        if not game or len(game.players) >= game.max_players:
            self.world.metrics.inc_game_join('fail')
            await self.send_payload(pkt_join_fail())
            return

        # Guard against duplicate registration on 0x20 retry (client retries every 2s)
        is_new = self.user.name not in game.players
        if is_new:
            self.world.add_player_to_game(gname, self.user.name)
            self.world.db.log_game_event(
                'join', self.user.name,
                channel=self.user.channel or '',
                room_name=gname, map_name=game.map_name,
            )
        # Keep user_type=0 — same reasoning as _on_game_create.
        # Joiner is entering the game room but game hasn't started yet.

        await self.send_payload(pkt_join_ok())
        self.world.metrics.inc_game_join('success')
        self._log.info('User %s joined game %s', self.user.name, gname)

        # Broadcast 0x76 sub 1 (user add) to ALL room members (host + joiner).
        # Host (room-ready, flag==0) receives this and sends 0x29 → server
        # responds with full room state (0x76 sub 0 + 0x81).
        # Joiner also receives this → same 0x29 flow.
        if is_new:
            await self.world.broadcast_game_players(
                game, pkt_user_add_76(self.user))

    # ── 0x21 – P2P host setup signal ─────────────────────────────────────────

    async def _on_p2p_setup(self, _p: bytes):
        """0x21 – sent from game room states when exiting or when P2P fails.

        Creator (DP HOST): exits game room → 0x21.
        Joiner (DP CLIENT): 0x70 sub 0 → EnumSessions failed → 0x21.

        Response: 0x71 sub 0 – silent return to lobby.
        (sub 1 would show error dialog "방장이나 이용자의 통신 상태가 고르지 못합니다")
        """
        if not self.user:
            return

        ch_name = self.user.channel

        # 1) Host path: remove hosted game(s)
        hosted_game = self.world.get_hosted_game(self.user.name)
        if hosted_game:
            gn = hosted_game.name
            self.world.remove_game(gn, ch_name=ch_name)
            self._log.info('Cleaned up game %s (host returned to lobby)', gn)

        # 2) Joiner path: remove self from any game's player list
        if not hosted_game:
            game = self.world.remove_player_from_game(self.user.name)
            if game and game.host != self.user.name:
                self._log.info('Player %s left game %s', self.user.name, game.name)

        # 3) Always reset user status and notify channel
        self.user.user_type = 0
        if ch_name:
            payloads = [pkt_user_detail_add(self.user)]
            if hosted_game:
                payloads.insert(0, pkt_game_remove(hosted_game.name))
            await self.world.broadcast_lobby_payloads(ch_name, payloads)

        # 4) Silent return to lobby (sub 0 = no error dialog)
        await self.send_payload(pkt_p2p_ok())

    # ── 0x25 – game room init ─────────────────────────────────────────────────

    async def _on_game_room_init(self, _p: bytes):
        """0x25 – client entered game room init (JOIN path).

        The lobby and the game join dialog use DIFFERENT data sources:
        - Lobby: reads only 0x76 data (participant list)
        - Join dialog: reads the 0x75 auxiliary array for the list

        So we send:
        1. 0x75 sub 0 with GAME ROOM entries (name=room title, IP=host IP)
           → populates join dialog list with room names, not usernames.
           This does NOT affect the lobby (lobby ignores 0x75).
        2. 0x76 sub 0 with ALL channel users (type=0x0f)
           → preserves lobby participant list for when user returns.
        """
        if not self.user:
            return
        self._log.info('Game room init (0x25) from %s', self.user.name)
        ch_name = self.user.channel or 'General'
        # Build game room entries for 0x75 (join dialog list)
        game_rooms = self.world.get_channel_game_rooms(ch_name)

        all_users = self.world.get_channel_users(ch_name)

        # 1) 0x75 sub 0: game rooms with room names → join dialog
        payloads = [pkt_game_room_details(game_rooms)]
        # 2) 0x76 sub 0: ALL channel users (type=0x0f) → lobby
        payloads.append(pkt_game_list([], all_users))
        await self.send_payloads(payloads)

    # ── 0x27 – game room list resync ────────────────────────────────────────

    async def _on_game_list_resync(self, _p: bytes):
        """0x27 – client requests full game room list (0x75 sub 0).
        Sent when client receives 0x75 sub-1/2 before sub-0.
        """
        if not self.user:
            return
        ch_name = self.user.channel or 'General'
        game_rooms = self.world.get_channel_game_rooms(ch_name)
        await self.send_payload(pkt_game_room_details(game_rooms))
        self._log.debug('Game list resync sent to %s (%d rooms)',
                        self.user.name, len(game_rooms))

    # ── 0x28 – user list resync ──────────────────────────────────────────────

    async def _on_user_list_resync(self, _p: bytes):
        """0x28 – client requests full user name list (0x74 sub 0).
        Sent when client receives 0x74 sub-1/2 before sub-0.
        """
        if not self.user:
            return
        ch_name = self.user.channel or 'General'
        users = self.world.get_channel_user_names(ch_name)
        await self.send_payload(pkt_user_list(users))
        self._log.debug('User list resync sent to %s (%d users)',
                        self.user.name, len(users))

    # ── 0x29 – game room ready / request state ────────────────────────────────

    async def _on_game_room_ready(self, _p: bytes):
        """0x29 – single-byte packet; client requests the full room state.
        Sent by the 0x76 handler when sub-1/sub-2 arrives and the full-list flag=0.
        Flag is set to 1 when sub-0 arrives; subsequent sub-1/sub-2 do not re-trigger 0x29.

        Response: 0x76 sub-0 (sets the full-list flag) + 0x81 (game options).
        """
        if not self.user:
            return
        game = self.world.get_game_for_player(self.user.name)
        if not game:
            return
        users = self.world.get_game_users(game)
        await self.send_payloads([
            pkt_game_list([], users),   # 0x76 sub-0 with room players
            pkt_game_options(game),     # 0x81
        ])
        self._log.info('Room state sent to %s (game=%s)', self.user.name, game.name)

    # ── 0x40 – character select confirm ──────────────────────────────────────

    async def _on_char_select_confirm(self, payload: bytes):
        """0x40 – sent from the character-select loop when the user confirms.
        Format: [40][username(21)] = 22 bytes.

        Response: 0x90 sub 0 – accepted, client transitions to the lobby.
        """
        if not self.user:
            return
        if len(payload) >= 22:
            name = decode_fixed(payload[1:22])
            self._log.debug('Char select confirm from %s (name=%r)',
                            self.user.name, name)
        await self.send_payload(pkt_char_select_ok())

    # ── 0x41 – login screen inquiry ─────────────────────────────────────────

    async def _on_inquiry(self, payload: bytes):
        """0x41 – inquiry/message from the login screen.
        Format: [41][username(21)][data(11)] = 33 bytes.
        Sent via login-screen button 3, NOT a game result.
        """
        if not self.user or len(payload) < 33:
            return
        target_name = decode_fixed(payload[1:22])
        inquiry_data = payload[22:33]
        self._log.info('Inquiry from %s: target=%s len=%d',
                       self.user.name, target_name, len(inquiry_data))

    # ── 0x02 – lobby socket chat ─────────────────────────────────────────────

    async def _on_lobby_chat(self, payload: bytes):
        """0x02 – chat/whisper received on the lobby socket.
        Format: [02][len(2,BE)][sub_type(1)][data...]
          sub_type 0x02 = channel chat: data = EUC-KR message bytes
          sub_type 0x03 = whisper:      data = [target(21)][EUC-KR message]
        """
        if not self.user or len(payload) < 4:
            return
        msg_len  = struct.unpack('>H', payload[1:3])[0]
        if len(payload) < 3 + msg_len or msg_len < 1:
            return
        sub_type = payload[3]
        data     = payload[4:3 + msg_len]

        if sub_type == 0x02:
            message = data.decode('euc-kr', errors='replace')
            self._log.debug('LobbyChat from %s len=%d', self.user.name, len(message))
            if message.startswith('/'):
                self.world.metrics.inc_chat_message('slash')
                await self._on_slash_command(message)
                return
            if self.user.channel:
                await self.world.broadcast_chat(
                    self.user.channel,
                    pkt_chat_msg(0, self.user.name, message),
                    sender=self.user.name)

        elif sub_type == 0x03:
            if len(data) < 22:
                return
            target  = decode_fixed(data[0:21])
            message = data[21:].decode('euc-kr', errors='replace')
            self._log.debug('LobbyWhisper %s → %s len=%d',
                            self.user.name, target, len(message))
            tu = self.world.users.get(target)
            if tu and tu.chat_handler:
                if self.user.name in tu.ignored:
                    return
                await tu.chat_handler.send_payload(
                    pkt_chat_msg(1, self.user.name, message))

        else:
            self._log.debug('0x02 unknown sub_type=0x%02x', sub_type)

    async def _on_slash_command(self, message: str):
        """Handle /commands from lobby chat."""
        message = message.split('\x00')[0].strip()
        parts = message.split(None, 1)
        cmd   = parts[0].upper()
        arg   = parts[1].strip() if len(parts) > 1 else ''

        if cmd == '/IGNORE' and arg and self.user:
            target = arg.split('\x00')[0].strip()
            if target in self.user.ignored:
                self.user.ignored.discard(target)
                self._log.debug('UNIGNORE %s → %r', self.user.name, target)
            else:
                self.user.ignored.add(target)
                self._log.debug('IGNORE %s → %r', self.user.name, target)
        elif cmd in ('/GUILD', '/길드'):
            await self.handle_guild_command(message)
        else:
            self._log.debug('Unknown slash command from %s', self.user.name if self.user else '?')

    # ── 0x31 – player stats query ───────────────────────────────────────────

    async def _on_player_stats(self, payload: bytes):
        """0x31 – player stats query from game join dialog.
        Format: [31][name(20)][ip(4)] = 25 bytes.
        Response format is uncertain; send stats via chat system message.
        """
        if not self.user or len(payload) < 21:
            return
        target_name = decode_fixed(payload[1:21])
        self._log.debug('Player stats query from %s for %s', self.user.name, target_name)
        profile = self.world.db.get_profile_stats(target_name)
        guild = self.world.get_guild_for_user(target_name)
        guild_str = f' | 길드: {guild.name}[{guild.tag}]' if guild else ''
        await self._chat_system_msg(
            f'{target_name} - W:{profile["wins"]} L:{profile["losses"]} D:{profile["draws"]} '
            f'Total:{profile["rank"]}/{profile["total_rank"]} '
            f'Weekly:{profile["weekly_points"]}/{profile["weekly_rank"]} '
            f'Grade:{profile["grade"]}{guild_str}')

    # ── 0x36 – player info (guild query) ────────────────────────────────────

    async def _on_player_info(self, payload: bytes):
        """0x36 – selected item detail query.
        Format: [36][name(20)] = 21 bytes.
        Context-dependent:
        - From 대화방 설정 (chat-room settings): name is a channel → respond 0x86 (channel info)
        - From lobby: name is a player → respond 0x91 (guild info)
        0x86 displays: "방이름 : [name]" + "인원 [current] / [max]"
        """
        if not self.user or len(payload) < 21:
            return
        target_name = decode_fixed(payload[1:21])
        self._log.debug('Detail query from %s for %s', self.user.name, target_name)

        # Channel info query (from 대화방 설정)
        ch = self.world.channels.get(target_name)
        if ch is not None:
            user_count = len(ch.users)
            await self.send_payload(pkt_channel_info(user_count))
            return

        # Player guild info query (from lobby)
        guild = self.world.get_guild_for_user(target_name)
        if guild:
            await self.send_payload(pkt_guild_info_result(guild.name, guild.leader, found=True))
        else:
            await self.send_payload(pkt_guild_info_result('', '', found=False))

    # ── 0x37 – guild dialog confirm ────────────────────────────────────────

    async def _on_guild_register(self, payload: bytes):
        """0x37 – client confirmed guild invitation dialog (0x87).
        Format: [37][guild_name(21)][leader_name(9)] = 31 bytes.
        The client echoes back the two fields from the 0x87 prompt.
        """
        if not self.user or len(payload) < 31:
            return
        gname = decode_fixed(payload[1:22])
        field2 = decode_fixed(payload[22:31])
        self._log.info('Guild accept from %s: name=%r field2=%r',
                        self.user.name, gname, field2)
        if not gname:
            return

        if self.user.guild_name:
            await self._chat_system_msg('이미 길드에 가입되어 있습니다.')
            return

        existing = self.world.guilds.get(gname)
        if not existing:
            await self._chat_system_msg('해당 길드가 존재하지 않습니다.')
            return

        ok = self.world.db.add_guild_member(existing.guild_id, self.user.name)
        if not ok:
            await self._chat_system_msg('길드 가입에 실패했습니다.')
            return
        self.world.assign_guild_member(existing, self.user.name)
        self._security_event('guild_join guild=%s leader=%s',
                             existing.name, existing.leader)
        await self._chat_system_msg(f'길드 [{existing.tag}] {existing.name}에 가입했습니다.')
        await self._broadcast_user_refresh(self.user)

    # ── guild slash commands ───────────────────────────────────────────────

    async def handle_guild_command(self, message: str):
        """Process /guild (or /길드) commands. Called from lobby chat and chat socket."""
        if not self.user:
            return
        message = message.split('\x00')[0].strip()
        parts = message.split()
        sub = parts[1] if len(parts) > 1 else ''
        sub_upper = sub.upper()
        # Map Korean aliases
        sub_map = {'탈퇴': 'LEAVE', '정보': 'INFO', '목록': 'MEMBERS',
                   '해산': 'DISBAND', '리스트': 'LIST', '생성': 'CREATE',
                   '초대': 'INVITE'}
        sub_upper = sub_map.get(sub, sub_upper)

        if sub_upper == '':
            self.world.metrics.inc_guild_command('status')
            await self._guild_show_status()

        elif sub_upper == 'CREATE':
            # /guild create <name> <tag>
            if len(parts) < 4:
                await self._chat_system_msg('사용법: /guild create <길드명> <태그>')
                return
            self.world.metrics.inc_guild_command('create')
            await self._guild_create(parts[2], parts[3])

        elif sub_upper == 'INVITE':
            # /guild invite <player>
            if len(parts) < 3:
                await self._chat_system_msg('사용법: /guild invite <플레이어>')
                return
            self.world.metrics.inc_guild_command('invite')
            await self._guild_invite(parts[2])

        elif sub_upper == 'LEAVE':
            self.world.metrics.inc_guild_command('leave')
            await self._guild_leave()

        elif sub_upper == 'INFO':
            self.world.metrics.inc_guild_command('info')
            await self._guild_info()

        elif sub_upper == 'MEMBERS':
            self.world.metrics.inc_guild_command('members')
            await self._guild_members()

        elif sub_upper == 'DISBAND':
            self.world.metrics.inc_guild_command('disband')
            await self._guild_disband()

        elif sub_upper == 'LIST':
            self.world.metrics.inc_guild_command('list')
            await self._guild_list()

        else:
            self.world.metrics.inc_guild_command('unknown')
            await self._chat_system_msg(
                '/guild create <이름> <태그> | invite <유저> | '
                'leave | info | members | disband | list')

    async def _guild_show_status(self):
        """Show current guild info or usage help."""
        if self.user.guild_name:
            await self._guild_info()
        else:
            await self._chat_system_msg(
                '/guild create <이름> <태그> — 길드 생성')
            await self._chat_system_msg(
                '/guild list — 전체 길드 목록')

    async def _guild_create(self, gname: str, gtag: str):
        if self.user.guild_name:
            await self._chat_system_msg('이미 길드에 가입되어 있습니다.')
            return
        if len(gtag.encode('euc-kr', errors='replace')) > 8:
            await self._chat_system_msg('태그는 8바이트 이하여야 합니다.')
            return
        if not self.world.is_valid_guild_name(gname):
            await self._chat_system_msg('Invalid guild name.')
            return
        if not self.world.is_valid_guild_tag(gtag):
            await self._chat_system_msg('Invalid guild tag.')
            return
        from hqnet.models import GuildInfo
        guild_id = self.world.db.create_guild(gname, gtag, self.user.name)
        if guild_id < 0:
            await self._chat_system_msg('길드명 또는 태그가 이미 사용 중입니다.')
            return
        gi = GuildInfo(guild_id=guild_id, name=gname, tag=gtag,
                       leader=self.user.name, members=[self.user.name])
        self.world.guilds[gname] = gi
        self.world.assign_guild_member(gi, self.user.name)
        self._security_event('guild_create guild=%s tag=%s',
                             gname, gtag)
        await self._chat_system_msg(f'길드 [{gtag}] {gname}을(를) 생성했습니다.')
        await self._broadcast_user_refresh(self.user)

    async def _guild_invite(self, target_name: str):
        if not self.user.guild_name:
            await self._chat_system_msg('길드에 가입되어 있지 않습니다.')
            return
        guild = self.world.guilds.get(self.user.guild_name)
        if not guild:
            return
        target = self.world.users.get(target_name)
        if not target or not target.session:
            await self._chat_system_msg(f'{target_name} 님을 찾을 수 없습니다.')
            return
        if target.guild_name:
            await self._chat_system_msg(f'{target_name} 님은 이미 길드에 가입되어 있습니다.')
            return
        # Send 0x87 to target: invitation prompt
        self._security_event('guild_invite target=%s guild=%s',
                             target_name, guild.name)
        await target.session.send_payload(pkt_guild_screen(guild.name, guild.leader))
        await self._chat_system_msg(f'{target_name} 님에게 길드 초대를 보냈습니다.')

    async def _guild_leave(self):
        if not self.user or not self.user.guild_name:
            await self._chat_system_msg('길드에 가입되어 있지 않습니다.')
            return
        guild = self.world.guilds.get(self.user.guild_name)
        if not guild:
            self.user.guild_name = ''
            self.user.guild_tag = ''
            return
        if guild.leader == self.user.name:
            await self._chat_system_msg('길드장은 탈퇴할 수 없습니다. /guild disband로 해산하세요.')
            return
        self.world.db.remove_guild_member(guild.guild_id, self.user.name)
        old_tag = self.user.guild_tag
        self.world.remove_guild_member(self.user.name)
        await self._chat_system_msg(f'길드 [{old_tag}] {guild.name}에서 탈퇴했습니다.')
        await self._broadcast_user_refresh(self.user)

    async def _guild_info(self):
        if not self.user or not self.user.guild_name:
            await self._chat_system_msg('길드에 가입되어 있지 않습니다.')
            return
        guild = self.world.guilds.get(self.user.guild_name)
        if not guild:
            return
        await self._chat_system_msg(
            f'길드: {guild.name} [{guild.tag}] | 길드장: {guild.leader} '
            f'| 멤버: {len(guild.members)}명')

    async def _guild_members(self):
        if not self.user or not self.user.guild_name:
            await self._chat_system_msg('길드에 가입되어 있지 않습니다.')
            return
        guild = self.world.guilds.get(self.user.guild_name)
        if not guild:
            return
        members_str = ', '.join(guild.members)
        await self._chat_system_msg(f'[{guild.tag}] 멤버: {members_str}')

    async def _guild_disband(self):
        if not self.user or not self.user.guild_name:
            await self._chat_system_msg('길드에 가입되어 있지 않습니다.')
            return
        guild = self.world.guilds.get(self.user.guild_name)
        if not guild:
            return
        if guild.leader != self.user.name:
            await self._chat_system_msg('길드장만 해산할 수 있습니다.')
            return
        guild_name = guild.name
        guild_tag = guild.tag
        self._security_event('guild_disband guild=%s tag=%s member_count=%d',
                             guild_name, guild_tag, len(guild.members))
        # Clear guild from all online members
        for mname in list(guild.members):
            mu = self.world.users.get(mname)
            self.world.remove_guild_member(mname)
            if mu:
                await self._broadcast_user_refresh(mu)
                if mu.chat_handler:
                    await mu.chat_handler.send_payload(
                        pkt_chat_msg(0, '', f'길드 [{guild_tag}] {guild_name}이(가) 해산되었습니다.'))
        self.world.db.disband_guild(guild.guild_id)
        self.world.remove_guild(guild_name)

    async def _guild_list(self):
        if not self.world.guilds:
            await self._chat_system_msg('생성된 길드가 없습니다.')
            return
        lines = []
        for g in self.world.guilds.values():
            lines.append(f'  [{g.tag}] {g.name} (장:{g.leader}, {len(g.members)}명)')
        await self._chat_system_msg('길드 목록:')
        for line in lines:
            await self._chat_system_msg(line)

    async def _broadcast_user_refresh(self, u: UserInfo):
        """Remove then re-add a user's 0x76 entry so tag changes are visible."""
        if u.channel:
            await self.world.broadcast_lobby_payloads(
                u.channel,
                [
                    pkt_game_remove(u.name),
                    pkt_user_add_76(u),
                ],
            )

    async def _chat_system_msg(self, msg: str):
        """Send a system message to this user's chat socket."""
        if self.user and self.user.chat_handler:
            await self.user.chat_handler.send_payload(pkt_chat_msg(0, '', msg))

    # ── game cleanup (shared by _on_lobby_ready and _cleanup) ─────────────────

    async def _cleanup_games(self, ch_name: str):
        """Remove any games this user hosts or participates in.
        Called from _on_lobby_ready (normal game end → 0x26) and _cleanup (disconnect).
        """
        if not self.user:
            return
        uname = self.user.name
        hosted_game = self.world.get_hosted_game(uname)
        if hosted_game:
            self.world.remove_game(hosted_game.name, ch_name=ch_name)
            await self.world.broadcast_lobby(ch_name, pkt_game_remove(hosted_game.name))
            self._log.info('Cleaned up game %s (host returned to lobby)', hosted_game.name)
        else:
            self.world.remove_player_from_game(uname)
        # Reset user status back to "in lobby"
        self.user.user_type = 0

    # ── cleanup (disconnect) ───────────────────────────────────────────────────

    async def _cleanup(self):
        self._closed = True
        self.world.metrics.inc_disconnect('lobby')
        if self.user:
            uname   = self.user.name
            ch_name = self.user.channel

            # If disconnecting during an active game, record as a loss
            game = self.world.get_game_for_player(uname)
            if game and game.all_players_snapshot and uname not in game.result_submissions:
                self._log.info('Player %s disconnected during game %s — recording as loss',
                               uname, game.name)
                game.result_submissions.add(uname)
                self.world.db.record_match_result(uname, 2)  # LOSS
                self.world.db.log_game_event(
                    'result_disconnect', uname,
                    channel=ch_name or '', room_name=game.name,
                    map_name=game.map_name, detail='loss (disconnect)',
                )
                stats = self.world.db.get_account_stats(uname)
                if stats:
                    w, l, d = stats['wins'], stats['losses'] + 1, stats['draws']
                    rank, _ = self.world.db.calculate_progression(w, l, d)
                    self.world.db.update_stats(uname, wins=w, losses=l, draws=d, rank=rank)
                # Infer WIN for remaining opponents
                self.world.apply_inferred_result(game, uname, 2)

            # Remove any games this user hosted or participated in
            if ch_name:
                await self._cleanup_games(ch_name)

            # Broadcast departure to channel
            if ch_name:
                await self.world.broadcast_lobby_payloads(
                    ch_name,
                    [
                        pkt_user_remove(uname),
                        pkt_user_detail_remove(uname, self.user.user_id),
                        pkt_game_remove(uname),
                    ],
                    exclude=uname,
                )

            self.world.remove_user(uname)
            peer_ip = self.addr[0] if self.addr else ''
            self.world.db.log_connection('disconnect', uname, peer_ip,
                                         detail=f'channel={ch_name or ""}')
            self._security_event('disconnect channel=%s', ch_name or '')
            self._log.info('User %s disconnected', uname)

        try:
            self.writer.close()
            await self.writer.wait_closed()
        except (ConnectionError, OSError):
            pass
