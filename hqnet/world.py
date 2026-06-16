"""WorldState – global shared state and broadcast helpers."""

import asyncio
from collections import defaultdict, deque
import logging
import socket
import struct
import time

from hqnet.db import AccountDB
from hqnet.metrics import Metrics
from hqnet.models import ChannelInfo, GameInfo, GuildInfo, UserInfo

log = logging.getLogger(__name__)
SLOW_BROADCAST_MS = 10.0
SLOW_BROADCAST_COUNTS: dict[str, int] = defaultdict(int)
AUTH_WINDOW_SEC = 60.0
AUTH_IP_LIMIT = 20
AUTH_USER_LIMIT = 10
AUTH_BLOCK_SEC = 120.0
PASSWORD_CHANGE_WINDOW_SEC = 60.0
PASSWORD_CHANGE_IP_LIMIT = 8
PASSWORD_CHANGE_USER_LIMIT = 5
PASSWORD_CHANGE_BLOCK_SEC = 300.0
DEFAULT_BAD_PACKET_WINDOW_SEC = 10
DEFAULT_BAD_PACKET_IP_LIMIT = 3
DEFAULT_BAD_PACKET_BAN_BASE_SEC = 60
DEFAULT_BAD_PACKET_BAN_MAX_SEC = 3600

DEFAULT_CHANNELS = ('General', '초보자', '고수')


class WorldState:
    def __init__(self, metrics: Metrics | None = None,
                 bad_packet_window_sec: int = DEFAULT_BAD_PACKET_WINDOW_SEC,
                 bad_packet_ip_limit: int = DEFAULT_BAD_PACKET_IP_LIMIT,
                 bad_packet_ban_base_sec: int = DEFAULT_BAD_PACKET_BAN_BASE_SEC,
                 bad_packet_ban_max_sec: int = DEFAULT_BAD_PACKET_BAN_MAX_SEC):
        self.metrics = metrics or Metrics(False)
        self.bad_packet_window_sec = max(1, int(bad_packet_window_sec))
        self.bad_packet_ip_limit = max(1, int(bad_packet_ip_limit))
        self.bad_packet_ban_base_sec = max(1, int(bad_packet_ban_base_sec))
        self.bad_packet_ban_max_sec = int(bad_packet_ban_max_sec)
        if self.bad_packet_ban_max_sec != -1:
            self.bad_packet_ban_max_sec = max(
                self.bad_packet_ban_base_sec,
                self.bad_packet_ban_max_sec,
            )
        self.channels: dict[str, ChannelInfo] = {}
        self.users: dict[str, UserInfo] = {}
        self.games: dict[str, GameInfo] = {}
        self.guilds: dict[str, GuildInfo] = {}   # guild_name → GuildInfo
        self.guild_by_member: dict[str, GuildInfo] = {}
        self.game_by_player: dict[str, str] = {}
        self.hosted_game_by_host: dict[str, str] = {}
        self.db = AccountDB(metrics=self.metrics)
        self._load_channels()
        self.auth_failures_by_ip: dict[str, deque[float]] = defaultdict(deque)
        self.auth_failures_by_user: dict[str, deque[float]] = defaultdict(deque)
        self.auth_blocked_until_ip: dict[str, float] = {}
        self.auth_blocked_until_user: dict[str, float] = {}
        self.password_change_failures_by_ip: dict[str, deque[float]] = defaultdict(deque)
        self.password_change_failures_by_user: dict[str, deque[float]] = defaultdict(deque)
        self.password_change_blocked_until_ip: dict[str, float] = {}
        self.password_change_blocked_until_user: dict[str, float] = {}
        self.load_guilds()
        self._update_metrics()

    def _update_metrics(self):
        self.metrics.set_world_state(
            channels=len(self.channels),
            users_online=len(self.users),
            games_active=len(self.games),
            guilds_total=len(self.guilds),
        )
        self.metrics.sync_channel_states({
            channel.name: (len(channel.users), len(channel.games))
            for channel in self.channels.values()
        })
        self.metrics.set_world_cache_sizes(
            guild_by_member=len(self.guild_by_member),
            game_by_player=len(self.game_by_player),
            hosted_game_by_host=len(self.hosted_game_by_host),
        )

    # ---- guilds ----
    def load_guilds(self):
        """Load all guilds from DB into memory cache."""
        self.guilds.clear()
        self.guild_by_member.clear()
        for gd in self.db.get_all_guilds_with_members():
            members = list(gd["members"])
            gi = GuildInfo(
                guild_id=gd["guild_id"], name=gd["guild_name"],
                tag=gd["guild_tag"], leader=gd["leader"], members=members,
            )
            self.guilds[gi.name] = gi
            for member in members:
                self.guild_by_member[member] = gi
        log.info("Loaded %d guilds from DB", len(self.guilds))
        self._update_metrics()

    def get_guild_for_user(self, name: str) -> GuildInfo | None:
        """Find the guild a user belongs to (from cache)."""
        return self.guild_by_member.get(name)

    def assign_guild_member(self, guild: GuildInfo, member_name: str):
        if member_name not in guild.members:
            guild.members.append(member_name)
        self.guild_by_member[member_name] = guild
        user = self.users.get(member_name)
        if user:
            user.guild_name = guild.name
            user.guild_tag = guild.tag
        self._update_metrics()

    def remove_guild_member(self, member_name: str) -> GuildInfo | None:
        guild = self.guild_by_member.pop(member_name, None)
        if guild and member_name in guild.members:
            guild.members.remove(member_name)
        user = self.users.get(member_name)
        if user:
            user.guild_name = ''
            user.guild_tag = ''
        self._update_metrics()
        return guild

    def remove_guild(self, guild_name: str) -> GuildInfo | None:
        guild = self.guilds.pop(guild_name, None)
        if not guild:
            return None
        for member_name in list(guild.members):
            self.guild_by_member.pop(member_name, None)
            user = self.users.get(member_name)
            if user:
                user.guild_name = ''
                user.guild_tag = ''
        self._update_metrics()
        return guild

    # ---- user CRUD ----
    def add_user(self, name: str, account: str = '',
                 peer_ip: str = '127.0.0.1') -> UserInfo:
        # The 0x75 user_id field is actually the user's IP address.
        # The x86 client decodes it back to a dotted IP for the join dialog.
        # Encoding: network-order IP bytes interpreted as LE uint32, then packed BE.
        ip_encoded = struct.unpack('<I', socket.inet_aton(peer_ip))[0]
        profile = self.db.get_profile_stats(name)
        guild = self.get_guild_for_user(name)
        u = UserInfo(
            name=name, account=account, user_id=ip_encoded,
            grade=profile["grade"],
            wins=profile["wins"], losses=profile["losses"], draws=profile["draws"],
            rank=profile["rank"],
            total_rank=profile["total_rank"],
            weekly_points=profile["weekly_points"],
            weekly_rank=profile["weekly_rank"],
            guild_name=guild.name if guild else '',
            guild_tag=guild.tag if guild else '',
        )
        self.users[name] = u
        self._update_metrics()
        return u

    def refresh_user_profile(self, name: str):
        user = self.users.get(name)
        if not user:
            return
        profile = self.db.get_profile_stats(name)
        user.wins = profile["wins"]
        user.losses = profile["losses"]
        user.draws = profile["draws"]
        user.rank = profile["rank"]
        user.grade = profile["grade"]
        user.total_rank = profile["total_rank"]
        user.weekly_points = profile["weekly_points"]
        user.weekly_rank = profile["weekly_rank"]

    def refresh_channel_profiles(self, ch_name: str):
        ch = self.channels.get(ch_name)
        if not ch:
            return
        for name in ch.users:
            if name in self.users:
                self.refresh_user_profile(name)

    def remove_user(self, name: str):
        u = self.users.pop(name, None)
        if u and u.channel:
            ch = self.channels.get(u.channel)
            if ch and name in ch.users:
                ch.users.remove(name)
        self._update_metrics()

    # ---- channel persistence ----
    def _load_channels(self):
        """Load channels from DB, ensuring defaults exist."""
        self.db.ensure_default_channels(DEFAULT_CHANNELS)
        for ch in self.db.load_channels():
            if ch['name'] not in self.channels:
                self.channels[ch['name']] = ChannelInfo(name=ch['name'])
        self._default_channel_names = {ch['name'] for ch in self.db.load_channels()
                                        if ch['is_default']}

    def admin_create_channel(self, name: str, sort_order: int = 0) -> bool:
        """Create a persistent channel via admin. Returns False if exists."""
        if not self.is_valid_channel_name(name):
            return False
        if not self.db.create_channel(name, sort_order):
            return False
        if name not in self.channels:
            self.channels[name] = ChannelInfo(name=name)
        self._update_metrics()
        return True

    def admin_delete_channel(self, name: str) -> tuple[bool, list[str]]:
        """Delete a persistent channel. Moves users to General.
        Returns (success, moved_users)."""
        if not self.db.delete_channel(name):
            return False, []
        moved = []
        ch = self.channels.get(name)
        if ch:
            moved = list(ch.users)
            for uname in moved:
                u = self.users.get(uname)
                if u:
                    u.channel = 'General'
                    gen = self.channels.get('General')
                    if gen and uname not in gen.users:
                        gen.users.append(uname)
            del self.channels[name]
        self._update_metrics()
        return True, moved

    def admin_rename_channel(self, old_name: str, new_name: str) -> tuple[bool, int]:
        """Rename a persistent channel. Returns (success, affected_users)."""
        if not self.is_valid_channel_name(new_name):
            return False, 0
        if not self.db.rename_channel(old_name, new_name):
            return False, 0
        ch = self.channels.get(old_name)
        affected = 0
        if ch:
            ch.name = new_name
            self.channels[new_name] = ch
            del self.channels[old_name]
            for uname in ch.users:
                u = self.users.get(uname)
                if u and u.channel == old_name:
                    u.channel = new_name
                    affected += 1
        self._update_metrics()
        return True, affected

    # ---- channel helpers ----
    def join_channel(self, name: str, ch_name: str):
        if ch_name not in self.channels:
            self.channels[ch_name] = ChannelInfo(name=ch_name)
        ch = self.channels[ch_name]
        u = self.users.get(name)
        if u and u.channel and u.channel != ch_name:
            self._leave_channel(name, u.channel)
        if name not in ch.users:
            ch.users.append(name)
        if u:
            u.channel = ch_name
        self._update_metrics()

    def _leave_channel(self, name: str, ch_name: str):
        ch = self.channels.get(ch_name)
        if ch and name in ch.users:
            ch.users.remove(name)
        u = self.users.get(name)
        if u and u.channel == ch_name:
            u.channel = None
        self._update_metrics()

    def is_valid_channel_name(self, name: str) -> bool:
        if not name or not name.strip():
            return False
        if any(ch in name for ch in ('\x00', '\r', '\n', '\t')):
            return False
        return name.isprintable() and 0 < len(name.encode('euc-kr', errors='replace')) < 20

    def is_valid_account_name(self, name: str) -> bool:
        if not name or not name.strip():
            return False
        if any(ch in name for ch in ('\x00', '\r', '\n', '\t', ' ')):
            return False
        return name.isprintable() and 0 < len(name.encode('euc-kr', errors='replace')) < 21

    def is_valid_guild_name(self, name: str) -> bool:
        if not name or not name.strip():
            return False
        if any(ch in name for ch in ('\x00', '\r', '\n', '\t')):
            return False
        return name.isprintable() and 0 < len(name.encode('euc-kr', errors='replace')) < 21

    def is_valid_guild_tag(self, tag: str) -> bool:
        if not tag or not tag.strip():
            return False
        if any(ch in tag for ch in ('\x00', '\r', '\n', '\t', ' ')):
            return False
        return tag.isprintable() and 0 < len(tag.encode('euc-kr', errors='replace')) <= 8

    def switch_channel(self, username: str, new_ch: str) -> str | None:
        """Switch user to a new channel. Returns old channel name.
        Empty non-default channels are auto-deleted."""
        u = self.users.get(username)
        old_ch = u.channel if u else None
        if old_ch:
            self._leave_channel(username, old_ch)
            ch_obj = self.channels.get(old_ch)
            # Only auto-delete channels that are not persisted in DB
            is_persisted = self.db._fetchone(
                "SELECT 1 FROM channels WHERE name = ?", (old_ch,)
            )
            if ch_obj and not ch_obj.users and not ch_obj.games and not is_persisted:
                del self.channels[old_ch]
        self.join_channel(username, new_ch)
        self._update_metrics()
        return old_ch

    def get_channel_game_rooms(self, ch_name: str) -> list[tuple[GameInfo, UserInfo]]:
        ch = self.channels.get(ch_name)
        if not ch:
            return []
        game_rooms: list[tuple[GameInfo, UserInfo]] = []
        for game_name in ch.games:
            game = self.games.get(game_name)
            if not game:
                continue
            host = self.users.get(game.host)
            if host:
                game_rooms.append((game, host))
        return game_rooms

    def get_channel_users(self, ch_name: str) -> list[UserInfo]:
        ch = self.channels.get(ch_name)
        if not ch:
            return []
        return [self.users[name] for name in ch.users if name in self.users]

    def get_channel_user_names(self, ch_name: str) -> list[str]:
        ch = self.channels.get(ch_name)
        if not ch:
            return []
        return [name for name in ch.users if name in self.users]

    def get_game_users(self, game: GameInfo) -> list[UserInfo]:
        return [self.users[name] for name in game.players if name in self.users]

    # ---- game helpers ----
    def add_game(self, game: GameInfo, ch_name: str):
        existing = self.games.get(game.name)
        if existing:
            self.remove_game(game.name, ch_name=ch_name)
        self.games[game.name] = game
        self.hosted_game_by_host[game.host] = game.name
        for player in game.players:
            self.game_by_player[player] = game.name
        ch = self.channels.get(ch_name)
        if ch and game.name not in ch.games:
            ch.games.append(game.name)
        self._update_metrics()

    def add_player_to_game(self, game_name: str, player_name: str) -> GameInfo | None:
        game = self.games.get(game_name)
        if not game:
            return None
        if player_name not in game.players:
            game.players.append(player_name)
        self.game_by_player[player_name] = game_name
        self._update_metrics()
        return game

    def get_game_for_player(self, player_name: str) -> GameInfo | None:
        game_name = self.game_by_player.get(player_name)
        if not game_name:
            return None
        return self.games.get(game_name)

    def get_hosted_game(self, host_name: str) -> GameInfo | None:
        game_name = self.hosted_game_by_host.get(host_name)
        if not game_name:
            return None
        return self.games.get(game_name)

    def remove_player_from_game(self, player_name: str) -> GameInfo | None:
        game_name = self.game_by_player.pop(player_name, None)
        if not game_name:
            return None
        game = self.games.get(game_name)
        if game and player_name in game.players:
            game.players.remove(player_name)
        self._update_metrics()
        return game

    def remove_game(self, game_name: str, *, ch_name: str | None = None) -> GameInfo | None:
        game = self.games.pop(game_name, None)
        if not game:
            return None
        self.hosted_game_by_host.pop(game.host, None)
        for player_name in list(game.players):
            self.game_by_player.pop(player_name, None)
        if ch_name:
            ch = self.channels.get(ch_name)
            if ch:
                if game_name in ch.games:
                    ch.games.remove(game_name)
                ch.stale_game_removes.add(game_name)
        self._update_metrics()
        return game

    def apply_inferred_result(self, game: GameInfo, reporter: str, sub: int):
        """Apply the opposite result to opponents who didn't report.
        sub: 1=WIN→opponents get LOSS, 2=LOSS→opponents get WIN, 3=DRAW→opponents get DRAW.
        Called after the reporter's own result is recorded.
        """
        OPPOSITE = {1: 2, 2: 1, 3: 3}  # win→loss, loss→win, draw→draw
        opp_sub = OPPOSITE.get(sub)
        if opp_sub is None:
            return
        snapshot = game.all_players_snapshot
        if not snapshot:
            return
        for pname in snapshot:
            if pname == reporter or pname in game.result_submissions:
                continue
            game.result_submissions.add(pname)
            # Update DB stats directly (player may be offline)
            opp_label = {1: 'win', 2: 'loss', 3: 'draw'}[opp_sub]
            log.info('Inferred %s for %s (opponent of %s)', opp_label, pname, reporter)
            self.db.record_match_result(pname, opp_sub)
            self.db.log_game_event(
                'result_inferred', pname,
                room_name=game.name, map_name=game.map_name,
                detail=f'{opp_label} (inferred from {reporter})',
            )
            # Update account stats
            stats = self.db.get_account_stats(pname)
            if stats:
                w, l, d = stats['wins'], stats['losses'], stats['draws']
                if opp_sub == 1:
                    w += 1
                elif opp_sub == 2:
                    l += 1
                else:
                    d += 1
                rank, _ = self.db.calculate_progression(w, l, d)
                self.db.update_stats(pname, wins=w, losses=l, draws=d, rank=rank)
                # If player is online, update in-memory state too
                u = self.users.get(pname)
                if u:
                    u.wins, u.losses, u.draws, u.rank = w, l, d, rank
                    u.grade = self.db.grade_for_rank(rank)
                    self.refresh_user_profile(pname)

    @staticmethod
    async def _run_targets(targets: list):
        if targets:
            await asyncio.gather(*targets, return_exceptions=True)

    @staticmethod
    def _prune_attempts(attempts: deque[float], now: float, window_sec: float):
        while attempts and now - attempts[0] > window_sec:
            attempts.popleft()

    def get_auth_block_remaining(self, ip: str, username: str) -> float:
        now = time.monotonic()
        blocked_until = max(
            self.auth_blocked_until_ip.get(ip, 0.0),
            self.auth_blocked_until_user.get(username, 0.0),
        )
        return max(0.0, blocked_until - now)

    def record_auth_failure(self, ip: str, username: str):
        now = time.monotonic()
        ip_attempts = self.auth_failures_by_ip[ip]
        user_attempts = self.auth_failures_by_user[username]
        self._prune_attempts(ip_attempts, now, AUTH_WINDOW_SEC)
        self._prune_attempts(user_attempts, now, AUTH_WINDOW_SEC)
        ip_attempts.append(now)
        user_attempts.append(now)
        if len(ip_attempts) >= AUTH_IP_LIMIT:
            self.auth_blocked_until_ip[ip] = now + AUTH_BLOCK_SEC
        if len(user_attempts) >= AUTH_USER_LIMIT:
            self.auth_blocked_until_user[username] = now + AUTH_BLOCK_SEC
        self.metrics.set_auth_blocks_active(self.get_active_auth_block_count())

    def clear_auth_failures(self, ip: str, username: str):
        self.auth_failures_by_ip.pop(ip, None)
        self.auth_failures_by_user.pop(username, None)
        self.auth_blocked_until_ip.pop(ip, None)
        self.auth_blocked_until_user.pop(username, None)
        self.metrics.set_auth_blocks_active(self.get_active_auth_block_count())

    def get_active_auth_block_count(self) -> int:
        now = time.monotonic()
        ip_count = sum(1 for blocked_until in self.auth_blocked_until_ip.values()
                       if blocked_until > now)
        user_count = sum(1 for blocked_until in self.auth_blocked_until_user.values()
                         if blocked_until > now)
        return ip_count + user_count

    def get_password_change_block_remaining(self, ip: str, username: str) -> float:
        now = time.monotonic()
        blocked_until = max(
            self.password_change_blocked_until_ip.get(ip, 0.0),
            self.password_change_blocked_until_user.get(username, 0.0),
        )
        return max(0.0, blocked_until - now)

    def record_password_change_failure(self, ip: str, username: str):
        now = time.monotonic()
        ip_attempts = self.password_change_failures_by_ip[ip]
        user_attempts = self.password_change_failures_by_user[username]
        self._prune_attempts(ip_attempts, now, PASSWORD_CHANGE_WINDOW_SEC)
        self._prune_attempts(user_attempts, now, PASSWORD_CHANGE_WINDOW_SEC)
        ip_attempts.append(now)
        user_attempts.append(now)
        if len(ip_attempts) >= PASSWORD_CHANGE_IP_LIMIT:
            self.password_change_blocked_until_ip[ip] = now + PASSWORD_CHANGE_BLOCK_SEC
        if len(user_attempts) >= PASSWORD_CHANGE_USER_LIMIT:
            self.password_change_blocked_until_user[username] = now + PASSWORD_CHANGE_BLOCK_SEC

    def clear_password_change_failures(self, ip: str, username: str):
        self.password_change_failures_by_ip.pop(ip, None)
        self.password_change_failures_by_user.pop(username, None)
        self.password_change_blocked_until_ip.pop(ip, None)
        self.password_change_blocked_until_user.pop(username, None)

    def get_bad_packet_block_remaining(self, ip: str) -> float:
        return self.db.get_packet_ban_remaining(ip)

    def record_bad_packet(self, ip: str, reason: str) -> dict:
        return self.db.record_bad_packet(
            ip,
            reason,
            window_sec=self.bad_packet_window_sec,
            threshold=self.bad_packet_ip_limit,
            base_block_sec=self.bad_packet_ban_base_sec,
            max_block_sec=self.bad_packet_ban_max_sec,
        )

    def _log_slow_broadcast(self, label: str, started: float, target_count: int):
        elapsed_ms = (time.perf_counter() - started) * 1000
        kind = label.split(':', 1)[0]
        self.metrics.observe_broadcast(kind, elapsed_ms, target_count)
        if elapsed_ms >= SLOW_BROADCAST_MS:
            SLOW_BROADCAST_COUNTS[label] += 1
            log.debug("Slow broadcast %.2fms: %s targets=%d count=%d",
                      elapsed_ms, label, target_count, SLOW_BROADCAST_COUNTS[label])

    def _iter_channel_users(self, ch_name: str, *, exclude: str = ''):
        ch = self.channels.get(ch_name)
        if not ch:
            return
        for uname in ch.users:
            if uname != exclude:
                user = self.users.get(uname)
                if user:
                    yield user

    # ---- broadcast (payload, not full packet) ----
    async def broadcast_lobby(self, ch_name: str, payload: bytes,
                              *, exclude: str = ''):
        started = time.perf_counter()
        targets = []
        for u in self._iter_channel_users(ch_name, exclude=exclude):
            if u and u.session:
                targets.append(u.session.send_payload(payload))
        await self._run_targets(targets)
        self._log_slow_broadcast(f"lobby:{ch_name}", started, len(targets))

    async def broadcast_lobby_payloads(self, ch_name: str, payloads: list[bytes],
                                       *, exclude: str = ''):
        if not payloads:
            return
        started = time.perf_counter()
        targets = []
        for u in self._iter_channel_users(ch_name, exclude=exclude):
            if u and u.session:
                targets.append(u.session.send_payloads(payloads))
        await self._run_targets(targets)
        self._log_slow_broadcast(f"lobby_batch:{ch_name}", started, len(targets))

    async def broadcast_chat(self, ch_name: str, payload: bytes,
                             *, exclude: str = '', sender: str = ''):
        started = time.perf_counter()
        targets = []
        for u in self._iter_channel_users(ch_name, exclude=exclude):
            if u and u.chat_handler:
                if sender and sender in u.ignored:
                    continue
                targets.append(u.chat_handler.send_payload(payload))
        await self._run_targets(targets)
        self._log_slow_broadcast(f"chat:{ch_name}", started, len(targets))

    async def broadcast_game_players(self, game: GameInfo, payload: bytes):
        started = time.perf_counter()
        targets = []
        for player_name in game.players:
            user = self.users.get(player_name)
            if user and user.session:
                targets.append(user.session.send_payload(payload))
        await self._run_targets(targets)
        self._log_slow_broadcast(f"game:{game.name}", started, len(targets))

    @staticmethod
    def peer_ip_from_addr(addr) -> str:
        if isinstance(addr, tuple) and addr:
            return str(addr[0])
        return ''

    def build_runtime_snapshot(self) -> dict:
        return {
            "channels": len(self.channels),
            "users_online": len(self.users),
            "games_active": len(self.games),
            "guilds_total": len(self.guilds),
            "auth_blocks_active": self.get_active_auth_block_count(),
            "active_packet_bans": len(self.db.list_packet_bans(limit=500, active_only=True)),
        }

    def list_users_snapshot(self) -> list[dict]:
        items: list[dict] = []
        for user in sorted(self.users.values(), key=lambda item: item.name.lower()):
            session_ip = self.peer_ip_from_addr(user.session.addr) if user.session else ''
            chat_ip = self.peer_ip_from_addr(user.chat_handler.addr) if user.chat_handler else ''
            items.append({
                "name": user.name,
                "channel": user.channel or '',
                "grade": user.grade,
                "rank": user.rank,
                "wins": user.wins,
                "losses": user.losses,
                "draws": user.draws,
                "guild_tag": user.guild_tag,
                "session_ip": session_ip,
                "chat_ip": chat_ip,
                "has_session": bool(user.session and not user.session._closed),
                "has_chat": bool(user.chat_handler and not user.chat_handler._closed),
            })
        return items

    def get_user_snapshot(self, name: str) -> dict | None:
        user = self.users.get(name)
        if not user:
            return None
        game = self.get_game_for_player(name)
        return {
            "name": user.name,
            "account": user.account,
            "channel": user.channel or '',
            "grade": user.grade,
            "rank": user.rank,
            "wins": user.wins,
            "losses": user.losses,
            "draws": user.draws,
            "total_rank": user.total_rank,
            "weekly_points": user.weekly_points,
            "weekly_rank": user.weekly_rank,
            "guild_name": user.guild_name,
            "guild_tag": user.guild_tag,
            "ignored": sorted(user.ignored),
            "session_ip": self.peer_ip_from_addr(user.session.addr) if user.session else '',
            "chat_ip": self.peer_ip_from_addr(user.chat_handler.addr) if user.chat_handler else '',
            "game": game.name if game else '',
        }

    def list_games_snapshot(self) -> list[dict]:
        items: list[dict] = []
        now = time.monotonic()
        for game in sorted(self.games.values(), key=lambda item: item.name.lower()):
            items.append({
                "name": game.name,
                "host": game.host,
                "channel": next((channel.name for channel in self.channels.values()
                                  if game.name in channel.games), ''),
                "players": list(game.players),
                "map_name": game.map_name,
                "status": game.status,
                "age_seconds": round(max(0.0, now - game.created_at), 1) if game.created_at else 0.0,
            })
        return items

    def get_game_snapshot(self, name: str) -> dict | None:
        game = self.games.get(name)
        if not game:
            return None
        now = time.monotonic()
        return {
            "name": game.name,
            "host": game.host,
            "players": list(game.players),
            "map_name": game.map_name,
            "status": game.status,
            "max_players": game.max_players,
            "age_seconds": round(max(0.0, now - game.created_at), 1) if game.created_at else 0.0,
            "result_submissions": sorted(game.result_submissions),
        }

    def list_channels_snapshot(self) -> list[dict]:
        return [{
            "name": channel.name,
            "users": list(channel.users),
            "games": list(channel.games),
        } for channel in sorted(self.channels.values(), key=lambda item: item.name.lower())]

    def list_guilds_snapshot(self) -> list[dict]:
        return [{
            "name": guild.name,
            "tag": guild.tag,
            "leader": guild.leader,
            "members": list(guild.members),
        } for guild in sorted(self.guilds.values(), key=lambda item: item.name.lower())]

    async def admin_disconnect_user(self, name: str, *, reason: str = 'admin') -> bool:
        user = self.users.get(name)
        if not user:
            return False
        if user.chat_handler and not user.chat_handler._closed:
            await user.chat_handler._close_transport()
        if user.session and not user.session._closed:
            try:
                from hqnet.packets import pkt_disconnect
                await user.session.send_payload(pkt_disconnect())
            except Exception:
                pass
            user.session._closed = True
            try:
                user.session.writer.close()
            except (ConnectionError, OSError):
                pass
        return True

    async def admin_disconnect_ip(self, ip_address: str, *, reason: str = 'admin') -> list[str]:
        names: list[str] = []
        for user in list(self.users.values()):
            session_ip = self.peer_ip_from_addr(user.session.addr) if user.session else ''
            chat_ip = self.peer_ip_from_addr(user.chat_handler.addr) if user.chat_handler else ''
            if ip_address and ip_address not in (session_ip, chat_ip):
                continue
            names.append(user.name)
            await self.admin_disconnect_user(user.name, reason=reason)
        return names

    async def admin_notice(self, target: str, message: str) -> int:
        from hqnet.packets import pkt_chat_msg

        payload = pkt_chat_msg(0, 'ADMIN', message)
        delivered = 0
        if target == 'all':
            for user in list(self.users.values()):
                if user.chat_handler and not user.chat_handler._closed:
                    await user.chat_handler.send_payload(payload)
                    delivered += 1
            return delivered
        if target.startswith('channel:'):
            channel_name = target.split(':', 1)[1]
            for user in self.get_channel_users(channel_name):
                if user.chat_handler and not user.chat_handler._closed:
                    await user.chat_handler.send_payload(payload)
                    delivered += 1
            return delivered
        if target.startswith('user:'):
            user = self.users.get(target.split(':', 1)[1])
            if user and user.chat_handler and not user.chat_handler._closed:
                await user.chat_handler.send_payload(payload)
                return 1
            return 0
        return 0
