"""Prometheus metrics support for the HQNET server."""

from __future__ import annotations

import logging
import os
import time

log = logging.getLogger("hqnet.metrics")
_OPCODE_LABELS = tuple(f"0x{i:02X}" for i in range(256))

try:
    from prometheus_client import Counter, Gauge, Histogram, start_http_server
    from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
    _PROMETHEUS_AVAILABLE = True
except ImportError:  # pragma: no cover - runtime fallback
    Counter = Gauge = Histogram = None
    start_http_server = generate_latest = CONTENT_TYPE_LATEST = None
    _PROMETHEUS_AVAILABLE = False


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def env_metrics_enabled(default: bool = False) -> bool:
    return _env_bool("HQNET_METRICS_ENABLED", default)


def env_metrics_host(default: str = "127.0.0.1") -> str:
    return os.getenv("HQNET_METRICS_HOST", default)


def env_metrics_port(default: int = 9108) -> int:
    raw = os.getenv("HQNET_METRICS_PORT")
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


class Metrics:
    def __init__(self, enabled: bool = False, host: str = "127.0.0.1",
                 port: int = 9108):
        self.requested_enabled = enabled
        self.enabled = enabled and _PROMETHEUS_AVAILABLE
        self.host = host
        self.port = port
        self.started = False
        self.start_time = time.time()
        self._warned_missing = False
        self._init_handles()

    def _init_handles(self):
        self.up = None
        self.start_time_seconds = None
        self.active_connections = None
        self.active_connections_by_type = None
        self.connections_accepted_total = None
        self.connections_rejected_total = None
        self.disconnects_total = None
        self.idle_timeouts_total = None
        self.login_attempts_total = None
        self.register_attempts_total = None
        self.auth_blocks_active = None
        self.packets_received_total = None
        self.packets_sent_total = None
        self.packet_parse_failures_total = None
        self.db_queries_total = None
        self.db_query_duration_seconds = None
        self.db_slow_queries_total = None
        self.broadcasts_total = None
        self.broadcast_duration_seconds = None
        self.broadcast_targets = None
        self.lobby_build_duration_seconds = None
        self.lobby_build_slow_total = None
        self.chat_messages_total = None
        self.chat_rate_limited_total = None
        self.guild_commands_total = None
        self.game_create_total = None
        self.game_join_total = None
        self.match_results_total = None
        self.rank_recalculations_total = None
        self.security_events_total = None
        self.db_operation_errors_total = None
        self.send_failures_total = None
        self.channels = None
        self.users_online = None
        self.games_active = None
        self.guilds_total = None
        self.channel_users = None
        self.channel_games = None
        self.world_cache_size = None
        self._active_conn_lobby = None
        self._active_conn_chat = None
        self._connection_rejected = {}
        self._disconnects = {}
        self._idle_timeouts = {}
        self._login_attempts = {}
        self._register_attempts = {}
        self._packet_received = {}
        self._packet_sent = {}
        self._packet_parse_failures = {}
        self._db_queries = {}
        self._db_durations = {}
        self._db_slow = {}
        self._broadcasts = {}
        self._broadcast_durations = {}
        self._broadcast_targets = {}
        self._chat_messages = {}
        self._guild_commands = {}
        self._game_joins = {}
        self._match_results = {}
        self._security_events = {}
        self._db_errors = {}
        self._send_failures = {}
        self._channel_users = {}
        self._channel_games = {}
        self._known_channels = set()
        self._world_cache_sizes = {}
        if not self.enabled:
            return

        self.up = Gauge("hqnet_up", "Server process health")
        self.start_time_seconds = Gauge(
            "hqnet_start_time_seconds", "Server process start time"
        )
        self.active_connections = Gauge(
            "hqnet_active_connections", "Active TCP connections"
        )
        self.active_connections_by_type = Gauge(
            "hqnet_active_connections_by_type",
            "Active TCP connections by type",
            ["type"],
        )
        self.connections_accepted_total = Counter(
            "hqnet_connections_accepted_total",
            "Accepted TCP connections",
        )
        self.connections_rejected_total = Counter(
            "hqnet_connections_rejected_total",
            "Rejected TCP connections",
            ["reason"],
        )
        self.disconnects_total = Counter(
            "hqnet_disconnects_total",
            "Connection disconnects",
            ["type"],
        )
        self.idle_timeouts_total = Counter(
            "hqnet_idle_timeouts_total",
            "Idle timeouts",
            ["type"],
        )
        self.login_attempts_total = Counter(
            "hqnet_login_attempts_total",
            "Login attempts",
            ["result"],
        )
        self.register_attempts_total = Counter(
            "hqnet_register_attempts_total",
            "Registration attempts",
            ["result"],
        )
        self.auth_blocks_active = Gauge(
            "hqnet_auth_blocks_active",
            "Currently active auth blocks",
        )
        self.packets_received_total = Counter(
            "hqnet_packets_received_total",
            "Packets received",
            ["type", "opcode"],
        )
        self.packets_sent_total = Counter(
            "hqnet_packets_sent_total",
            "Packets sent",
            ["type", "opcode"],
        )
        self.packet_parse_failures_total = Counter(
            "hqnet_packet_parse_failures_total",
            "Packet parse failures",
            ["phase"],
        )
        self.db_queries_total = Counter(
            "hqnet_db_queries_total",
            "Database operations",
            ["kind"],
        )
        self.db_query_duration_seconds = Histogram(
            "hqnet_db_query_duration_seconds",
            "Database operation duration",
            ["kind"],
            buckets=(0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 1.0),
        )
        self.db_slow_queries_total = Counter(
            "hqnet_db_slow_queries_total",
            "Slow database operations",
            ["kind"],
        )
        self.broadcasts_total = Counter(
            "hqnet_broadcasts_total",
            "Broadcast operations",
            ["kind"],
        )
        self.broadcast_duration_seconds = Histogram(
            "hqnet_broadcast_duration_seconds",
            "Broadcast duration",
            ["kind"],
            buckets=(0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 1.0),
        )
        self.broadcast_targets = Histogram(
            "hqnet_broadcast_targets",
            "Broadcast target fan-out",
            ["kind"],
            buckets=(1, 2, 4, 8, 16, 32, 64, 128, 256, 512),
        )
        self.lobby_build_duration_seconds = Histogram(
            "hqnet_lobby_build_duration_seconds",
            "Lobby payload build duration",
            buckets=(0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25),
        )
        self.lobby_build_slow_total = Counter(
            "hqnet_lobby_build_slow_total",
            "Slow lobby payload builds",
        )
        self.chat_messages_total = Counter(
            "hqnet_chat_messages_total",
            "Chat messages processed",
            ["kind"],
        )
        self.chat_rate_limited_total = Counter(
            "hqnet_chat_rate_limited_total",
            "Chat messages rejected by rate limit",
        )
        self.guild_commands_total = Counter(
            "hqnet_guild_commands_total",
            "Guild slash commands processed",
            ["command"],
        )
        self.game_create_total = Counter(
            "hqnet_game_create_total",
            "Game rooms created",
        )
        self.game_join_total = Counter(
            "hqnet_game_join_total",
            "Game room join attempts",
            ["result"],
        )
        self.match_results_total = Counter(
            "hqnet_match_results_total",
            "Match results processed",
            ["result"],
        )
        self.rank_recalculations_total = Counter(
            "hqnet_rank_recalculations_total",
            "Rank recalculations after results",
        )
        self.security_events_total = Counter(
            "hqnet_security_events_total",
            "Security-related events",
            ["event"],
        )
        self.db_operation_errors_total = Counter(
            "hqnet_db_operation_errors_total",
            "Database operation errors",
            ["kind"],
        )
        self.send_failures_total = Counter(
            "hqnet_send_failures_total",
            "Send failures by connection type",
            ["type"],
        )
        self.channels = Gauge(
            "hqnet_channels",
            "Current channel count",
        )
        self.users_online = Gauge(
            "hqnet_users_online",
            "Current online user count",
        )
        self.games_active = Gauge(
            "hqnet_games_active",
            "Current active game count",
        )
        self.guilds_total = Gauge(
            "hqnet_guilds_total",
            "Current guild count",
        )
        self.channel_users = Gauge(
            "hqnet_channel_users",
            "Users per channel",
            ["channel"],
        )
        self.channel_games = Gauge(
            "hqnet_channel_games",
            "Games per channel",
            ["channel"],
        )
        self.world_cache_size = Gauge(
            "hqnet_world_cache_size",
            "World cache sizes",
            ["cache"],
        )
        self._prime_label_cache()

    def _prime_label_cache(self):
        self._active_conn_lobby = self.active_connections_by_type.labels(type="lobby")
        self._active_conn_chat = self.active_connections_by_type.labels(type="chat")

        for reason in ("global_cap", "per_ip_cap", "bad_first_packet", "timeout"):
            self._connection_rejected[reason] = self.connections_rejected_total.labels(reason=reason)

        for conn_type in ("lobby", "chat"):
            self._disconnects[conn_type] = self.disconnects_total.labels(type=conn_type)
            self._idle_timeouts[conn_type] = self.idle_timeouts_total.labels(type=conn_type)

        for result in ("success", "fail", "throttled"):
            self._login_attempts[result] = self.login_attempts_total.labels(result=result)
        for result in ("success", "duplicate", "invalid"):
            self._register_attempts[result] = self.register_attempts_total.labels(result=result)

        for phase in ("first_packet", "lobby_stream", "chat_stream"):
            self._packet_parse_failures[phase] = self.packet_parse_failures_total.labels(phase=phase)

        for kind in ("read", "write", "commit", "rollback"):
            self._db_queries[kind] = self.db_queries_total.labels(kind=kind)
            self._db_durations[kind] = self.db_query_duration_seconds.labels(kind=kind)
            self._db_slow[kind] = self.db_slow_queries_total.labels(kind=kind)

        for kind in ("lobby", "lobby_batch", "chat", "game"):
            self._broadcasts[kind] = self.broadcasts_total.labels(kind=kind)
            self._broadcast_durations[kind] = self.broadcast_duration_seconds.labels(kind=kind)
            self._broadcast_targets[kind] = self.broadcast_targets.labels(kind=kind)

        for kind in ("channel", "whisper", "slash"):
            self._chat_messages[kind] = self.chat_messages_total.labels(kind=kind)
        for command in ("status", "create", "invite", "leave", "info", "members", "disband", "list", "unknown"):
            self._guild_commands[command] = self.guild_commands_total.labels(command=command)
        for result in ("success", "fail"):
            self._game_joins[result] = self.game_join_total.labels(result=result)
        for result in ("win", "loss", "draw", "unknown"):
            self._match_results[result] = self.match_results_total.labels(result=result)
        for event in (
            "login_failed", "login_throttled", "bind_rejected", "rebind_rejected",
            "rebind_replace", "session_replaced", "guild_join", "guild_create",
            "guild_invite", "guild_disband", "disconnect", "idle_timeout", "rate_limit"
        ):
            self._security_events[event] = self.security_events_total.labels(event=event)
        for kind in ("read", "write", "commit", "rollback"):
            self._db_errors[kind] = self.db_operation_errors_total.labels(kind=kind)
        for conn_type in ("lobby", "chat"):
            self._send_failures[conn_type] = self.send_failures_total.labels(type=conn_type)
        for cache in ("guild_by_member", "game_by_player", "hosted_game_by_host"):
            self._world_cache_sizes[cache] = self.world_cache_size.labels(cache=cache)

    def start(self):
        if not self.requested_enabled:
            return
        if not _PROMETHEUS_AVAILABLE:
            if not self._warned_missing:
                log.warning(
                    "Prometheus metrics requested but prometheus_client is not installed"
                )
                self._warned_missing = True
            return
        if self.started:
            return
        self._start_cors_metrics_server(self.host, self.port)
        self.started = True
        self.up.set(1)
        self.start_time_seconds.set(self.start_time)
        log.info("Prometheus metrics listening on %s:%d", self.host, self.port)

    @staticmethod
    def _start_cors_metrics_server(host: str, port: int):
        """Start a metrics HTTP server with CORS headers."""
        import threading
        from http.server import HTTPServer, BaseHTTPRequestHandler

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path != "/metrics":
                    self.send_response(404)
                    self.end_headers()
                    return
                output = generate_latest()
                self.send_response(200)
                self.send_header("Content-Type", CONTENT_TYPE_LATEST)
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(output)

            def do_OPTIONS(self):
                self.send_response(204)
                self.send_header("Access-Control-Allow-Origin", "*")
                self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
                self.send_header("Access-Control-Allow-Headers", "*")
                self.end_headers()

            def log_message(self, format, *args):
                pass  # suppress request logs

        server = HTTPServer((host, port), Handler)
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()

    def set_active_connections(self, total: int, lobby: int, chat: int):
        if not self.enabled:
            return
        self.active_connections.set(total)
        self._active_conn_lobby.set(lobby)
        self._active_conn_chat.set(chat)

    def inc_connection_accepted(self):
        if self.enabled:
            self.connections_accepted_total.inc()

    def inc_connection_rejected(self, reason: str):
        if self.enabled:
            counter = self._connection_rejected.get(reason)
            if counter is None:
                counter = self.connections_rejected_total.labels(reason=reason)
                self._connection_rejected[reason] = counter
            counter.inc()

    def inc_disconnect(self, conn_type: str):
        if self.enabled:
            self._disconnects[conn_type].inc()

    def inc_idle_timeout(self, conn_type: str):
        if self.enabled:
            self._idle_timeouts[conn_type].inc()

    def inc_login_attempt(self, result: str):
        if self.enabled:
            self._login_attempts[result].inc()

    def inc_register_attempt(self, result: str):
        if self.enabled:
            self._register_attempts[result].inc()

    def set_auth_blocks_active(self, count: int):
        if self.enabled:
            self.auth_blocks_active.set(count)

    def inc_packet_received(self, conn_type: str, opcode: int):
        if not self.enabled:
            return
        key = (conn_type, opcode)
        counter = self._packet_received.get(key)
        if counter is None:
            counter = self.packets_received_total.labels(
                type=conn_type, opcode=_OPCODE_LABELS[opcode & 0xFF]
            )
            self._packet_received[key] = counter
        counter.inc()

    def inc_packet_sent(self, conn_type: str, opcode: int):
        if not self.enabled:
            return
        key = (conn_type, opcode)
        counter = self._packet_sent.get(key)
        if counter is None:
            counter = self.packets_sent_total.labels(
                type=conn_type, opcode=_OPCODE_LABELS[opcode & 0xFF]
            )
            self._packet_sent[key] = counter
        counter.inc()

    def inc_packet_parse_failure(self, phase: str):
        if self.enabled:
            self._packet_parse_failures[phase].inc()

    def observe_db_query(self, kind: str, elapsed_ms: float, slow: bool = False):
        if not self.enabled:
            return
        self._db_queries[kind].inc()
        self._db_durations[kind].observe(elapsed_ms / 1000.0)
        if slow:
            self._db_slow[kind].inc()

    def observe_broadcast(self, kind: str, elapsed_ms: float, targets: int):
        if not self.enabled:
            return
        counter = self._broadcasts.get(kind)
        duration = self._broadcast_durations.get(kind)
        target_hist = self._broadcast_targets.get(kind)
        if counter is None:
            counter = self.broadcasts_total.labels(kind=kind)
            duration = self.broadcast_duration_seconds.labels(kind=kind)
            target_hist = self.broadcast_targets.labels(kind=kind)
            self._broadcasts[kind] = counter
            self._broadcast_durations[kind] = duration
            self._broadcast_targets[kind] = target_hist
        counter.inc()
        duration.observe(elapsed_ms / 1000.0)
        target_hist.observe(targets)

    def observe_lobby_build(self, elapsed_ms: float, slow: bool = False):
        if not self.enabled:
            return
        self.lobby_build_duration_seconds.observe(elapsed_ms / 1000.0)
        if slow:
            self.lobby_build_slow_total.inc()

    def inc_chat_message(self, kind: str):
        if self.enabled:
            self._chat_messages[kind].inc()

    def inc_chat_rate_limited(self):
        if self.enabled:
            self.chat_rate_limited_total.inc()

    def inc_guild_command(self, command: str):
        if not self.enabled:
            return
        counter = self._guild_commands.get(command)
        if counter is None:
            counter = self.guild_commands_total.labels(command=command)
            self._guild_commands[command] = counter
        counter.inc()

    def inc_game_create(self):
        if self.enabled:
            self.game_create_total.inc()

    def inc_game_join(self, result: str):
        if self.enabled:
            self._game_joins[result].inc()

    def inc_match_result(self, result: str):
        if self.enabled:
            self._match_results[result].inc()

    def inc_rank_recalculation(self):
        if self.enabled:
            self.rank_recalculations_total.inc()

    def inc_security_event(self, event: str):
        if not self.enabled:
            return
        counter = self._security_events.get(event)
        if counter is None:
            counter = self.security_events_total.labels(event=event)
            self._security_events[event] = counter
        counter.inc()

    def inc_db_operation_error(self, kind: str):
        if self.enabled:
            self._db_errors[kind].inc()

    def inc_send_failure(self, conn_type: str):
        if self.enabled:
            self._send_failures[conn_type].inc()

    def set_world_state(self, channels: int, users_online: int,
                        games_active: int, guilds_total: int):
        if not self.enabled:
            return
        self.channels.set(channels)
        self.users_online.set(users_online)
        self.games_active.set(games_active)
        self.guilds_total.set(guilds_total)

    def set_channel_state(self, channel: str, users: int, games: int):
        if not self.enabled:
            return
        user_gauge = self._channel_users.get(channel)
        if user_gauge is None:
            user_gauge = self.channel_users.labels(channel=channel)
            self._channel_users[channel] = user_gauge
        game_gauge = self._channel_games.get(channel)
        if game_gauge is None:
            game_gauge = self.channel_games.labels(channel=channel)
            self._channel_games[channel] = game_gauge
        user_gauge.set(users)
        game_gauge.set(games)

    def sync_channel_states(self, channel_states: dict[str, tuple[int, int]]):
        if not self.enabled:
            return
        current = set(channel_states.keys())
        for channel in self._known_channels - current:
            self.set_channel_state(channel, 0, 0)
        for channel, (users, games) in channel_states.items():
            self.set_channel_state(channel, users, games)
        self._known_channels = current

    def set_world_cache_sizes(self, guild_by_member: int, game_by_player: int,
                              hosted_game_by_host: int):
        if not self.enabled:
            return
        self._world_cache_sizes["guild_by_member"].set(guild_by_member)
        self._world_cache_sizes["game_by_player"].set(game_by_player)
        self._world_cache_sizes["hosted_game_by_host"].set(hosted_game_by_host)
