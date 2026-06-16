"""AccountDB – SQLite-backed account storage with SHA-256 password hashing."""

from collections import defaultdict
from datetime import datetime, timedelta, timezone
import hashlib
import logging
import sqlite3
import time
from pathlib import Path

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from hqnet.models import DEFAULT_GRADE, GRADE_TITLES
from hqnet.metrics import Metrics

log = logging.getLogger(__name__)
SLOW_QUERY_MS = 10.0
SLOW_QUERY_COUNTS: dict[str, int] = defaultdict(int)
PASSWORD_HASHER = PasswordHasher()
GRADE_THRESHOLDS: tuple[tuple[int, str], ...] = (
    (0, GRADE_TITLES[0]),
    (200, GRADE_TITLES[1]),
    (420, GRADE_TITLES[2]),
    (662, GRADE_TITLES[3]),
    (928, GRADE_TITLES[4]),
    (1221, GRADE_TITLES[5]),
    (1543, GRADE_TITLES[6]),
    (1897, GRADE_TITLES[7]),
    (2287, GRADE_TITLES[8]),
    (2716, GRADE_TITLES[9]),
    (3187, GRADE_TITLES[10]),
    (3706, GRADE_TITLES[11]),
    (4277, GRADE_TITLES[12]),
    (4905, GRADE_TITLES[13]),
    (5595, GRADE_TITLES[14]),
    (6354, GRADE_TITLES[15]),
    (7190, GRADE_TITLES[16]),
    (8109, GRADE_TITLES[17]),
    (9120, GRADE_TITLES[18]),
    (10232, GRADE_TITLES[19]),
)

class AccountDB:
    def __init__(self, path: str = "hqnet.db", metrics: Metrics | None = None):
        self._path = Path(path)
        self.metrics = metrics or Metrics(False)
        self._conn = sqlite3.connect(self._path)
        self._configure_connection()
        self._init_db()
        log.info("Account DB opened: %s", self._path.resolve())

    def _execute_kind(self, kind: str, sql: str, params: tuple = ()):
        started = time.perf_counter()
        try:
            return self._conn.execute(sql, params)
        except sqlite3.Error:
            self.metrics.inc_db_operation_error(kind)
            raise
        finally:
            self._log_query(kind, sql, started)

    def _execute_read(self, sql: str, params: tuple = ()):
        return self._execute_kind("read", sql, params)

    def _execute_write(self, sql: str, params: tuple = ()):
        return self._execute_kind("write", sql, params)

    def _fetchone(self, sql: str, params: tuple = ()):
        return self._execute_read(sql, params).fetchone()

    def _fetchall(self, sql: str, params: tuple = ()):
        return self._execute_read(sql, params).fetchall()

    def _commit(self):
        started = time.perf_counter()
        try:
            self._conn.commit()
        except sqlite3.Error:
            self.metrics.inc_db_operation_error("commit")
            raise
        finally:
            self._log_query("commit", "COMMIT", started)

    def _rollback(self):
        started = time.perf_counter()
        try:
            self._conn.rollback()
        except sqlite3.Error:
            self.metrics.inc_db_operation_error("rollback")
            raise
        finally:
            self._log_query("rollback", "ROLLBACK", started)

    def _log_query(self, kind: str, sql: str, started: float):
        elapsed_ms = (time.perf_counter() - started) * 1000
        slow = elapsed_ms >= SLOW_QUERY_MS
        self.metrics.observe_db_query(kind, elapsed_ms, slow=slow)
        if slow:
            head = " ".join(sql.strip().split())[:80]
            SLOW_QUERY_COUNTS[head] += 1
            log.debug("Slow DB query %.2fms: %s count=%d",
                      elapsed_ms, head, SLOW_QUERY_COUNTS[head])

    def _configure_connection(self):
        """Apply SQLite settings suitable for a long-running server process."""
        self._execute_write("PRAGMA journal_mode=WAL")
        self._execute_write("PRAGMA synchronous=NORMAL")
        self._execute_write("PRAGMA foreign_keys=ON")

    def _init_db(self):
        self._execute_write(
            "CREATE TABLE IF NOT EXISTS accounts ("
            "  username TEXT PRIMARY KEY,"
            "  pw_hash  TEXT NOT NULL,"
            "  wins     INTEGER DEFAULT 0,"
            "  losses   INTEGER DEFAULT 0,"
            "  draws    INTEGER DEFAULT 0,"
            "  rank     INTEGER DEFAULT 0,"
            f"  grade    TEXT    DEFAULT '{DEFAULT_GRADE}',"
            "  created  TEXT DEFAULT CURRENT_TIMESTAMP"
            ")"
        )
        self._execute_write(
            "CREATE TABLE IF NOT EXISTS guilds ("
            "  guild_id   INTEGER PRIMARY KEY AUTOINCREMENT,"
            "  guild_name TEXT NOT NULL UNIQUE,"
            "  guild_tag  TEXT NOT NULL UNIQUE,"
            "  leader     TEXT NOT NULL,"
            "  created    TEXT DEFAULT CURRENT_TIMESTAMP"
            ")"
        )
        self._execute_write(
            "CREATE TABLE IF NOT EXISTS guild_members ("
            "  guild_id    INTEGER NOT NULL,"
            "  member_name TEXT NOT NULL UNIQUE,"
            "  rank        INTEGER DEFAULT 0,"
            "  FOREIGN KEY(guild_id) REFERENCES guilds(guild_id)"
            ")"
        )
        self._execute_write(
            "CREATE TABLE IF NOT EXISTS match_results ("
            "  result_id     INTEGER PRIMARY KEY AUTOINCREMENT,"
            "  username      TEXT NOT NULL,"
            "  result_type   INTEGER NOT NULL,"
            "  points_delta  INTEGER NOT NULL,"
            "  played_at     TEXT DEFAULT CURRENT_TIMESTAMP,"
            "  FOREIGN KEY(username) REFERENCES accounts(username)"
            ")"
        )
        self._execute_write(
            "CREATE TABLE IF NOT EXISTS packet_bans ("
            "  ip_address            TEXT PRIMARY KEY,"
            "  recent_window_started TEXT,"
            "  recent_bad_packets    INTEGER DEFAULT 0,"
            "  ban_count             INTEGER DEFAULT 0,"
            "  last_reason           TEXT DEFAULT '',"
            "  last_duration_sec     INTEGER DEFAULT 0,"
            "  is_permanent          INTEGER DEFAULT 0,"
            "  blocked_until         TEXT,"
            "  updated_at            TEXT DEFAULT CURRENT_TIMESTAMP"
            ")"
        )
        self._execute_write(
            "CREATE TABLE IF NOT EXISTS packet_ban_events ("
            "  event_id          INTEGER PRIMARY KEY AUTOINCREMENT,"
            "  ip_address        TEXT NOT NULL,"
            "  reason            TEXT NOT NULL,"
            "  recent_bad_packets INTEGER DEFAULT 0,"
            "  threshold         INTEGER DEFAULT 0,"
            "  ban_count         INTEGER DEFAULT 0,"
            "  ban_duration_sec  INTEGER DEFAULT 0,"
            "  is_permanent      INTEGER DEFAULT 0,"
            "  blocked_until     TEXT,"
            "  created_at        TEXT DEFAULT CURRENT_TIMESTAMP"
            ")"
        )
        self._execute_write(
            "CREATE TABLE IF NOT EXISTS admin_audit_logs ("
            "  event_id     INTEGER PRIMARY KEY AUTOINCREMENT,"
            "  category     TEXT NOT NULL,"
            "  message      TEXT NOT NULL,"
            "  remote_addr  TEXT DEFAULT '',"
            "  created_at   TEXT DEFAULT CURRENT_TIMESTAMP"
            ")"
        )
        self._execute_write(
            "CREATE INDEX IF NOT EXISTS idx_guild_members_guild_id "
            "ON guild_members(guild_id)"
        )
        self._execute_write(
            "CREATE INDEX IF NOT EXISTS idx_guild_members_guild_member "
            "ON guild_members(guild_id, member_name)"
        )
        self._execute_write(
            "CREATE INDEX IF NOT EXISTS idx_match_results_user_played "
            "ON match_results(username, played_at)"
        )
        self._execute_write(
            "CREATE INDEX IF NOT EXISTS idx_packet_ban_events_ip_created "
            "ON packet_ban_events(ip_address, created_at)"
        )
        self._execute_write(
            "CREATE TABLE IF NOT EXISTS chat_logs ("
            "  log_id     INTEGER PRIMARY KEY AUTOINCREMENT,"
            "  channel    TEXT NOT NULL,"
            "  sender     TEXT NOT NULL,"
            "  kind       TEXT NOT NULL DEFAULT 'channel',"
            "  target     TEXT DEFAULT '',"
            "  message    TEXT NOT NULL,"
            "  created_at TEXT DEFAULT CURRENT_TIMESTAMP"
            ")"
        )
        self._execute_write(
            "CREATE TABLE IF NOT EXISTS game_events ("
            "  event_id   INTEGER PRIMARY KEY AUTOINCREMENT,"
            "  event_type TEXT NOT NULL,"
            "  channel    TEXT DEFAULT '',"
            "  room_name  TEXT DEFAULT '',"
            "  map_name   TEXT DEFAULT '',"
            "  username   TEXT NOT NULL,"
            "  detail     TEXT DEFAULT '',"
            "  created_at TEXT DEFAULT CURRENT_TIMESTAMP"
            ")"
        )
        self._execute_write(
            "CREATE TABLE IF NOT EXISTS channels ("
            "  name       TEXT PRIMARY KEY,"
            "  is_default INTEGER DEFAULT 0,"
            "  sort_order INTEGER DEFAULT 0,"
            "  created_at TEXT DEFAULT CURRENT_TIMESTAMP"
            ")"
        )
        self._execute_write(
            "CREATE TABLE IF NOT EXISTS connection_logs ("
            "  log_id     INTEGER PRIMARY KEY AUTOINCREMENT,"
            "  event      TEXT NOT NULL,"
            "  username   TEXT DEFAULT '',"
            "  ip_address TEXT DEFAULT '',"
            "  detail     TEXT DEFAULT '',"
            "  created_at TEXT DEFAULT CURRENT_TIMESTAMP"
            ")"
        )
        self._execute_write(
            "CREATE INDEX IF NOT EXISTS idx_connection_logs_event_created "
            "ON connection_logs(event, created_at)"
        )
        self._execute_write(
            "CREATE INDEX IF NOT EXISTS idx_connection_logs_username "
            "ON connection_logs(username, created_at)"
        )
        self._execute_write(
            "CREATE INDEX IF NOT EXISTS idx_chat_logs_channel_created "
            "ON chat_logs(channel, created_at)"
        )
        self._execute_write(
            "CREATE INDEX IF NOT EXISTS idx_chat_logs_sender "
            "ON chat_logs(sender, created_at)"
        )
        self._execute_write(
            "CREATE INDEX IF NOT EXISTS idx_game_events_type_created "
            "ON game_events(event_type, created_at)"
        )
        self._execute_write(
            "CREATE INDEX IF NOT EXISTS idx_game_events_username "
            "ON game_events(username, created_at)"
        )
        self._execute_write(
            "CREATE INDEX IF NOT EXISTS idx_admin_audit_logs_created "
            "ON admin_audit_logs(created_at)"
        )
        self._commit()
        # Migrate: add columns if they don't exist yet (for existing DBs)
        for col, typedef in [
            ("wins", "INTEGER DEFAULT 0"),
            ("losses", "INTEGER DEFAULT 0"),
            ("draws", "INTEGER DEFAULT 0"),
            ("rank", "INTEGER DEFAULT 0"),
            ("grade", f"TEXT DEFAULT '{DEFAULT_GRADE}'"),
        ]:
            try:
                self._execute_write(f"ALTER TABLE accounts ADD COLUMN {col} {typedef}")
                self._commit()
            except sqlite3.OperationalError:
                pass  # column already exists
        for table, col, typedef in [
            ("packet_bans", "is_permanent", "INTEGER DEFAULT 0"),
            ("packet_ban_events", "is_permanent", "INTEGER DEFAULT 0"),
        ]:
            try:
                self._execute_write(f"ALTER TABLE {table} ADD COLUMN {col} {typedef}")
                self._commit()
            except sqlite3.OperationalError:
                pass

    @staticmethod
    def _legacy_hash(username: str, password: str) -> str:
        return hashlib.sha256((username + password).encode()).hexdigest()

    @staticmethod
    def _hash_password(password: str) -> str:
        return PASSWORD_HASHER.hash(password)

    @staticmethod
    def _verify_password_hash(username: str, password: str, stored_hash: str) -> tuple[bool, bool]:
        if not stored_hash:
            return False, False
        try:
            verified = PASSWORD_HASHER.verify(stored_hash, password)
            needs_rehash = PASSWORD_HASHER.check_needs_rehash(stored_hash)
            return verified, needs_rehash
        except InvalidHashError:
            return stored_hash == AccountDB._legacy_hash(username, password), True
        except VerificationError:
            return False, False

    @staticmethod
    def grade_for_rank(rank: int) -> str:
        """Map rank points to the client title string."""
        grade = GRADE_THRESHOLDS[0][1]
        for min_rank, label in GRADE_THRESHOLDS:
            if rank < min_rank:
                break
            grade = label
        return grade

    @staticmethod
    def calculate_progression(wins: int, losses: int, draws: int) -> tuple[int, str]:
        """Derive rank points and grade string from match results."""
        rank = max((wins * 120) + (draws * 40) - (losses * 30), 0)
        return rank, AccountDB.grade_for_rank(rank)

    @staticmethod
    def _week_start_utc(now: datetime | None = None) -> str:
        current = now or datetime.now(timezone.utc)
        week_start = (current - timedelta(days=current.weekday())).replace(
            hour=0, minute=0, second=0, microsecond=0
        )
        return week_start.strftime("%Y-%m-%d %H:%M:%S")

    @staticmethod
    def _utcnow() -> datetime:
        return datetime.now(timezone.utc)

    @staticmethod
    def _fmt_dt(value: datetime | None) -> str | None:
        if value is None:
            return None
        return value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    @staticmethod
    def _parse_dt(value: str | None) -> datetime | None:
        if not value:
            return None
        return datetime.strptime(value, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)

    def register(self, username: str, password: str) -> bool:
        """Insert a new account. Returns False if username already exists."""
        try:
            self._execute_write(
                "INSERT INTO accounts (username, pw_hash) VALUES (?, ?)",
                (username, self._hash_password(password)),
            )
            self._commit()
            log.info("Registered new account: %s", username)
            return True
        except sqlite3.IntegrityError:
            log.warning("Registration failed (duplicate): %s", username)
            return False

    def authenticate(self, username: str, password: str) -> int:
        """Check credentials. Returns 0 on success, 3=not found, 4=wrong password."""
        row = self._fetchone(
            "SELECT pw_hash FROM accounts WHERE username = ?", (username,)
        )
        if row is None:
            log.warning("Auth failed (not found): %s", username)
            return 3
        verified, needs_rehash = self._verify_password_hash(username, password, row[0] or "")
        if not verified:
            log.warning("Auth failed (bad password): %s", username)
            return 4
        if needs_rehash:
            self._execute_write(
                "UPDATE accounts SET pw_hash = ? WHERE username = ?",
                (self._hash_password(password), username),
            )
            self._commit()
            log.info("Password hash upgraded: %s", username)
        return 0

    def set_password(self, username: str, new_password: str) -> bool:
        """Update password hash directly. Returns False if the account is missing."""
        cur = self._execute_write(
            "UPDATE accounts SET pw_hash = ? WHERE username = ?",
            (self._hash_password(new_password), username),
            )
        self._commit()
        if cur.rowcount < 1:
            log.warning("Password change failed (not found): %s", username)
            return False
        log.info("Password changed: %s", username)
        return True

    def get_account_stats(self, username: str) -> dict | None:
        """Return basic stats for a user, or None if not found."""
        row = self._fetchone(
            "SELECT wins, losses, draws, rank FROM accounts WHERE username = ?",
            (username,),
        )
        if row is None:
            return None
        return {"wins": row[0] or 0, "losses": row[1] or 0,
                "draws": row[2] or 0, "rank": row[3] or 0}

    def normalize_stats(self, username: str) -> tuple[int, int, int, int, str]:
        """Ensure stored rank matches the automatic progression formula."""
        row = self._fetchone(
            "SELECT wins, losses, draws, rank FROM accounts WHERE username = ?",
            (username,),
        )
        if row is None:
            return 0, 0, 0, 0, DEFAULT_GRADE
        wins = row[0] or 0
        losses = row[1] or 0
        draws = row[2] or 0
        rank = row[3] or 0
        calc_rank, calc_grade = self.calculate_progression(wins, losses, draws)
        if rank != calc_rank:
            self.update_stats(
                username,
                wins=wins,
                losses=losses,
                draws=draws,
                rank=calc_rank,
            )
            return wins, losses, draws, calc_rank, calc_grade
        return wins, losses, draws, rank, calc_grade

    def update_stats(self, username: str, *, wins: int = 0, losses: int = 0,
                     draws: int = 0, rank: int = 0, grade: str = "") -> None:
        """Update player stats."""
        self._execute_write(
            "UPDATE accounts SET wins=?, losses=?, draws=?, rank=? "
            "WHERE username=?",
            (wins, losses, draws, rank, username),
        )
        self._commit()

    def record_match_result(self, username: str, result_type: int) -> None:
        points_delta = {1: 120, 2: -30, 3: 40}.get(result_type, 0)
        self._execute_write(
            "INSERT INTO match_results (username, result_type, points_delta) "
            "VALUES (?, ?, ?)",
            (username, result_type, points_delta),
        )
        self._commit()

    def get_total_rank_position(self, username: str, rank: int | None = None) -> int:
        if rank is None:
            row = self._fetchone("SELECT rank FROM accounts WHERE username = ?", (username,))
            if row is None:
                return 0
            rank = row[0] or 0
        row = self._fetchone(
            "SELECT COUNT(*) FROM accounts "
            "WHERE rank > ? OR (rank = ? AND username < ?)",
            (rank, rank, username),
        )
        return (row[0] or 0) + 1 if row else 1

    def get_weekly_points(self, username: str, since: str | None = None) -> int:
        row = self._fetchone(
            "SELECT COALESCE(SUM(points_delta), 0) "
            "FROM match_results WHERE username = ? AND played_at >= ?",
            (username, since or self._week_start_utc()),
        )
        return row[0] or 0 if row else 0

    def get_weekly_rank_position(self, username: str, weekly_points: int | None = None,
                                 since: str | None = None) -> int:
        window_start = since or self._week_start_utc()
        if weekly_points is None:
            weekly_points = self.get_weekly_points(username, since=window_start)
        row = self._fetchone(
            "SELECT COUNT(*) FROM ("
            "  SELECT a.username, COALESCE(SUM(m.points_delta), 0) AS weekly_points "
            "  FROM accounts a "
            "  LEFT JOIN match_results m "
            "    ON a.username = m.username AND m.played_at >= ? "
            "  GROUP BY a.username "
            "  HAVING weekly_points > ? OR (weekly_points = ? AND a.username < ?)"
            ")",
            (window_start, weekly_points, weekly_points, username),
        )
        return (row[0] or 0) + 1 if row else 1

    def get_profile_stats(self, username: str) -> dict:
        wins, losses, draws, rank, grade = self.normalize_stats(username)
        weekly_points = self.get_weekly_points(username)
        return {
            "wins": wins,
            "losses": losses,
            "draws": draws,
            "rank": rank,
            "grade": grade,
            "total_rank": self.get_total_rank_position(username, rank=rank),
            "weekly_points": weekly_points,
            "weekly_rank": self.get_weekly_rank_position(
                username, weekly_points=weekly_points
            ),
        }

    def get_packet_ban(self, ip_address: str) -> dict | None:
        row = self._fetchone(
            "SELECT ip_address, recent_window_started, recent_bad_packets, "
            "       ban_count, last_reason, last_duration_sec, is_permanent, "
            "       blocked_until, updated_at "
            "FROM packet_bans WHERE ip_address = ?",
            (ip_address,),
        )
        if not row:
            return None
        return {
            "ip_address": row[0],
            "recent_window_started": row[1],
            "recent_bad_packets": row[2] or 0,
            "ban_count": row[3] or 0,
            "last_reason": row[4] or "",
            "last_duration_sec": row[5] or 0,
            "is_permanent": bool(row[6]),
            "blocked_until": row[7],
            "updated_at": row[8],
        }

    def list_packet_bans(self, *, limit: int = 50, active_only: bool = False) -> list[dict]:
        rows = self._fetchall(
            "SELECT ip_address, recent_window_started, recent_bad_packets, "
            "       ban_count, last_reason, last_duration_sec, is_permanent, "
            "       blocked_until, updated_at "
            "FROM packet_bans ORDER BY updated_at DESC LIMIT ?",
            (max(1, int(limit)),),
        )
        now = self._utcnow()
        items: list[dict] = []
        for row in rows:
            blocked_until = self._parse_dt(row[7])
            is_permanent = bool(row[6])
            if active_only and not is_permanent:
                if blocked_until is None or blocked_until <= now:
                    continue
            items.append({
                "ip_address": row[0],
                "recent_window_started": row[1],
                "recent_bad_packets": row[2] or 0,
                "ban_count": row[3] or 0,
                "last_reason": row[4] or "",
                "last_duration_sec": row[5] or 0,
                "is_permanent": is_permanent,
                "blocked_until": row[7],
                "updated_at": row[8],
            })
        return items

    def get_packet_ban_events(self, ip_address: str, *, limit: int = 20) -> list[dict]:
        rows = self._fetchall(
            "SELECT created_at, reason, recent_bad_packets, threshold, "
            "       ban_count, ban_duration_sec, is_permanent, blocked_until "
            "FROM packet_ban_events WHERE ip_address = ? "
            "ORDER BY created_at DESC LIMIT ?",
            (ip_address, max(1, int(limit))),
        )
        return [{
            "created_at": row[0],
            "reason": row[1],
            "recent_bad_packets": row[2] or 0,
            "threshold": row[3] or 0,
            "ban_count": row[4] or 0,
            "ban_duration_sec": row[5] or 0,
            "is_permanent": bool(row[6]),
            "blocked_until": row[7],
        } for row in rows]

    def get_packet_ban_remaining(self, ip_address: str) -> float:
        row = self._fetchone(
            "SELECT is_permanent, blocked_until FROM packet_bans WHERE ip_address = ?",
            (ip_address,),
        )
        if not row:
            return 0.0
        if row[0]:
            return float("inf")
        if not row[1]:
            return 0.0
        blocked_until = self._parse_dt(row[1])
        if blocked_until is None:
            return 0.0
        return max(0.0, (blocked_until - self._utcnow()).total_seconds())

    def record_bad_packet(self, ip_address: str, reason: str, *,
                          window_sec: int, threshold: int,
                          base_block_sec: int, max_block_sec: int) -> dict:
        now = self._utcnow()
        current = self.get_packet_ban(ip_address)
        if current is None:
            recent_window_started = now
            recent_bad_packets = 1
            ban_count = 0
        else:
            recent_window_started = self._parse_dt(current["recent_window_started"]) or now
            if (now - recent_window_started).total_seconds() > window_sec:
                recent_window_started = now
                recent_bad_packets = 1
            else:
                recent_bad_packets = current["recent_bad_packets"] + 1
            ban_count = current["ban_count"]

        ban_duration_sec = 0
        is_permanent = False
        blocked_until = None
        if recent_bad_packets >= threshold:
            ban_count += 1
            if max_block_sec == -1:
                ban_duration_sec = -1
                is_permanent = True
            else:
                ban_duration_sec = min(
                    base_block_sec * (2 ** (ban_count - 1)),
                    max_block_sec,
                )
                blocked_until = now + timedelta(seconds=ban_duration_sec)
            recent_bad_packets = 0
            recent_window_started = now

        self._execute_write(
            "INSERT INTO packet_bans ("
            "  ip_address, recent_window_started, recent_bad_packets, "
            "  ban_count, last_reason, last_duration_sec, is_permanent, "
            "  blocked_until, updated_at"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP) "
            "ON CONFLICT(ip_address) DO UPDATE SET "
            "  recent_window_started = excluded.recent_window_started, "
            "  recent_bad_packets = excluded.recent_bad_packets, "
            "  ban_count = excluded.ban_count, "
            "  last_reason = excluded.last_reason, "
            "  last_duration_sec = excluded.last_duration_sec, "
            "  is_permanent = excluded.is_permanent, "
            "  blocked_until = excluded.blocked_until, "
            "  updated_at = CURRENT_TIMESTAMP",
            (
                ip_address,
                self._fmt_dt(recent_window_started),
                recent_bad_packets,
                ban_count,
                reason,
                ban_duration_sec,
                int(is_permanent),
                self._fmt_dt(blocked_until),
            ),
        )
        self._execute_write(
            "INSERT INTO packet_ban_events ("
            "  ip_address, reason, recent_bad_packets, threshold, "
            "  ban_count, ban_duration_sec, is_permanent, blocked_until"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                ip_address,
                reason,
                threshold if ban_duration_sec else recent_bad_packets,
                threshold,
                ban_count,
                ban_duration_sec,
                int(is_permanent),
                self._fmt_dt(blocked_until),
            ),
        )
        self._commit()
        return {
            "ip_address": ip_address,
            "reason": reason,
            "recent_bad_packets": recent_bad_packets,
            "threshold": threshold,
            "ban_count": ban_count,
            "ban_duration_sec": ban_duration_sec,
            "is_permanent": is_permanent,
            "blocked_until": self._fmt_dt(blocked_until),
        }

    def set_packet_ban(self, ip_address: str, *, duration_sec: int, reason: str) -> dict:
        current = self.get_packet_ban(ip_address)
        ban_count = (current["ban_count"] if current else 0) + 1
        is_permanent = duration_sec == -1
        blocked_until = None if is_permanent else self._utcnow() + timedelta(seconds=max(1, duration_sec))
        self._execute_write(
            "INSERT INTO packet_bans ("
            "  ip_address, recent_window_started, recent_bad_packets, "
            "  ban_count, last_reason, last_duration_sec, is_permanent, "
            "  blocked_until, updated_at"
            ") VALUES (?, NULL, 0, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP) "
            "ON CONFLICT(ip_address) DO UPDATE SET "
            "  recent_window_started = excluded.recent_window_started, "
            "  recent_bad_packets = excluded.recent_bad_packets, "
            "  ban_count = excluded.ban_count, "
            "  last_reason = excluded.last_reason, "
            "  last_duration_sec = excluded.last_duration_sec, "
            "  is_permanent = excluded.is_permanent, "
            "  blocked_until = excluded.blocked_until, "
            "  updated_at = CURRENT_TIMESTAMP",
            (
                ip_address,
                ban_count,
                reason,
                duration_sec,
                int(is_permanent),
                self._fmt_dt(blocked_until),
            ),
        )
        self._execute_write(
            "INSERT INTO packet_ban_events ("
            "  ip_address, reason, recent_bad_packets, threshold, "
            "  ban_count, ban_duration_sec, is_permanent, blocked_until"
            ") VALUES (?, ?, 0, 0, ?, ?, ?, ?)",
            (
                ip_address,
                reason,
                ban_count,
                duration_sec,
                int(is_permanent),
                self._fmt_dt(blocked_until),
            ),
        )
        self._commit()
        return self.get_packet_ban(ip_address) or {
            "ip_address": ip_address,
            "ban_count": ban_count,
            "last_reason": reason,
            "last_duration_sec": duration_sec,
            "is_permanent": is_permanent,
            "blocked_until": self._fmt_dt(blocked_until),
        }

    def clear_packet_ban(self, ip_address: str) -> bool:
        cur = self._execute_write(
            "UPDATE packet_bans SET recent_bad_packets = 0, ban_count = 0, "
            "last_duration_sec = 0, is_permanent = 0, blocked_until = NULL, "
            "updated_at = CURRENT_TIMESTAMP WHERE ip_address = ?",
            (ip_address,),
        )
        self._commit()
        return cur.rowcount > 0

    def add_admin_audit_log(self, category: str, message: str, remote_addr: str = '') -> None:
        self._execute_write(
            "INSERT INTO admin_audit_logs (category, message, remote_addr) "
            "VALUES (?, ?, ?)",
            (category, message, remote_addr),
        )
        self._commit()

    def list_admin_audit_logs(self, *, limit: int = 100) -> list[dict]:
        rows = self._fetchall(
            "SELECT event_id, category, message, remote_addr, created_at "
            "FROM admin_audit_logs ORDER BY event_id DESC LIMIT ?",
            (max(1, int(limit)),),
        )
        return [{
            "event_id": row[0],
            "category": row[1],
            "message": row[2],
            "remote_addr": row[3] or '',
            "created_at": row[4],
        } for row in rows]

    # ── guild CRUD ─────────────────────────────────────────────────────────

    def create_guild(self, name: str, tag: str, leader: str) -> int:
        """Create a guild. Returns guild_id on success, -1 on conflict."""
        try:
            cur = self._execute_write(
                "INSERT INTO guilds (guild_name, guild_tag, leader) VALUES (?, ?, ?)",
                (name, tag, leader),
            )
            guild_id = cur.lastrowid
            self._execute_write(
                "INSERT INTO guild_members (guild_id, member_name, rank) VALUES (?, ?, 2)",
                (guild_id, leader),
            )
            self._commit()
            log.info("Guild created: %s [%s] by %s (id=%d)", name, tag, leader, guild_id)
            return guild_id
        except sqlite3.IntegrityError:
            self._rollback()
            log.warning("Guild creation failed (conflict): %s [%s]", name, tag)
            return -1

    def disband_guild(self, guild_id: int):
        """Delete a guild and all its members."""
        self._execute_write("DELETE FROM guild_members WHERE guild_id = ?", (guild_id,))
        self._execute_write("DELETE FROM guilds WHERE guild_id = ?", (guild_id,))
        self._commit()
        log.info("Guild disbanded: id=%d", guild_id)

    def get_all_guilds_with_members(self) -> list[dict]:
        """Return all guilds with member names in a single joined query."""
        rows = self._fetchall(
            "SELECT g.guild_id, g.guild_name, g.guild_tag, g.leader, "
            "       m.member_name "
            "FROM guilds g "
            "LEFT JOIN guild_members m ON g.guild_id = m.guild_id "
            "ORDER BY g.guild_id, m.member_name"
        )
        guilds: list[dict] = []
        current_id = None
        current = None
        for guild_id, guild_name, guild_tag, leader, member_name in rows:
            if guild_id != current_id:
                current = {
                    "guild_id": guild_id,
                    "guild_name": guild_name,
                    "guild_tag": guild_tag,
                    "leader": leader,
                    "members": [],
                }
                guilds.append(current)
                current_id = guild_id
            if member_name and current is not None:
                current["members"].append(member_name)
        return guilds

    def add_guild_member(self, guild_id: int, name: str, rank: int = 0) -> bool:
        """Add a member to a guild. Returns False if already in a guild."""
        try:
            self._execute_write(
                "INSERT INTO guild_members (guild_id, member_name, rank) VALUES (?, ?, ?)",
                (guild_id, name, rank),
            )
            self._commit()
            log.info("Guild member added: %s → guild %d", name, guild_id)
            return True
        except sqlite3.IntegrityError:
            return False

    def remove_guild_member(self, guild_id: int, name: str):
        """Remove a member from a guild."""
        self._execute_write(
            "DELETE FROM guild_members WHERE guild_id = ? AND member_name = ?",
            (guild_id, name),
        )
        self._commit()
        log.info("Guild member removed: %s from guild %d", name, guild_id)

    # ── Chat / Game logs ─────────────────────────────────────────────────────

    # ── Channel management ─────────────────────────────────────────────────

    def ensure_default_channels(self, defaults: tuple[str, ...]) -> None:
        """Insert default channels if they don't exist yet."""
        for i, name in enumerate(defaults):
            try:
                self._execute_write(
                    "INSERT OR IGNORE INTO channels (name, is_default, sort_order) "
                    "VALUES (?, 1, ?)",
                    (name, i),
                )
            except sqlite3.Error:
                pass
        self._commit()

    def load_channels(self) -> list[dict]:
        """Return all channels ordered by sort_order, name."""
        rows = self._fetchall(
            "SELECT name, is_default, sort_order FROM channels "
            "ORDER BY sort_order, name"
        )
        return [{"name": r[0], "is_default": bool(r[1]), "sort_order": r[2]}
                for r in rows]

    def create_channel(self, name: str, sort_order: int = 0) -> bool:
        """Create a custom channel. Returns False if already exists."""
        try:
            self._execute_write(
                "INSERT INTO channels (name, is_default, sort_order) VALUES (?, 0, ?)",
                (name, sort_order),
            )
            self._commit()
            return True
        except sqlite3.IntegrityError:
            return False

    def delete_channel(self, name: str) -> bool:
        """Delete a non-default channel. Returns False if default or not found."""
        row = self._fetchone(
            "SELECT is_default FROM channels WHERE name = ?", (name,)
        )
        if not row or row[0]:
            return False
        self._execute_write("DELETE FROM channels WHERE name = ?", (name,))
        self._commit()
        return True

    def rename_channel(self, old_name: str, new_name: str) -> bool:
        """Rename a non-default channel. Returns False if default, not found, or name conflict."""
        row = self._fetchone(
            "SELECT is_default FROM channels WHERE name = ?", (old_name,)
        )
        if not row or row[0]:
            return False
        try:
            self._execute_write(
                "UPDATE channels SET name = ? WHERE name = ?",
                (new_name, old_name),
            )
            self._commit()
            return True
        except sqlite3.IntegrityError:
            return False

    # ── Logs ─────────────────────────────────────────────────────────────────

    def log_connection(self, event: str, username: str = "",
                       ip_address: str = "", detail: str = "") -> None:
        self._execute_write(
            "INSERT INTO connection_logs (event, username, ip_address, detail) "
            "VALUES (?, ?, ?, ?)",
            (event, username, ip_address, detail),
        )
        self._commit()

    def log_chat(self, channel: str, sender: str, message: str,
                 kind: str = "channel", target: str = "") -> None:
        self._execute_write(
            "INSERT INTO chat_logs (channel, sender, kind, target, message) "
            "VALUES (?, ?, ?, ?, ?)",
            (channel, sender, kind, target, message),
        )
        self._commit()

    def log_game_event(self, event_type: str, username: str,
                       channel: str = "", room_name: str = "",
                       map_name: str = "", detail: str = "") -> None:
        self._execute_write(
            "INSERT INTO game_events (event_type, channel, room_name, map_name, username, detail) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (event_type, channel, room_name, map_name, username, detail),
        )
        self._commit()
