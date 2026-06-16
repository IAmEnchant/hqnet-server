"""Data models and state enum."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto

GRADE_TITLES: tuple[str, ...] = (
    '이병',
    '일병',
    '상병',
    '병장',
    '하사',
    '중사',
    '상사',
    '원사',
    '준위',
    '소위',
    '중위',
    '대위',
    '소령',
    '중령',
    '대령',
    '준장',
    '소장',
    '중장',
    '대장',
    '원수',
)
DEFAULT_GRADE = GRADE_TITLES[0]


@dataclass
class UserInfo:
    name: str
    account: str = ''
    grade: str = DEFAULT_GRADE
    user_id: int = 0
    user_type: int = 0   # 0=in lobby  1=in game  2=spectator
    attr: int = 0
    channel: str | None = None
    # stats (loaded from DB)
    wins: int = 0
    losses: int = 0
    draws: int = 0
    rank: int = 0
    total_rank: int = 0
    weekly_points: int = 0
    weekly_rank: int = 0
    # guild
    guild_name: str = ''
    guild_tag: str = ''
    # runtime refs
    ignored: set[str] = field(default_factory=set)  # names this user is ignoring
    session: ClientSession | None = None
    chat_handler: ChatHandler | None = None


@dataclass
class GuildInfo:
    guild_id: int
    name: str
    tag: str
    leader: str
    members: list[str] = field(default_factory=list)


# 0x76 type field — game room icon groups
GAME_ROOM_SETUP   = 0x0b  # 설정중 (icon group 1)
GAME_ROOM_PLAYING = 0x0d  # 진행중 (icon group 2)


@dataclass
class GameInfo:
    name: str
    map_name: str = ''
    host: str = ''
    host_ip: bytes = b'\x00\x00\x00\x00'
    password: str = ''
    players: list[str] = field(default_factory=list)
    max_players: int = 8
    team_size: int = 1
    status: int = 0       # 0=waiting 1=playing
    # extra 50-byte entry fields
    field1: int = 0
    field2: int = 0
    field3: int = 0
    field4: int = 0
    field5: int = 0
    field6: int = 0
    field7: int = 0
    created_at: float = 0.0
    result_submissions: set[str] = field(default_factory=set)
    all_players_snapshot: list[str] = field(default_factory=list)  # frozen at first result


@dataclass
class ChannelInfo:
    name: str
    users: list[str] = field(default_factory=list)
    games: list[str] = field(default_factory=list)
    # Game names removed during this server session. Sent as 0x76 sub-2 removes to
    # users who connect after removal (the game-list widget is never cleared by sub-0).
    stale_game_removes: set[str] = field(default_factory=set)


class State(Enum):
    AWAIT_HANDSHAKE = auto()
    SENT_ACK1 = auto()
    SENT_ACK2 = auto()
    AWAIT_AUTH = auto()
    AWAIT_LOGIN = auto()
    LOGGED_IN = auto()
    DISCONNECTED = auto()


# These are resolved at runtime via TYPE_CHECKING to avoid circular imports.
# The forward references in UserInfo are strings, so no actual import needed.
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from hqnet.session import ClientSession
    from hqnet.chat import ChatHandler
