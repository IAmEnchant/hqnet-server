"""Packet builders (server → client payloads, WITHOUT the 3-byte header)."""

import struct
from typing import Optional

from hqnet.protocol import (
    ENCODING, NAME_SIZE, NAME_FIELD, MAP_SIZE,
    GAME_ENTRY_SIZE, USER_DETAIL_SIZE, CHANNEL_DELIMITER,
    encode_fixed,
)
from hqnet.models import (
    DEFAULT_GRADE,
    GRADE_TITLES,
    UserInfo,
    GameInfo,
    GAME_ROOM_SETUP,
    GAME_ROOM_PLAYING,
)

GRADE_LEVELS = {title: idx + 1 for idx, title in enumerate(GRADE_TITLES)}

def _grade_level(grade: str) -> int:
    """Parse grade string like 'Lv3' → 3 (numeric level for packet encoding)."""
    if not grade:
        return 0
    if grade in GRADE_LEVELS:
        return GRADE_LEVELS[grade]
    if grade.startswith('Lv'):
        try:
            return int(grade[2:])
        except ValueError:
            pass
    if grade == DEFAULT_GRADE:
        return 1
    return 0

# ── handshake / auth ──────────────────────────────────────────────────────────

def pkt_ack1() -> bytes:
    """0x01 – echo back (handshake step 2)."""
    return b'\x01'

def pkt_ack2() -> bytes:
    """0x03 – challenge (handshake step 4)."""
    return b'\x03'

def pkt_proceed() -> bytes:
    """0x06 sub 0 – advance client to auth screen (handshake step 6)."""
    return b'\x06\x00'

def pkt_grade(sub: int, name: str, grade: str) -> bytes:
    """0x02 – grade info.
    Format: [0x02][sub(1)][name(21)][len(2,BE)][grade_data].
    Send empty grade_data (grade='') during auth to avoid spurious chat log entry.
    """
    p = bytearray([0x02, sub])
    p += encode_fixed(name, NAME_SIZE)
    grade_data = grade.encode(ENCODING, errors='replace')
    p += struct.pack('>H', len(grade_data))
    p += grade_data
    return bytes(p)

def pkt_auth_ok() -> bytes:
    """0x92 sub 0 – auth accepted, advance to the login screen."""
    return b'\x92\x00'

# ── login result (0x62) ───────────────────────────────────────────────────────

def pkt_login_ok() -> bytes:
    """0x62 sub 0 – login accepted (client transitions to the lobby).
    CRITICAL: sub 0 is the only value that makes the client enter the lobby.
    """
    return b'\x62\x00'

def pkt_login_fail(reason: int = 4) -> bytes:
    """0x62 sub 1-5 – login failure.
    1 = 이미 접속중입니다 (already connected)
    3 = 존재하지 않는 계정입니다 (account not found)
    4 = 비밀번호가 맞지 않습니다 (wrong password)
    """
    return bytes([0x62, max(1, min(reason, 5))])

# ── channel list (0x04) ───────────────────────────────────────────────────────

def pkt_channel_list(names: list[str]) -> bytes:
    """0x04 – channel name list (newline-delimited)."""
    body = CHANNEL_DELIMITER.join(names).encode(ENCODING)
    return b'\x04' + struct.pack('>H', len(body)) + body

# ── user name list (0x74) ─────────────────────────────────────────────────────

def pkt_user_list(names: list[str]) -> bytes:
    """0x74 sub 0 – full user name list.
    byte_count = len(names) × 21 (NOT entry count).
    """
    bc = len(names) * NAME_SIZE
    p = bytearray(b'\x74\x00') + struct.pack('>H', bc)
    for n in names:
        p += encode_fixed(n, NAME_SIZE)
    return bytes(p)

def pkt_user_add(name: str) -> bytes:
    """0x74 sub 1 – add single user (20-byte raw name field)."""
    return b'\x74\x01' + encode_fixed(name, NAME_FIELD)

def pkt_user_remove(name: str) -> bytes:
    """0x74 sub 2 – remove single user (20-byte raw name field)."""
    return b'\x74\x02' + encode_fixed(name, NAME_FIELD)

# ── user details (0x75) ───────────────────────────────────────────────────────

def _user_detail_entry(u: UserInfo) -> bytes:
    """27-byte entry: [name(20)][type(1)][grade(1)][id(4,BE)][attr(1)].
    type 0 = in lobby (plain name), 1 = in game ("[게임중] name" in join dialog).
    """
    return (encode_fixed(u.name, NAME_FIELD)
            + bytes([u.user_type, _grade_level(u.grade)])
            + struct.pack('>I', u.user_id)
            + bytes([u.attr]))

def pkt_user_details(users: list[UserInfo]) -> bytes:
    """0x75 sub 0 – full user details list. byte_count = len × 27."""
    bc = len(users) * USER_DETAIL_SIZE
    p = bytearray(b'\x75\x00') + struct.pack('>H', bc)
    for u in users:
        p += _user_detail_entry(u)
    return bytes(p)

def pkt_user_detail_add(u: UserInfo) -> bytes:
    """0x75 sub 1 – add / update single user detail."""
    return b'\x75\x01' + _user_detail_entry(u)

def pkt_user_detail_remove(name: str, uid: int) -> bytes:
    """0x75 sub 2 – remove single user."""
    return (b'\x75\x02'
            + encode_fixed(name, NAME_FIELD)
            + bytes([0, 0])          # type, grade (unused in remove)
            + struct.pack('>I', uid)
            + bytes([0]))            # attr (unused in remove)

def _game_room_detail_entry(g: GameInfo, host: UserInfo) -> bytes:
    """27-byte 0x75 entry for game room (join dialog context).
    name = room name (displayed in join dialog),
    type = g.status: 0 (설정중/joinable) or 1 (진행중),
    grade = host's grade (non-zero → join button enabled),
    IP = host's IP (big-endian for the x86 client to decode),
    attr = 0x0f → enables the join button group on the client (the client
           checks attr == 0x0f/0x10 and requires a non-zero host grade).
    """
    return (encode_fixed(g.name, NAME_FIELD)
            + bytes([g.status, max(_grade_level(host.grade), 1)])
            + g.host_ip
            + bytes([0x0f]))

def pkt_game_room_details(rooms: list[tuple[GameInfo, UserInfo]]) -> bytes:
    """0x75 sub 0 – game room list for join dialog.
    The lobby only reads 0x76, not 0x75, so this does not
    affect the lobby participant list.
    """
    bc = len(rooms) * USER_DETAIL_SIZE
    p = bytearray(b'\x75\x00') + struct.pack('>H', bc)
    for g, host in rooms:
        p += _game_room_detail_entry(g, host)
    return bytes(p)

# ── game / participant list (0x76) ────────────────────────────────────────────

def _game_entry(g: GameInfo) -> bytes:
    """50-byte game room entry (type depends on status → game list widget).
    status=0 → type=0x0b (설정중, icon group 1)
    status=1 → type=0x0d (진행중, icon group 2)
    """
    room_type = GAME_ROOM_PLAYING if g.status else GAME_ROOM_SETUP
    e = bytearray()
    e += encode_fixed(g.name, NAME_SIZE)            # 21
    e += encode_fixed(g.map_name, MAP_SIZE)          # 9
    e += struct.pack('>H', g.field1)                 # 2  wins (reused)
    e += struct.pack('>H', g.field2)                 # 2  losses
    e += struct.pack('>H', g.field3)                 # 2  draws
    e += struct.pack('>H', g.field4)                 # 2  grade
    e += struct.pack('>I', g.field5)                 # 4  score/exp
    e += struct.pack('>H', g.field6)                 # 2  f6
    e += struct.pack('>I', g.field7)                 # 4  f7
    e += bytes([room_type, g.status])                # 2  type, status
    assert len(e) == GAME_ENTRY_SIZE
    return bytes(e)

def _user_entry_76(u: UserInfo) -> bytes:
    """50-byte channel user entry (type=0x0f → lobby participant list).
    Fields: name(21)+map(9)+wins(2)+losses(2)+draws(2)+grade(2)+id(4)+f6(2)+f7(4)+type(1)+status(1)
    List entries show as plain names; "[게임중]" is set via 0x75 user_type=1, not here.
    map field (offset 21, 9 bytes): guild tag — rendered as [tag] in list items
    by the 0x76 handler (half-width brackets). Also rendered in the lobby info
    header as 【tag】 (full-width brackets), gated by the 0x63 tag field. Both
    visible on selection → duplicate if both set.
    0x63 tag MUST be empty to avoid "[TG]【TG】name" duplication.
    """
    e = bytearray()
    e += encode_fixed(u.name, NAME_SIZE)                    # 21
    e += encode_fixed(u.guild_tag, MAP_SIZE)                      # 9   clan tag (selection detail reads this)
    e += struct.pack('>H', min(u.wins,         0xFFFF))     # 2   wins
    e += struct.pack('>H', min(u.losses,       0xFFFF))     # 2   losses
    e += struct.pack('>H', min(u.draws,        0xFFFF))     # 2   draws
    e += struct.pack('>H', min(u.total_rank, 0xFFFF))       # 2   total rank (selection/detail path)
    e += struct.pack('>I', min(u.rank, 0xFFFFFFFF))         # 4   total points for title lookup
    e += struct.pack('>H', min(u.weekly_rank, 0xFFFF))      # 2   weekly rank
    e += struct.pack('>I', min(u.weekly_points, 0xFFFFFFFF))# 4   weekly points
    e += bytes([0x0F, 0])                                   # 2   type=0x0F, status=0
    assert len(e) == GAME_ENTRY_SIZE
    return bytes(e)

def pkt_game_list(games: list[GameInfo],
                  users: Optional[list[UserInfo]] = None) -> bytes:
    """0x76 sub 0 – full participant/game list → lobby display.
    0x74 populates a SEPARATE widget used by 대화방 설정 (chat-room settings);
    channel names go there via pkt_user_list, not here.
    Sub-0 clears the participant list widget before populating.
    """
    users = users or []
    entries = bytearray()
    for u in users:
        entries += _user_entry_76(u)
    for g in games:
        entries += _game_entry(g)
    return bytes(b'\x76\x00' + struct.pack('>H', len(entries)) + entries)

def pkt_user_add_76(u: UserInfo) -> bytes:
    """0x76 sub 1 – add single user to participant list (type=0x0f)."""
    return b'\x76\x01' + _user_entry_76(u)

def pkt_game_remove(name: str) -> bytes:
    """0x76 sub 2 – remove entry by name (works for both game rooms and users)."""
    return b'\x76\x02' + encode_fixed(name, NAME_SIZE)

# ── game room creation result (0x69 → DP HOST) ───────────────────────────────

def pkt_game_create_ok() -> bytes:
    """0x69 sub 0 – create OK; sent to game CREATOR (0x19 sender).
    Client opens the DirectPlay session in CREATE mode → DP HOST (binds 2560, listens).
    Creator becomes the DirectPlay session host; joiner connects to this host.
    """
    return b'\x69\x00'

def pkt_game_create_fail() -> bytes:
    """0x70 sub 1 – create fail; shows dialog "개설된 방에 입장할 수 없습니다" then returns to lobby."""
    return b'\x70\x01'

# ── game join result (0x70 → DP CLIENT) ───────────────────────────────────────

def pkt_join_ok() -> bytes:
    """0x70 sub 0 – join OK; sent to game JOINER (0x20 sender).
    Client enumerates sessions and opens in JOIN mode → DP CLIENT.
    Joiner connects to the creator's IP (taken from the join dialog).
    """
    return b'\x70\x00'

def pkt_join_fail() -> bytes:
    """0x69 sub 1 – join fail."""
    return b'\x69\x01'

# ── P2P match result (0x71) ───────────────────────────────────────────────────

def pkt_p2p_ok() -> bytes:
    """0x71 sub 0 – P2P match OK; silent return to lobby."""
    return b'\x71\x00'

# ── character select result (0x90) ────────────────────────────────────────────

def pkt_char_select_ok() -> bytes:
    """0x90 sub 0 – character selection accepted; client transitions to the lobby.
    Send in response to 0x40 (character select confirm).
    """
    return b'\x90\x00'

# ── game options broadcast (0x81) ─────────────────────────────────────────────

def pkt_game_options(g: GameInfo) -> bytes:
    """0x81 sub 0 – game options broadcast.
    Format: [81][sub(1)][name(21)][f1-f6(6×1)][options(2,BE)][speed(2,BE)][diff(1)]
    Total: 34 bytes (including opcode).
    Send in response to 0x29 (game room ready signal), along with 0x76 sub-0.
    """
    team_size = g.team_size if 1 <= g.team_size <= 4 else 1
    p = bytearray([0x81, 0x00])
    p += encode_fixed(g.host, NAME_SIZE)            # 21 bytes: host name
    p += struct.pack('>HHH', team_size, team_size, 0)
    p += struct.pack('>HH', g.max_players, 0)       # options(2,BE), speed(2,BE)
    p += bytes([team_size])                         # diff(1): room mode 1..4
    return bytes(p)

# ── chat server info (0x63) ───────────────────────────────────────────────────

def pkt_chat_server_info(u: UserInfo, channel_name: str = '') -> bytes:
    """0x63 – triggers client to open the chat TCP socket.
    Format: [63][wins(2,BE)][losses(2,BE)][draws(2,BE)][grade(2,BE)][exp(4,BE)]
            [f4(2,BE)][rank(4,BE)][name(20)][tag(9)][uid(4,BE)]
    Total payload: 52 bytes (including opcode).

    name field → rendered as "[ %s ]" in the lobby header.
    Stat-header matching compares against the login username (NOT this name field),
    so changing the name here does NOT affect the stat display.
    The chat-socket identify also uses the login username, not this field.
    We put the channel name here so the lobby header shows "[ General ]".

    Tag field gates the info-header tag display (full-width 【tag】). If non-empty,
    the lobby renders 【tag】 in the header, which DUPLICATES the 0x76 list item
    [tag] (half-width). Keep tag EMPTY here; guild tag is displayed via the 0x76
    map field only (list items + selection).
    """
    p = bytearray([0x63])
    p += struct.pack('>HHHH',
                     min(u.wins,         0xFFFF),   # wins
                     min(u.losses,       0xFFFF),   # losses
                     min(u.draws,        0xFFFF),   # draws
                     min(u.total_rank,   0xFFFF))   # total rank (also title tier hint)
    p += struct.pack('>I', min(u.rank, 0xFFFFFFFF))          # exp/points used by title lookup
    p += struct.pack('>H', min(u.weekly_rank, 0xFFFF))       # weekly rank
    p += struct.pack('>I', min(u.weekly_points, 0xFFFFFFFF)) # weekly points
    p += encode_fixed(channel_name or u.name, NAME_FIELD)  # name → lobby "[ %s ]"
    p += encode_fixed('', MAP_SIZE)             # tag  (9 bytes) — MUST be empty; 0x76 handles tag display via list items
    p += struct.pack('>I', u.user_id)         # uid
    return bytes(p)

# ── chat message (0x02) ───────────────────────────────────────────────────────

def pkt_chat_msg(msg_type: int, sender: str, msg: str) -> bytes:
    """Chat message (both directions).
    Format: [02][type(1)][sender(21)][len(2,BE)][message(EUC-KR)]
    type 0 = channel broadcast, type 1 = whisper/private.
    """
    body = msg.encode(ENCODING, errors='replace')
    p = bytearray([0x02, msg_type])
    p += encode_fixed(sender, NAME_SIZE)
    p += struct.pack('>H', len(body))
    p += body
    return bytes(p)

# ── channel / room info (0x86) ───────────────────────────────────────────────

def pkt_channel_info(user_count: int, max_users: int = 0) -> bytes:
    """0x86 sub 0 – channel/room detail display (response to 0x36 with channel name).
    Format: [86][00][byte1(1)][byte2(1)] = 4 bytes payload.
    The client renders this on the channel detail panel:
      Line 1: "방이름 : [selected_entry_name]"   (from the 대화방 설정 widget)
      Line 2: "인원 [byte2] / [byte1]"
    byte1 = count1 (denominator), byte2 = count2 (numerator).
    """
    return bytes([0x86, 0x00, max_users & 0xFF, user_count & 0xFF])

# ── guild dialog (0x87) ──────────────────────────────────────────────────────

def pkt_guild_info_result(guild_name: str, field2: str, found: bool = True) -> bytes:
    """0x91 – guild info display result (response to 0x36).
    Format: [91][sub(1)][guild_name(21)][field2(21)] = 44 bytes payload.
    sub=0: success → the lobby list shows guild_name + field2.
    sub≠0: not found.
    """
    sub = 0 if found else 1
    return (bytes([0x91, sub])
            + encode_fixed(guild_name, NAME_SIZE)
            + encode_fixed(field2, NAME_SIZE))

def pkt_guild_screen(name: str, leader: str) -> bytes:
    """0x87 – trigger guild invitation dialog on client.
    Format: [87][guild_name(21)][leader_name(9)] = 31 bytes payload.
    Client displays: "[guild_name]의 길드장 [leader_name]님이 ..."
    Second field is leader name (shown as inviter), NOT guild tag.
    """
    return b'\x87' + encode_fixed(name, NAME_SIZE) + encode_fixed(leader, MAP_SIZE)

# ── misc ──────────────────────────────────────────────────────────────────────

def pkt_account_check(sub: int) -> bytes:
    """0x64 – account ID check result. sub=0: OK, sub=1/2: error."""
    return bytes([0x64, sub])

def pkt_password_change(sub: int) -> bytes:
    """0x66 – password change result. sub=0: success, sub=1-3: failure."""
    return bytes([0x66, sub])

def pkt_name_change(sub: int, name: str = '') -> bytes:
    """0x68 – name change result.
    sub=0: success → lobby transition.
    sub=1: error dialog.
    sub=2: name updated → name(20) + lobby transition.
    """
    p = bytes([0x68, sub])
    if sub == 2:
        p += encode_fixed(name, NAME_FIELD)
    return p

def pkt_heartbeat_ack() -> bytes:
    """0x72 sub 0 – heartbeat ACK; clears the client's wait flag.
    Sent in response to 0x22 (interval heartbeat).
    """
    return b'\x72\x00'

def pkt_disconnect() -> bytes:
    """0x09 – force client disconnect."""
    return b'\x09'
