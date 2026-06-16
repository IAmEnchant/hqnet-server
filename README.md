# HQNET Lobby Server

원본 게임의 로비 프로토콜을 독립적으로 재구현한 비공식 서버 에뮬레이터.
단일 TCP 포트에서 로비와 채팅을 처리하고, 계정·전적·길드·채널·게임방을 관리한다.

- Python 3.10+ (표준 라이브러리 기반의 asyncio 서버)
- 외부 의존성 3종: `argon2-cffi`, `python-dotenv`, `prometheus_client`

## 빠른 시작

```bash
pip install -r requirements.txt
cp .env.example .env          # 필요한 값 수정 (특히 HQNET_ADMIN_TOKEN)
python -m hqnet --port 6112
```

SQLite DB(`hqnet.db`)는 최초 실행 시 작업 디렉터리에 자동 생성된다.

## 설정

서버는 시작 시 저장소 루트의 `.env`를 자동 로드한다 (`.env.example` 참고).
CLI 인자가 `.env`보다 우선한다.

| 환경변수 | 기본값 | 설명 |
|---|---|---|
| `HQNET_HOST` | `127.0.0.1` | bind 호스트 |
| `HQNET_PORT` | `6112` | 서버 TCP 포트 |
| `HQNET_METRICS_ENABLED` | `false` | Prometheus metrics 엔드포인트 활성화 |
| `HQNET_METRICS_HOST` / `HQNET_METRICS_PORT` | `127.0.0.1` / `9108` | metrics bind |
| `HQNET_ADMIN_ENABLED` | `false` | 관리 제어 소켓 활성화 |
| `HQNET_ADMIN_HOST` / `HQNET_ADMIN_PORT` | `127.0.0.1` / `9110` | 관리 소켓 bind (loopback 권장) |
| `HQNET_ADMIN_TOKEN` | — | 관리 소켓 인증 토큰 (활성화 시 필수) |
| `HQNET_BAD_PACKET_WINDOW_SEC` | `10` | 불량 패킷 집계 윈도우(초) |
| `HQNET_BAD_PACKET_IP_LIMIT` | `3` | 윈도우당 IP 임계치 |
| `HQNET_BAD_PACKET_BAN_BASE_SEC` | `60` | 최초 차단 시간(초) |
| `HQNET_BAD_PACKET_BAN_MAX_SEC` | `3600` | 최대 차단 시간(초), `-1`=영구 |

주요 CLI 인자: `--host`, `--port`, `--debug`,
`--metrics-enabled/--metrics-host/--metrics-port`,
`--admin-enabled/--admin-host/--admin-port/--admin-token`.

## Docker

```bash
cp .env.example .env
docker compose up -d --build
```

- 컨테이너는 `python -m hqnet --host 0.0.0.0 --port 6112`로 실행되고
  `6112`을 노출한다. DB는 `./data`에 마운트된다.
- metrics를 쓰려면 `.env`에서 `HQNET_METRICS_ENABLED=true`로 켜고 `9108`을 함께 게시한다.
- 단일 컨테이너 실행:
  ```bash
  docker build -t hqnet-server .
  docker run --rm -p 6112:6112 -v "$PWD/data:/data" hqnet-server
  ```

## 구조

```
hqnet/
├── __main__.py   # python -m hqnet 진입점
├── server.py     # LobbyServer — TCP accept, 로비/채팅 분기, CLI/env 설정
├── session.py    # ClientSession — 로비 TCP 핸들러 (핸드셰이크~게임)
├── chat.py       # ChatHandler — 채팅 TCP 핸들러
├── protocol.py   # PacketCodec, 상수 (EUC-KR, 필드 크기)
├── packets.py    # 서버→클라이언트 패킷 빌더
├── models.py     # UserInfo / GameInfo / ChannelInfo / GuildInfo / State
├── world.py      # WorldState — 전역 상태, 채널, 브로드캐스트
├── db.py         # AccountDB — SQLite, 계정/전적/길드/채널/감사 로그
├── metrics.py    # Prometheus metrics
└── admin.py      # AdminServer — 로컬 관리 제어 소켓
```

## 주요 기능

- 이중 TCP 소켓: 로비 + 채팅을 한 포트(6112)에서 처리
- 계정: 회원가입·로그인·비밀번호 변경
- 채널: DB 영속 채널, 채널 전환
- 길드: 생성/해산/초대/탈퇴, `/guild`(`/길드`) 채팅 명령
- 채팅: 채널 채팅, 귓속말(`/whisper`), 무시(`/ignore`)
- 게임: 방 생성/참가, 전적 저장(승/패/무)
- 운영: Prometheus metrics, IP 단위 불량 패킷 차단, 로컬 관리 제어 소켓(토큰 인증)

## Disclaimer

이 프로젝트는 원본 게임의 로비 서버 프로토콜을 독립적으로 재구현한 비공식 서버
에뮬레이터다. 상호운용(interoperability)·보존·학습 목적으로 제공된다.

- 원 게임의 개발사·배급사와 무관하며, 어떤 형태로도 제휴·후원·승인을 받지 않았다.
- 원 게임의 클라이언트 바이너리, 소스 코드, 그래픽·사운드 등 저작물을 일절 포함하지 않는다. 이 저장소는 순수 Python으로 작성한 네트워크 프로토콜 구현만 담는다.
- 모든 상표 및 게임 콘텐츠의 권리는 각 권리자에게 있다.
- 사용에 따른 관련 법률 및 이용약관 준수 책임은 이용자에게 있다.

## License

MIT License — [LICENSE](LICENSE) 참조.
