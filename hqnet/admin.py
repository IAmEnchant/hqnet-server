"""Local admin control server for monitoring and moderation commands."""

from __future__ import annotations

import asyncio
import json
import logging
import time


log = logging.getLogger('hqnet.admin')
AUDIT_LOG = logging.getLogger('hqnet.security')


class AdminServer:
    def __init__(self, lobby_server, host: str, port: int, token: str):
        self.lobby_server = lobby_server
        self.host = host
        self.port = port
        self.token = token
        self.started_at = time.monotonic()
        self._server: asyncio.AbstractServer | None = None

    async def start(self) -> asyncio.AbstractServer:
        self._server = await asyncio.start_server(self._handle, self.host, self.port)
        log.info('HQNET Admin Server listening on %s:%d', self.host, self.port)
        self._audit('lifecycle', '', 'admin_server_started host=%s port=%d', self.host, self.port)
        return self._server

    def _audit(self, category: str, remote_addr, message: str, *args):
        formatted = message % args if args else message
        AUDIT_LOG.warning('admin category=%s addr=%s %s', category, remote_addr, formatted)
        self.lobby_server.world.db.add_admin_audit_log(
            category=category,
            message=formatted,
            remote_addr=str(remote_addr or ''),
        )

    @staticmethod
    def _summarize_args(args: dict) -> dict:
        summary = dict(args)
        if 'message' in summary:
            message = str(summary['message'])
            summary['message_len'] = len(message)
            del summary['message']
        return summary

    async def _close_writer(self, writer: asyncio.StreamWriter):
        try:
            writer.close()
            await writer.wait_closed()
        except (ConnectionError, OSError):
            pass

    async def _send(self, writer: asyncio.StreamWriter, payload: dict):
        writer.write((json.dumps(payload, ensure_ascii=True) + '\n').encode('utf-8'))
        await writer.drain()

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        addr = writer.get_extra_info('peername')
        log.info('Admin connection from %s', addr)
        self._audit('connect', addr, 'connect')
        try:
            while True:
                line = await reader.readline()
                if not line:
                    break
                try:
                    request = json.loads(line.decode('utf-8'))
                except json.JSONDecodeError:
                    self._audit('invalid_json', addr, 'invalid_json')
                    await self._send(writer, {"ok": False, "error": "invalid_json"})
                    continue
                if request.get('token') != self.token:
                    self._audit('unauthorized', addr, 'unauthorized')
                    await self._send(writer, {"ok": False, "error": "unauthorized"})
                    break
                command = str(request.get('command') or '').strip().lower()
                args = request.get('args') or {}
                try:
                    data = await self._dispatch(command, args)
                    self._audit('command_ok', addr, 'command=%s args=%s',
                                command, self._summarize_args(args))
                    await self._send(writer, {"ok": True, "data": data})
                except Exception as exc:
                    log.exception('Admin command failed: %s', command)
                    self._audit('command_failed', addr, 'command=%s args=%s error=%s',
                                command, self._summarize_args(args), exc)
                    await self._send(writer, {"ok": False, "error": str(exc)})
        finally:
            self._audit('disconnect', addr, 'disconnect')
            await self._close_writer(writer)

    async def _dispatch(self, command: str, args: dict):
        world = self.lobby_server.world
        if command == 'ping':
            return {"pong": True}
        if command == 'stats':
            return {
                "uptime_seconds": round(time.monotonic() - self.lobby_server.started_at, 1),
                "active_connections": self.lobby_server.active_connections,
                "active_lobby_connections": self.lobby_server.active_lobby_connections,
                "active_chat_connections": self.lobby_server.active_chat_connections,
                "world": world.build_runtime_snapshot(),
            }
        if command == 'users':
            return world.list_users_snapshot()
        if command == 'user':
            return world.get_user_snapshot(str(args.get('name') or ''))
        if command == 'games':
            return world.list_games_snapshot()
        if command == 'game':
            return world.get_game_snapshot(str(args.get('name') or ''))
        if command == 'channels':
            return world.list_channels_snapshot()
        if command == 'guilds':
            return world.list_guilds_snapshot()
        if command == 'admin_logs':
            return world.db.list_admin_audit_logs(limit=int(args.get('limit', 100)))
        if command == 'bans':
            return world.db.list_packet_bans(
                limit=int(args.get('limit', 50)),
                active_only=bool(args.get('active_only', False)),
            )
        if command == 'ban_info':
            ip_address = str(args.get('ip_address') or '')
            return {
                "ban": world.db.get_packet_ban(ip_address),
                "events": world.db.get_packet_ban_events(ip_address, limit=int(args.get('limit', 20))),
            }
        if command == 'ban':
            ip_address = str(args.get('ip_address') or '')
            duration_sec = int(args.get('duration_sec', 0))
            reason = str(args.get('reason') or 'admin_manual_ban')
            if not ip_address:
                raise ValueError('missing ip_address')
            if duration_sec == 0:
                raise ValueError('duration_sec must be non-zero')
            result = world.db.set_packet_ban(
                ip_address,
                duration_sec=duration_sec,
                reason=reason,
            )
            self._audit('ban', '', 'ban ip=%s duration=%s reason=%s',
                        ip_address,
                        'permanent' if duration_sec == -1 else duration_sec,
                        reason)
            return result
        if command == 'unban':
            ip_address = str(args.get('ip_address') or '')
            if not ip_address:
                raise ValueError('missing ip_address')
            cleared = world.db.clear_packet_ban(ip_address)
            self._audit('unban', '', 'unban ip=%s cleared=%d', ip_address, int(cleared))
            return {"cleared": cleared}
        if command == 'kick':
            name = str(args.get('name') or '')
            if not name:
                raise ValueError('missing name')
            disconnected = await world.admin_disconnect_user(name, reason='admin_kick')
            self._audit('kick', '', 'kick user=%s disconnected=%d', name, int(disconnected))
            return {"disconnected": disconnected}
        if command == 'kick_ip':
            ip_address = str(args.get('ip_address') or '')
            if not ip_address:
                raise ValueError('missing ip_address')
            names = await world.admin_disconnect_ip(ip_address, reason='admin_kick_ip')
            self._audit('kick_ip', '', 'kick_ip ip=%s disconnected_users=%s', ip_address, names)
            return {"disconnected_users": names}
        if command == 'channel_create':
            name = str(args.get('name') or '')
            sort_order = int(args.get('sort_order', 0))
            if not name:
                raise ValueError('missing name')
            ok = world.admin_create_channel(name, sort_order)
            self._audit('channel_create', '', 'channel_create name=%s sort=%d ok=%d',
                        name, sort_order, int(ok))
            return {"created": ok, "name": name}
        if command == 'channel_delete':
            name = str(args.get('name') or '')
            if not name:
                raise ValueError('missing name')
            ok, moved = world.admin_delete_channel(name)
            self._audit('channel_delete', '', 'channel_delete name=%s ok=%d moved=%s',
                        name, int(ok), moved)
            return {"deleted": ok, "name": name, "moved_users": moved}
        if command == 'channel_rename':
            old_name = str(args.get('old_name') or '')
            new_name = str(args.get('new_name') or '')
            if not old_name or not new_name:
                raise ValueError('missing old_name or new_name')
            ok, affected = world.admin_rename_channel(old_name, new_name)
            self._audit('channel_rename', '', 'channel_rename %s -> %s ok=%d affected=%d',
                        old_name, new_name, int(ok), affected)
            return {"renamed": ok, "old_name": old_name, "new_name": new_name,
                    "affected_users": affected}
        if command == 'notice':
            target = str(args.get('target') or 'all')
            message = str(args.get('message') or '')
            if not message:
                raise ValueError('missing message')
            delivered = await world.admin_notice(target, message)
            self._audit('notice', '', 'notice target=%s delivered=%d message_len=%d',
                        target, delivered, len(message))
            return {"delivered": delivered, "target": target}
        raise ValueError(f'unknown_command:{command}')
