"""
FastAPI backend for authenticated, room-based encrypted chat.

Security model:
- The backend stores and routes opaque encrypted payloads.
- It does NOT decrypt message ciphertext.
"""

from __future__ import annotations

import base64
import io
import hashlib
import hmac
import json
import logging
import os
import secrets
import ssl
import sqlite3
import time
import uuid
from ftplib import FTP_TLS, error_perm
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import Depends, FastAPI, File, Form, HTTPException, Query, UploadFile, WebSocket, WebSocketDisconnect, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field


logger = logging.getLogger("chat-portal")
logging.basicConfig(level=logging.INFO)

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(APP_DIR, "chat_portal.db")
TOKEN_SECRET = os.getenv("CHAT_TOKEN_SECRET", "replace-this-in-production")
TOKEN_TTL_SECONDS = 7 * 24 * 60 * 60
ONLINE_WINDOW_SECONDS = int(os.getenv("ONLINE_WINDOW_SECONDS", "90"))
FTPS_USERNAME = os.getenv("FTPS_USERNAME", "ftpuser")
FTPS_PASSWORD = os.getenv("FTPS_PASSWORD", "ftppass")
FTPS_HOST = os.getenv("FTPS_HOST", "127.0.0.1")
FTPS_CHUNK_SIZE_BYTES = 1 * 1024 * 1024
FTPS_CONNECT_TIMEOUT_SECONDS = int(os.getenv("FTPS_CONNECT_TIMEOUT_SECONDS", "20"))
FTPS_SERVERS = [
    {"host": FTPS_HOST, "port": 2121},
    {"host": FTPS_HOST, "port": 2122},
    {"host": FTPS_HOST, "port": 2123},
]
DEFAULT_CORS_ORIGINS = ["http://localhost:5173", "http://127.0.0.1:5173"]
ENV_CORS_ORIGINS = [value.strip() for value in os.getenv("CORS_ALLOW_ORIGINS", "").split(",") if value.strip()]
CORS_ALLOW_ORIGIN_REGEX = os.getenv(
    "CORS_ALLOW_ORIGIN_REGEX",
    r"^https?://(localhost|127\.0\.0\.1|10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2\d|3[0-1])(?:\.\d{1,3}){2})(:\d+)?$",
)

app = FastAPI(title="CS3001 Chat Portal Backend", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ENV_CORS_ORIGINS or DEFAULT_CORS_ORIGINS,
    allow_origin_regex=CORS_ALLOW_ORIGIN_REGEX,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

bearer_scheme = HTTPBearer(auto_error=False)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def online_cutoff_iso() -> str:
    return (datetime.now(timezone.utc) - timedelta(seconds=ONLINE_WINDOW_SECONDS)).isoformat()


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db() -> None:
    with get_conn() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                display_name TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                public_key TEXT,
                last_seen_at TEXT,
                is_online INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS rooms (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                owner_id INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS room_members (
                room_id TEXT NOT NULL,
                user_id INTEGER NOT NULL,
                joined_at TEXT NOT NULL,
                PRIMARY KEY (room_id, user_id),
                FOREIGN KEY (room_id) REFERENCES rooms(id) ON DELETE CASCADE,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                room_id TEXT NOT NULL,
                sender_id INTEGER NOT NULL,
                payload TEXT NOT NULL,
                is_deleted INTEGER NOT NULL DEFAULT 0,
                deleted_at TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (room_id) REFERENCES rooms(id) ON DELETE CASCADE,
                FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message_id INTEGER,
                room_id TEXT NOT NULL,
                uploader_id INTEGER NOT NULL,
                filename TEXT NOT NULL,
                mime_type TEXT,
                byte_size INTEGER NOT NULL DEFAULT 0,
                total_chunks INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (message_id) REFERENCES messages(id) ON DELETE SET NULL,
                FOREIGN KEY (room_id) REFERENCES rooms(id) ON DELETE CASCADE,
                FOREIGN KEY (uploader_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS file_chunks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_id INTEGER NOT NULL,
                chunk_index INTEGER NOT NULL,
                ftp_server_ip TEXT NOT NULL,
                ftp_server_port INTEGER NOT NULL,
                remote_path TEXT NOT NULL,
                FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE,
                UNIQUE(file_id, chunk_index)
            );

            CREATE INDEX IF NOT EXISTS idx_messages_room_id ON messages(room_id, id);
            CREATE INDEX IF NOT EXISTS idx_files_room_id ON files(room_id, id);
            CREATE INDEX IF NOT EXISTS idx_file_chunks_file_id ON file_chunks(file_id, chunk_index);
            """
        )
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(users)").fetchall()}
        if "last_seen_at" not in columns:
            conn.execute("ALTER TABLE users ADD COLUMN last_seen_at TEXT")
        if "is_online" not in columns:
            conn.execute("ALTER TABLE users ADD COLUMN is_online INTEGER NOT NULL DEFAULT 0")
        message_columns = {row["name"] for row in conn.execute("PRAGMA table_info(messages)").fetchall()}
        if "is_deleted" not in message_columns:
            conn.execute("ALTER TABLE messages ADD COLUMN is_deleted INTEGER NOT NULL DEFAULT 0")
        if "deleted_at" not in message_columns:
            conn.execute("ALTER TABLE messages ADD COLUMN deleted_at TEXT")
        file_columns = {row["name"] for row in conn.execute("PRAGMA table_info(files)").fetchall()}
        if file_columns and "room_id" not in file_columns:
            conn.execute("ALTER TABLE files ADD COLUMN room_id TEXT")
        if file_columns and "uploader_id" not in file_columns:
            conn.execute("ALTER TABLE files ADD COLUMN uploader_id INTEGER")
        if file_columns and "mime_type" not in file_columns:
            conn.execute("ALTER TABLE files ADD COLUMN mime_type TEXT")
        if file_columns and "byte_size" not in file_columns:
            conn.execute("ALTER TABLE files ADD COLUMN byte_size INTEGER NOT NULL DEFAULT 0")
        if file_columns and "created_at" not in file_columns:
            conn.execute("ALTER TABLE files ADD COLUMN created_at TEXT")


def set_user_presence(user_id: int, *, online: bool) -> None:
    with get_conn() as conn:
        if online:
            conn.execute(
                "UPDATE users SET is_online = 1, last_seen_at = ? WHERE id = ?",
                (now_iso(), user_id),
            )
            return
        conn.execute("UPDATE users SET is_online = 0 WHERE id = ?", (user_id,))


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def b64url_decode(data: str) -> bytes:
    padding = "=" * ((4 - len(data) % 4) % 4)
    return base64.urlsafe_b64decode(data + padding)


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 210_000)
    return f"{salt}${digest.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        salt_hex, digest_hex = stored_hash.split("$", 1)
        candidate = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), 210_000)
    except ValueError:
        return False
    return hmac.compare_digest(candidate.hex(), digest_hex)


def create_access_token(user_id: int, username: str) -> str:
    payload = {
        "uid": user_id,
        "username": username,
        "exp": int(time.time()) + TOKEN_TTL_SECONDS,
    }
    payload_json = json.dumps(payload, separators=(",", ":")).encode()
    payload_b64 = b64url_encode(payload_json)
    signature = hmac.new(TOKEN_SECRET.encode(), payload_b64.encode(), hashlib.sha256).digest()
    return f"{payload_b64}.{b64url_encode(signature)}"


def decode_access_token(token: str) -> dict[str, Any]:
    try:
        payload_b64, signature_b64 = token.split(".", 1)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token format") from exc

    expected_signature = hmac.new(TOKEN_SECRET.encode(), payload_b64.encode(), hashlib.sha256).digest()
    try:
        actual_signature = b64url_decode(signature_b64)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token signature") from exc
    if not hmac.compare_digest(expected_signature, actual_signature):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token signature")

    try:
        payload = json.loads(b64url_decode(payload_b64))
    except (json.JSONDecodeError, ValueError) as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload") from exc

    if int(payload.get("exp", 0)) < int(time.time()):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")

    return payload


def serialize_user(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "username": row["username"],
        "display_name": row["display_name"],
        "created_at": row["created_at"],
    }


def get_room_or_404(conn: sqlite3.Connection, room_id: str) -> sqlite3.Row:
    row = conn.execute("SELECT * FROM rooms WHERE id = ?", (room_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Room not found")
    return row


def ensure_room_member(conn: sqlite3.Connection, room_id: str, user_id: int) -> None:
    row = conn.execute(
        "SELECT 1 FROM room_members WHERE room_id = ? AND user_id = ?",
        (room_id, user_id),
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User is not a room member")


def parse_json_text(value: str) -> dict[str, Any] | None:
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return None
    if not isinstance(parsed, dict):
        return None
    return parsed


def split_into_chunks(blob: bytes, *, chunk_size: int) -> list[bytes]:
    if chunk_size <= 0:
        raise ValueError("chunk_size must be > 0")
    if len(blob) == 0:
        return [b""]
    return [blob[i : i + chunk_size] for i in range(0, len(blob), chunk_size)]


def make_ftps_client(host: str, port: int) -> FTP_TLS:
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE

    ftps = FTP_TLS(context=ssl_context, timeout=FTPS_CONNECT_TIMEOUT_SECONDS)
    ftps.connect(host=host, port=port, timeout=FTPS_CONNECT_TIMEOUT_SECONDS)
    ftps.login(user=FTPS_USERNAME, passwd=FTPS_PASSWORD)
    ftps.prot_p()
    ftps.set_pasv(True)
    return ftps


def ensure_ftps_directory(ftps: FTP_TLS, directory_path: str) -> None:
    cleaned = directory_path.strip("/")
    if not cleaned:
        return

    current = ""
    for part in cleaned.split("/"):
        current = f"{current}/{part}" if current else part
        try:
            ftps.mkd(current)
        except error_perm as exc:
            if not str(exc).startswith("550"):
                raise


def ftps_upload_chunk(*, host: str, port: int, remote_path: str, chunk_data: bytes) -> None:
    ftps = make_ftps_client(host, port)
    try:
        parent_dir = remote_path.rsplit("/", 1)[0] if "/" in remote_path else ""
        ensure_ftps_directory(ftps, parent_dir)
        ftps.storbinary(f"STOR {remote_path}", io.BytesIO(chunk_data))
    finally:
        try:
            ftps.quit()
        except Exception:
            ftps.close()


def ftps_download_chunk(*, host: str, port: int, remote_path: str) -> bytes:
    ftps = make_ftps_client(host, port)
    buffer = io.BytesIO()
    try:
        ftps.retrbinary(f"RETR {remote_path}", buffer.write)
        return buffer.getvalue()
    finally:
        try:
            ftps.quit()
        except Exception:
            ftps.close()


def ftps_delete_chunk(*, host: str, port: int, remote_path: str) -> None:
    ftps = make_ftps_client(host, port)
    try:
        ftps.delete(remote_path)
    finally:
        try:
            ftps.quit()
        except Exception:
            ftps.close()


def content_disposition_filename(filename: str) -> str:
    safe = filename.replace("\\", "_").replace('"', "_").strip()
    return safe or "encrypted-file.bin"


async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
) -> dict[str, Any]:
    if credentials is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing authorization token")

    token_payload = decode_access_token(credentials.credentials)
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (token_payload["uid"],)).fetchone()
    if row is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User no longer exists")
    return serialize_user(row)


class RegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=40)
    password: str = Field(min_length=8, max_length=128)
    display_name: str | None = Field(default=None, min_length=1, max_length=60)


class LoginRequest(BaseModel):
    username: str = Field(min_length=3, max_length=40)
    password: str = Field(min_length=8, max_length=128)


class PublicKeyRequest(BaseModel):
    public_key: str = Field(min_length=50)


class RoomCreateRequest(BaseModel):
    name: str = Field(min_length=2, max_length=80)


class RoomMemberMutationRequest(BaseModel):
    user_id: int = Field(gt=0)


class OwnerLeaveRequest(BaseModel):
    new_owner_id: int = Field(gt=0)


class ConnectionManager:
    """
    Tracks active websocket clients per room and relays encrypted payloads.
    """

    def __init__(self) -> None:
        self.active_connections: dict[str, dict[int, WebSocket]] = {}

    async def connect(self, room_id: str, user_id: int, websocket: WebSocket) -> None:
        await websocket.accept()
        room_connections = self.active_connections.setdefault(room_id, {})

        existing = room_connections.get(user_id)
        if existing is not None and existing is not websocket:
            await existing.close(code=4001, reason="Replaced by a new socket")

        room_connections[user_id] = websocket

    def disconnect(self, room_id: str, user_id: int) -> None:
        room_connections = self.active_connections.get(room_id)
        if room_connections is None:
            return
        room_connections.pop(user_id, None)
        if not room_connections:
            self.active_connections.pop(room_id, None)

    async def close_user_socket(self, room_id: str, user_id: int, *, code: int, reason: str) -> None:
        room_connections = self.active_connections.get(room_id)
        if room_connections is None:
            return
        socket = room_connections.get(user_id)
        if socket is None:
            return
        try:
            await socket.close(code=code, reason=reason)
        except Exception:
            pass
        self.disconnect(room_id, user_id)
        await self.broadcast_online_count(room_id)

    async def broadcast_room(self, room_id: str, message: str, skip_user_id: int | None = None) -> None:
        room_connections = self.active_connections.get(room_id)
        if room_connections is None:
            return

        stale_user_ids: list[int] = []
        for uid, socket in list(room_connections.items()):
            if skip_user_id is not None and uid == skip_user_id:
                continue
            try:
                await socket.send_text(message)
            except Exception as exc:
                logger.warning("Dropping stale socket uid=%s room=%s err=%s", uid, room_id, exc)
                stale_user_ids.append(uid)

        for uid in stale_user_ids:
            self.disconnect(room_id, uid)

    async def broadcast_online_count(self, room_id: str) -> None:
        total_online = self.room_online_count(room_id)
        payload = json.dumps(
            {
                "type": "online_count",
                "roomId": room_id,
                "onlineCount": total_online,
                "peerOnlineCount": max(total_online - 1, 0),
                "sentAt": now_iso(),
            }
        )
        await self.broadcast_room(room_id, payload)

    async def close_room(self, room_id: str, code: int, reason: str) -> None:
        room_connections = self.active_connections.pop(room_id, {})
        for socket in room_connections.values():
            await socket.close(code=code, reason=reason)

    def room_client_count(self, room_id: str) -> int:
        return len(self.active_connections.get(room_id, {}))

    def room_online_count(self, room_id: str) -> int:
        with get_conn() as conn:
            return int(
                conn.execute(
                    """
                    SELECT COUNT(*) AS n
                    FROM room_members rm
                    JOIN users u ON u.id = rm.user_id
                    WHERE rm.room_id = ?
                      AND u.is_online = 1
                      AND u.last_seen_at IS NOT NULL
                      AND u.last_seen_at >= ?
                    """,
                    (room_id, online_cutoff_iso()),
                ).fetchone()["n"]
            )

    def total_client_count(self) -> int:
        return sum(len(room) for room in self.active_connections.values())

    async def broadcast_presence_for_user(self, user_id: int) -> None:
        active_room_ids = list(self.active_connections.keys())
        if not active_room_ids:
            return
        with get_conn() as conn:
            for room_id in active_room_ids:
                is_member = conn.execute(
                    "SELECT 1 FROM room_members WHERE room_id = ? AND user_id = ?",
                    (room_id, user_id),
                ).fetchone()
                if is_member is not None:
                    await self.broadcast_online_count(room_id)


manager = ConnectionManager()
init_db()


@app.get("/health")
async def health() -> dict[str, Any]:
    with get_conn() as conn:
        users = conn.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"]
        rooms = conn.execute("SELECT COUNT(*) AS n FROM rooms").fetchone()["n"]
        messages = conn.execute("SELECT COUNT(*) AS n FROM messages").fetchone()["n"]

    return {
        "status": "ok",
        "users": users,
        "rooms": rooms,
        "messages": messages,
        "connected_sockets": manager.total_client_count(),
    }


@app.post("/auth/register")
async def register(payload: RegisterRequest) -> dict[str, Any]:
    username = payload.username.strip().lower()
    display_name = payload.display_name.strip() if payload.display_name else username
    created_at = now_iso()

    with get_conn() as conn:
        existing = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        if existing is not None:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Username already exists")

        password_hash = hash_password(payload.password)
        cursor = conn.execute(
            """
            INSERT INTO users (username, display_name, password_hash, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (username, display_name, password_hash, created_at),
        )
        user_id = int(cursor.lastrowid)
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()

    set_user_presence(user_id, online=True)
    await manager.broadcast_presence_for_user(user_id)
    token = create_access_token(user_id=user_id, username=username)
    return {"token": token, "user": serialize_user(row)}


@app.post("/auth/login")
async def login(payload: LoginRequest) -> dict[str, Any]:
    username = payload.username.strip().lower()
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

    if row is None or not verify_password(payload.password, row["password_hash"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password")

    set_user_presence(int(row["id"]), online=True)
    await manager.broadcast_presence_for_user(int(row["id"]))
    token = create_access_token(user_id=row["id"], username=row["username"])
    return {"token": token, "user": serialize_user(row)}


@app.get("/auth/me")
async def me(current_user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    set_user_presence(int(current_user["id"]), online=True)
    await manager.broadcast_presence_for_user(int(current_user["id"]))
    return {"user": current_user}


@app.post("/auth/ping")
async def ping(current_user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    set_user_presence(int(current_user["id"]), online=True)
    await manager.broadcast_presence_for_user(int(current_user["id"]))
    return {"ok": True}


@app.post("/auth/logout")
async def logout(current_user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    set_user_presence(int(current_user["id"]), online=False)
    await manager.broadcast_presence_for_user(int(current_user["id"]))
    return {"ok": True}


@app.put("/auth/public-key")
async def update_public_key(
    payload: PublicKeyRequest,
    current_user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    with get_conn() as conn:
        conn.execute(
            "UPDATE users SET public_key = ? WHERE id = ?",
            (payload.public_key, current_user["id"]),
        )
    return {"message": "Public key updated"}


@app.get("/rooms")
async def list_rooms(current_user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    cutoff = online_cutoff_iso()
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT
                r.id,
                r.name,
                r.owner_id,
                r.created_at,
                owner.username AS owner_username,
                owner.display_name AS owner_display_name,
                (SELECT COUNT(*) FROM room_members rm2 WHERE rm2.room_id = r.id) AS member_count,
                (
                    SELECT COUNT(*)
                    FROM room_members rm3
                    JOIN users u3 ON u3.id = rm3.user_id
                    WHERE rm3.room_id = r.id
                      AND u3.is_online = 1
                      AND u3.last_seen_at IS NOT NULL
                      AND u3.last_seen_at >= ?
                ) AS online_member_count
            FROM room_members rm
            JOIN rooms r ON r.id = rm.room_id
            JOIN users owner ON owner.id = r.owner_id
            WHERE rm.user_id = ?
            ORDER BY r.created_at DESC
            """,
            (cutoff, current_user["id"]),
        ).fetchall()

    rooms = [
        {
            "id": row["id"],
            "name": row["name"],
            "owner_id": row["owner_id"],
            "owner_username": row["owner_username"],
            "owner_display_name": row["owner_display_name"],
            "member_count": row["member_count"],
            "online_member_count": row["online_member_count"],
            "is_owner": row["owner_id"] == current_user["id"],
            "created_at": row["created_at"],
        }
        for row in rows
    ]
    return {"rooms": rooms}


@app.post("/rooms")
async def create_room(
    payload: RoomCreateRequest,
    current_user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    room_id = uuid.uuid4().hex[:10]
    created_at = now_iso()

    with get_conn() as conn:
        conn.execute(
            "INSERT INTO rooms (id, name, owner_id, created_at) VALUES (?, ?, ?, ?)",
            (room_id, payload.name.strip(), current_user["id"], created_at),
        )
        conn.execute(
            "INSERT INTO room_members (room_id, user_id, joined_at) VALUES (?, ?, ?)",
            (room_id, current_user["id"], created_at),
        )

    return {
        "room": {
            "id": room_id,
            "name": payload.name.strip(),
            "owner_id": current_user["id"],
            "owner_username": current_user["username"],
            "owner_display_name": current_user["display_name"],
            "member_count": 1,
            "online_member_count": 1,
            "is_owner": True,
            "created_at": created_at,
        }
    }


@app.post("/rooms/{room_id}/join")
async def join_room(room_id: str, current_user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    joined_now = False
    cutoff = online_cutoff_iso()
    with get_conn() as conn:
        room = get_room_or_404(conn, room_id)
        cursor = conn.execute(
            """
            INSERT OR IGNORE INTO room_members (room_id, user_id, joined_at)
            VALUES (?, ?, ?)
            """,
            (room_id, current_user["id"], now_iso()),
        )
        joined_now = cursor.rowcount > 0

        row = conn.execute(
            """
            SELECT
                r.id,
                r.name,
                r.owner_id,
                r.created_at,
                owner.username AS owner_username,
                owner.display_name AS owner_display_name,
                (SELECT COUNT(*) FROM room_members rm2 WHERE rm2.room_id = r.id) AS member_count,
                (
                    SELECT COUNT(*)
                    FROM room_members rm3
                    JOIN users u3 ON u3.id = rm3.user_id
                    WHERE rm3.room_id = r.id
                      AND u3.is_online = 1
                      AND u3.last_seen_at IS NOT NULL
                      AND u3.last_seen_at >= ?
                ) AS online_member_count
            FROM rooms r
            JOIN users owner ON owner.id = r.owner_id
            WHERE r.id = ?
            """,
            (cutoff, room["id"]),
        ).fetchone()

    if joined_now:
        await manager.broadcast_room(
            room_id,
            json.dumps(
                {
                    "type": "member_joined",
                    "roomId": room_id,
                    "senderId": current_user["id"],
                    "sender": current_user["display_name"],
                    "senderUsername": current_user["username"],
                    "sentAt": now_iso(),
                }
            ),
            skip_user_id=current_user["id"],
        )
        await manager.broadcast_online_count(room_id)

    return {
        "room": {
            "id": row["id"],
            "name": row["name"],
            "owner_id": row["owner_id"],
            "owner_username": row["owner_username"],
            "owner_display_name": row["owner_display_name"],
            "member_count": row["member_count"],
            "online_member_count": row["online_member_count"],
            "is_owner": row["owner_id"] == current_user["id"],
            "created_at": row["created_at"],
        }
    }


@app.delete("/rooms/{room_id}")
async def delete_room(room_id: str, current_user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    with get_conn() as conn:
        room = get_room_or_404(conn, room_id)
        if room["owner_id"] != current_user["id"]:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only owner can delete this room")

    await manager.broadcast_room(
        room_id,
        json.dumps(
            {
                "type": "room_deleted",
                "roomId": room_id,
                "deletedBy": current_user["display_name"],
                "sentAt": now_iso(),
            }
        ),
    )
    await manager.close_room(room_id, code=4004, reason="Room deleted by owner")

    with get_conn() as conn:
        conn.execute("DELETE FROM rooms WHERE id = ?", (room_id,))

    return {"message": "Room deleted"}


@app.post("/rooms/{room_id}/leave")
async def leave_room(room_id: str, current_user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    with get_conn() as conn:
        room = get_room_or_404(conn, room_id)
        if room["owner_id"] == current_user["id"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Owner must transfer ownership first, then leave.",
            )

        membership = conn.execute(
            "SELECT 1 FROM room_members WHERE room_id = ? AND user_id = ?",
            (room_id, current_user["id"]),
        ).fetchone()
        if membership is None:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User is not a room member")

        conn.execute(
            "DELETE FROM room_members WHERE room_id = ? AND user_id = ?",
            (room_id, current_user["id"]),
        )

    await manager.close_user_socket(
        room_id,
        current_user["id"],
        code=4002,
        reason="Left room membership",
    )

    await manager.broadcast_room(
        room_id,
        json.dumps(
            {
                "type": "member_left",
                "roomId": room_id,
                "senderId": current_user["id"],
                "sender": current_user["display_name"],
                "senderUsername": current_user["username"],
                "sentAt": now_iso(),
            }
        ),
    )
    await manager.broadcast_online_count(room_id)
    return {"message": "Left room successfully"}


@app.post("/rooms/{room_id}/remove-member")
async def remove_member_from_room(
    room_id: str,
    payload: RoomMemberMutationRequest,
    current_user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    if payload.user_id == current_user["id"]:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Owner cannot remove themselves")

    with get_conn() as conn:
        room = get_room_or_404(conn, room_id)
        if room["owner_id"] != current_user["id"]:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only owner can remove members")

        member = conn.execute(
            "SELECT id, username, display_name FROM users WHERE id = ?",
            (payload.user_id,),
        ).fetchone()
        if member is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Member not found")
        if int(member["id"]) == int(room["owner_id"]):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot remove room owner")

        membership = conn.execute(
            "SELECT 1 FROM room_members WHERE room_id = ? AND user_id = ?",
            (room_id, payload.user_id),
        ).fetchone()
        if membership is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User is not a room member")

        conn.execute(
            "DELETE FROM room_members WHERE room_id = ? AND user_id = ?",
            (room_id, payload.user_id),
        )

    await manager.close_user_socket(
        room_id,
        payload.user_id,
        code=4003,
        reason="Removed by room owner",
    )
    await manager.broadcast_room(
        room_id,
        json.dumps(
            {
                "type": "member_left",
                "roomId": room_id,
                "senderId": int(member["id"]),
                "sender": member["display_name"],
                "senderUsername": member["username"],
                "removedById": current_user["id"],
                "removedBy": current_user["display_name"],
                "sentAt": now_iso(),
            }
        ),
    )
    await manager.broadcast_online_count(room_id)
    return {"message": "Member removed"}


@app.post("/rooms/{room_id}/owner-leave")
async def owner_transfer_and_leave(
    room_id: str,
    payload: OwnerLeaveRequest,
    current_user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    with get_conn() as conn:
        room = get_room_or_404(conn, room_id)
        if room["owner_id"] != current_user["id"]:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only owner can perform this action")
        if payload.new_owner_id == current_user["id"]:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Select a different member as owner")

        other_member_exists = conn.execute(
            "SELECT 1 FROM room_members WHERE room_id = ? AND user_id != ? LIMIT 1",
            (room_id, current_user["id"]),
        ).fetchone()
        if other_member_exists is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Owner cannot leave because no other member exists in this room.",
            )

        candidate = conn.execute(
            """
            SELECT u.id, u.username, u.display_name
            FROM room_members rm
            JOIN users u ON u.id = rm.user_id
            WHERE rm.room_id = ? AND rm.user_id = ?
            """,
            (room_id, payload.new_owner_id),
        ).fetchone()
        if candidate is None:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Selected user is not in this room")

        conn.execute(
            "UPDATE rooms SET owner_id = ? WHERE id = ?",
            (payload.new_owner_id, room_id),
        )
        conn.execute(
            "DELETE FROM room_members WHERE room_id = ? AND user_id = ?",
            (room_id, current_user["id"]),
        )

    await manager.close_user_socket(
        room_id,
        current_user["id"],
        code=4002,
        reason="Ownership transferred and room left",
    )
    await manager.broadcast_room(
        room_id,
        json.dumps(
            {
                "type": "owner_transferred",
                "roomId": room_id,
                "previousOwnerId": current_user["id"],
                "previousOwner": current_user["display_name"],
                "newOwnerId": int(candidate["id"]),
                "newOwner": candidate["display_name"],
                "newOwnerUsername": candidate["username"],
                "sentAt": now_iso(),
            }
        ),
    )
    await manager.broadcast_room(
        room_id,
        json.dumps(
            {
                "type": "member_left",
                "roomId": room_id,
                "senderId": current_user["id"],
                "sender": current_user["display_name"],
                "senderUsername": current_user["username"],
                "sentAt": now_iso(),
            }
        ),
    )
    await manager.broadcast_online_count(room_id)
    return {"message": "Ownership transferred and owner left the room"}


@app.get("/rooms/{room_id}/members")
async def list_room_members(room_id: str, current_user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    cutoff = online_cutoff_iso()
    with get_conn() as conn:
        get_room_or_404(conn, room_id)
        ensure_room_member(conn, room_id, current_user["id"])
        rows = conn.execute(
            """
            SELECT
                u.id,
                u.username,
                u.display_name,
                u.public_key,
                u.is_online,
                u.last_seen_at,
                rm.joined_at
            FROM room_members rm
            JOIN users u ON u.id = rm.user_id
            WHERE rm.room_id = ?
            ORDER BY rm.joined_at ASC
            """,
            (room_id,),
        ).fetchall()

    members = [
        {
            "id": row["id"],
            "username": row["username"],
            "display_name": row["display_name"],
            "public_key": row["public_key"],
            "is_online": bool(row["is_online"]) and bool(row["last_seen_at"]) and row["last_seen_at"] >= cutoff,
            "joined_at": row["joined_at"],
        }
        for row in rows
    ]
    return {"members": members}


@app.get("/rooms/{room_id}/messages")
async def list_room_messages(
    room_id: str,
    limit: int = Query(default=200, ge=1, le=500),
    current_user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    with get_conn() as conn:
        get_room_or_404(conn, room_id)
        membership = conn.execute(
            "SELECT joined_at FROM room_members WHERE room_id = ? AND user_id = ?",
            (room_id, current_user["id"]),
        ).fetchone()
        if membership is None:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User is not a room member")
        user_joined_at = membership["joined_at"]
        rows = conn.execute(
            """
            SELECT * FROM (
                SELECT
                    m.id,
                    m.payload,
                    m.is_deleted,
                    m.deleted_at,
                    m.created_at,
                    u.id AS sender_id,
                    u.username AS sender_username,
                    u.display_name AS sender_display_name
                FROM messages m
                JOIN users u ON u.id = m.sender_id
                WHERE m.room_id = ? AND m.created_at >= ?
                ORDER BY m.id DESC
                LIMIT ?
            ) recent
            ORDER BY recent.id ASC
            """,
            (room_id, user_joined_at, limit),
        ).fetchall()

    messages = []
    for row in rows:
        if int(row["is_deleted"]):
            payload = {
                "type": "message_deleted",
                "roomId": room_id,
                "messageId": row["id"],
                "senderId": row["sender_id"],
                "sender": row["sender_display_name"],
                "senderUsername": row["sender_username"],
                "sentAt": row["deleted_at"] or row["created_at"],
            }
        else:
            payload = parse_json_text(row["payload"])
            if isinstance(payload, dict) and payload.get("type") == "chat" and payload.get("messageId") is None:
                payload["messageId"] = row["id"]
        messages.append(
            {
                "id": row["id"],
                "created_at": row["created_at"],
                "sender": {
                    "id": row["sender_id"],
                    "username": row["sender_username"],
                    "display_name": row["sender_display_name"],
                },
                "packet": payload,
                "raw_payload": row["payload"] if payload is None else None,
            }
        )

    return {"messages": messages}


@app.post("/rooms/{room_id}/messages/{message_id}/delete")
async def delete_own_message(
    room_id: str,
    message_id: int,
    current_user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    deleted_at = now_iso()
    with get_conn() as conn:
        get_room_or_404(conn, room_id)
        ensure_room_member(conn, room_id, current_user["id"])
        row = conn.execute(
            """
            SELECT m.id, m.sender_id, m.is_deleted, u.username AS sender_username, u.display_name AS sender_name
            FROM messages m
            JOIN users u ON u.id = m.sender_id
            WHERE m.id = ? AND m.room_id = ?
            """,
            (message_id, room_id),
        ).fetchone()
        if row is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Message not found")
        if int(row["sender_id"]) != int(current_user["id"]):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You can only delete your own messages")
        if int(row["is_deleted"]):
            return {"message": "Message already deleted"}

        conn.execute(
            "UPDATE messages SET is_deleted = 1, deleted_at = ? WHERE id = ?",
            (deleted_at, message_id),
        )

    await manager.broadcast_room(
        room_id,
        json.dumps(
            {
                "type": "message_deleted",
                "roomId": room_id,
                "messageId": message_id,
                "senderId": current_user["id"],
                "sender": row["sender_name"],
                "senderUsername": row["sender_username"],
                "sentAt": deleted_at,
            }
        ),
    )
    return {"message": "Message deleted"}


@app.post("/ftp/upload")
async def ftp_upload(
    room_id: str = Form(..., min_length=4, max_length=64),
    message_id: int | None = Form(default=None, gt=0),
    file: UploadFile = File(...),
    current_user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    with get_conn() as conn:
        get_room_or_404(conn, room_id)
        ensure_room_member(conn, room_id, current_user["id"])
        if message_id is not None:
            msg = conn.execute(
                "SELECT id FROM messages WHERE id = ? AND room_id = ?",
                (message_id, room_id),
            ).fetchone()
            if msg is None:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid message_id for this room")

    encrypted_payload = await file.read()
    if encrypted_payload is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing upload file")

    chunks = split_into_chunks(encrypted_payload, chunk_size=FTPS_CHUNK_SIZE_BYTES)
    file_name = file.filename or "encrypted-file.bin"
    mime_type = file.content_type or "application/octet-stream"
    created_at = now_iso()

    uploaded_chunks: list[tuple[str, int, str]] = []
    file_id: int | None = None
    try:
        with get_conn() as conn:
            cursor = conn.execute(
                """
                INSERT INTO files (message_id, room_id, uploader_id, filename, mime_type, byte_size, total_chunks, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    message_id,
                    room_id,
                    current_user["id"],
                    file_name,
                    mime_type,
                    len(encrypted_payload),
                    len(chunks),
                    created_at,
                ),
            )
            file_id = int(cursor.lastrowid)

        for chunk_index, chunk in enumerate(chunks):
            server = FTPS_SERVERS[chunk_index % len(FTPS_SERVERS)]
            remote_path = f"room_{room_id}/file_{file_id}/chunk_{chunk_index:06d}.bin"
            ftps_upload_chunk(
                host=server["host"],
                port=server["port"],
                remote_path=remote_path,
                chunk_data=chunk,
            )
            uploaded_chunks.append((server["host"], int(server["port"]), remote_path))

        with get_conn() as conn:
            conn.executemany(
                """
                INSERT INTO file_chunks (file_id, chunk_index, ftp_server_ip, ftp_server_port, remote_path)
                VALUES (?, ?, ?, ?, ?)
                """,
                [
                    (
                        file_id,
                        chunk_index,
                        FTPS_SERVERS[chunk_index % len(FTPS_SERVERS)]["host"],
                        FTPS_SERVERS[chunk_index % len(FTPS_SERVERS)]["port"],
                        f"room_{room_id}/file_{file_id}/chunk_{chunk_index:06d}.bin",
                    )
                    for chunk_index in range(len(chunks))
                ],
            )
    except Exception as exc:
        logger.exception("FTPS upload failed for room=%s user=%s err=%s", room_id, current_user["id"], exc)
        if file_id is not None:
            with get_conn() as conn:
                conn.execute("DELETE FROM files WHERE id = ?", (file_id,))
        for host, port, remote_path in uploaded_chunks:
            try:
                ftps_delete_chunk(host=host, port=port, remote_path=remote_path)
            except Exception:
                logger.warning("Rollback could not delete chunk path=%s on %s:%s", remote_path, host, port)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Encrypted file upload to distributed FTPS storage failed",
        ) from exc

    return {
        "file_id": file_id,
        "room_id": room_id,
        "filename": file_name,
        "mime_type": mime_type,
        "byte_size": len(encrypted_payload),
        "total_chunks": len(chunks),
    }


@app.get("/ftp/download/{file_id}")
async def ftp_download(
    file_id: int,
    current_user: dict[str, Any] = Depends(get_current_user),
) -> StreamingResponse:
    with get_conn() as conn:
        file_row = conn.execute("SELECT * FROM files WHERE id = ?", (file_id,)).fetchone()
        if file_row is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found")
        ensure_room_member(conn, file_row["room_id"], current_user["id"])
        chunk_rows = conn.execute(
            """
            SELECT chunk_index, ftp_server_ip, ftp_server_port, remote_path
            FROM file_chunks
            WHERE file_id = ?
            ORDER BY chunk_index ASC
            """,
            (file_id,),
        ).fetchall()

    if not chunk_rows:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File chunks not found")

    assembled = io.BytesIO()
    try:
        for row in chunk_rows:
            chunk_data = ftps_download_chunk(
                host=row["ftp_server_ip"],
                port=int(row["ftp_server_port"]),
                remote_path=row["remote_path"],
            )
            assembled.write(chunk_data)
    except Exception as exc:
        logger.exception("FTPS download failed for file_id=%s err=%s", file_id, exc)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Unable to download encrypted file from distributed FTPS storage",
        ) from exc

    assembled.seek(0)
    download_name = content_disposition_filename(file_row["filename"])
    return StreamingResponse(
        assembled,
        media_type=file_row["mime_type"] or "application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{download_name}"'},
    )


def normalize_ws_packet(
    packet: dict[str, Any],
    *,
    room_id: str,
    user_id: int,
    sender_name: str,
    sender_username: str,
) -> dict[str, Any] | None:
    packet_type = packet.get("type")
    sent_at = packet.get("sentAt") or now_iso()

    if packet_type == "announce":
        public_key = packet.get("publicKey")
        if not isinstance(public_key, str) or len(public_key) < 50:
            return None
        return {
            "type": "announce",
            "roomId": room_id,
            "senderId": user_id,
            "sender": sender_name,
            "senderUsername": sender_username,
            "publicKey": public_key,
            "sentAt": sent_at,
        }

    if packet_type == "chat":
        encrypted_keys = packet.get("encryptedKeys")
        iv = packet.get("iv")
        ciphertext = packet.get("ciphertext")
        if not isinstance(encrypted_keys, dict) or not isinstance(iv, str) or not isinstance(ciphertext, str):
            return None
        return {
            "type": "chat",
            "roomId": room_id,
            "senderId": user_id,
            "sender": sender_name,
            "senderUsername": sender_username,
            "encryptedKeys": encrypted_keys,
            "iv": iv,
            "ciphertext": ciphertext,
            "sentAt": sent_at,
        }

    if packet_type == "file-intent":
        file_name = packet.get("fileName")
        file_size = packet.get("fileSize")
        content_type = packet.get("contentType")
        if not isinstance(file_name, str) or not isinstance(file_size, int):
            return None
        return {
            "type": "file-intent",
            "roomId": room_id,
            "senderId": user_id,
            "sender": sender_name,
            "senderUsername": sender_username,
            "fileName": file_name,
            "fileSize": file_size,
            "contentType": content_type if isinstance(content_type, str) else None,
            "sentAt": sent_at,
        }

    if packet_type == "file_shared":
        file_id = packet.get("fileId")
        file_name = packet.get("fileName")
        file_size = packet.get("fileSize")
        file_type = packet.get("fileType")
        encrypted_keys = packet.get("encryptedKeys")
        iv = packet.get("iv")
        if (
            not isinstance(file_id, int)
            or file_id <= 0
            or not isinstance(file_name, str)
            or not isinstance(file_size, int)
            or file_size < 0
            or not isinstance(encrypted_keys, dict)
            or not isinstance(iv, str)
        ):
            return None
        return {
            "type": "file_shared",
            "roomId": room_id,
            "senderId": user_id,
            "sender": sender_name,
            "senderUsername": sender_username,
            "fileId": file_id,
            "fileName": file_name,
            "fileSize": file_size,
            "fileType": file_type if isinstance(file_type, str) else "application/octet-stream",
            "encryptedKeys": encrypted_keys,
            "iv": iv,
            "sentAt": sent_at,
        }

    return None


@app.websocket("/ws/{room_id}")
async def websocket_endpoint(websocket: WebSocket, room_id: str, token: str | None = None) -> None:
    if not token:
        await websocket.close(code=4401, reason="Missing token")
        return

    try:
        token_payload = decode_access_token(token)
    except HTTPException:
        await websocket.close(code=4401, reason="Invalid token")
        return

    user_id = int(token_payload["uid"])
    with get_conn() as conn:
        user_row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if user_row is None:
            await websocket.close(code=4401, reason="Unknown user")
            return
        room_row = conn.execute("SELECT * FROM rooms WHERE id = ?", (room_id,)).fetchone()
        if room_row is None:
            await websocket.close(code=4404, reason="Room not found")
            return
        membership = conn.execute(
            "SELECT 1 FROM room_members WHERE room_id = ? AND user_id = ?",
            (room_id, user_id),
        ).fetchone()
        if membership is None:
            await websocket.close(code=4403, reason="You must join room first")
            return

    sender_name = user_row["display_name"]
    sender_username = user_row["username"]
    connected = False
    try:
        set_user_presence(user_id, online=True)
        await manager.broadcast_presence_for_user(user_id)
        await manager.connect(room_id, user_id, websocket)
        connected = True
        await manager.broadcast_online_count(room_id)
        room_online_count = manager.room_online_count(room_id)

        await websocket.send_text(
            json.dumps(
                {
                    "type": "server_ack",
                    "roomId": room_id,
                    "senderId": 0,
                    "sender": "server",
                    "onlineCount": room_online_count,
                    "peerOnlineCount": max(room_online_count - 1, 0),
                    "sentAt": now_iso(),
                }
            )
        )

        while True:
            incoming = await websocket.receive_text()
            packet = parse_json_text(incoming)
            if packet is None:
                continue

            normalized_packet = normalize_ws_packet(
                packet,
                room_id=room_id,
                user_id=user_id,
                sender_name=sender_name,
                sender_username=sender_username,
            )
            if normalized_packet is None:
                continue

            if normalized_packet["type"] == "announce":
                with get_conn() as conn:
                    conn.execute(
                        "UPDATE users SET public_key = ? WHERE id = ?",
                        (normalized_packet["publicKey"], user_id),
                    )

            if normalized_packet["type"] in {"chat", "file_shared"}:
                with get_conn() as conn:
                    serialized_packet_for_storage = json.dumps(normalized_packet, separators=(",", ":"))
                    cursor = conn.execute(
                        """
                        INSERT INTO messages (room_id, sender_id, payload, created_at)
                        VALUES (?, ?, ?, ?)
                        """,
                        (room_id, user_id, serialized_packet_for_storage, normalized_packet["sentAt"]),
                    )
                    normalized_packet["messageId"] = int(cursor.lastrowid)
                    if normalized_packet["type"] == "file_shared":
                        conn.execute(
                            """
                            UPDATE files
                            SET message_id = COALESCE(message_id, ?)
                            WHERE id = ? AND room_id = ?
                            """,
                            (normalized_packet["messageId"], normalized_packet["fileId"], room_id),
                        )

            serialized_packet = json.dumps(normalized_packet, separators=(",", ":"))

            await manager.broadcast_room(room_id, serialized_packet)

    except WebSocketDisconnect:
        logger.info("WebSocket disconnected: user=%s room=%s", user_id, room_id)
    except Exception as exc:
        logger.exception("WebSocket error: user=%s room=%s err=%s", user_id, room_id, exc)
        try:
            await websocket.close(code=1011, reason="Internal websocket error")
        except RuntimeError:
            pass
    finally:
        if connected:
            manager.disconnect(room_id, user_id)
            await manager.broadcast_online_count(room_id)
