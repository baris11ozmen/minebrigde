import os
import uuid
import sqlite3
import hashlib
import secrets
from datetime import datetime, timedelta
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
from typing import Optional

app = FastAPI(title="MineBridge API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer()
DB_PATH = "minebridge.db"


# ──────────────────────────────────────────────
# VERİTABANI
# ──────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS servers (
            id TEXT PRIMARY KEY,
            owner_id TEXT NOT NULL,
            name TEXT NOT NULL,
            description TEXT,
            tunnel_url TEXT,
            status TEXT DEFAULT 'offline',
            world_backup_url TEXT,
            created_at TEXT NOT NULL,
            last_seen TEXT,
            FOREIGN KEY (owner_id) REFERENCES users(id)
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS invites (
            id TEXT PRIMARY KEY,
            server_id TEXT NOT NULL,
            invite_code TEXT UNIQUE NOT NULL,
            created_by TEXT NOT NULL,
            max_uses INTEGER DEFAULT -1,
            use_count INTEGER DEFAULT 0,
            expires_at TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (server_id) REFERENCES servers(id)
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS server_members (
            server_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            joined_at TEXT NOT NULL,
            PRIMARY KEY (server_id, user_id),
            FOREIGN KEY (server_id) REFERENCES servers(id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    conn.commit()
    conn.close()
    print("[MineBridge] Veritabanı hazır.")


# ──────────────────────────────────────────────
# YARDIMCI FONKSİYONLAR
# ──────────────────────────────────────────────

def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    hashed = hashlib.sha256((salt + password).encode()).hexdigest()
    return f"{salt}:{hashed}"


def verify_password(password: str, stored: str) -> bool:
    try:
        salt, hashed = stored.split(":")
        return hashlib.sha256((salt + password).encode()).hexdigest() == hashed
    except Exception:
        return False


def create_session(user_id: str) -> str:
    token = secrets.token_hex(32)
    expires = (datetime.utcnow() + timedelta(days=7)).isoformat()
    conn = get_db()
    conn.execute(
        "INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)",
        (token, user_id, expires)
    )
    conn.commit()
    conn.close()
    return token


def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    conn = get_db()
    session = conn.execute(
        "SELECT * FROM sessions WHERE token = ?", (token,)
    ).fetchone()
    conn.close()

    if not session:
        raise HTTPException(status_code=401, detail="Geçersiz token")
    if datetime.fromisoformat(session["expires_at"]) < datetime.utcnow():
        raise HTTPException(status_code=401, detail="Token süresi dolmuş")

    conn = get_db()
    user = conn.execute(
        "SELECT * FROM users WHERE id = ?", (session["user_id"],)
    ).fetchone()
    conn.close()

    if not user:
        raise HTTPException(status_code=401, detail="Kullanıcı bulunamadı")
    return dict(user)


# ──────────────────────────────────────────────
# MODELLER
# ──────────────────────────────────────────────

class RegisterRequest(BaseModel):
    username: str
    email: str
    password: str

class LoginRequest(BaseModel):
    username: str
    password: str

class CreateServerRequest(BaseModel):
    name: str
    description: Optional[str] = ""

class UpdateServerRequest(BaseModel):
    tunnel_url: Optional[str] = None
    status: Optional[str] = None
    world_backup_url: Optional[str] = None

class CreateInviteRequest(BaseModel):
    server_id: str
    max_uses: Optional[int] = -1
    expires_hours: Optional[int] = None


# ──────────────────────────────────────────────
# AUTH ENDPOINTLERİ
# ──────────────────────────────────────────────

@app.post("/api/auth/register")
def register(req: RegisterRequest):
    if len(req.username) < 3:
        raise HTTPException(400, "Kullanıcı adı en az 3 karakter olmalı")
    if len(req.password) < 6:
        raise HTTPException(400, "Şifre en az 6 karakter olmalı")

    conn = get_db()
    existing = conn.execute(
        "SELECT id FROM users WHERE username = ? OR email = ?",
        (req.username, req.email)
    ).fetchone()

    if existing:
        conn.close()
        raise HTTPException(400, "Bu kullanıcı adı veya e-posta zaten kullanılıyor")

    user_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO users (id, username, email, password_hash, created_at) VALUES (?, ?, ?, ?, ?)",
        (user_id, req.username, req.email, hash_password(req.password), datetime.utcnow().isoformat())
    )
    conn.commit()
    conn.close()

    token = create_session(user_id)
    return {"token": token, "user_id": user_id, "username": req.username}


@app.post("/api/auth/login")
def login(req: LoginRequest):
    conn = get_db()
    user = conn.execute(
        "SELECT * FROM users WHERE username = ?", (req.username,)
    ).fetchone()
    conn.close()

    if not user or not verify_password(req.password, user["password_hash"]):
        raise HTTPException(401, "Kullanıcı adı veya şifre yanlış")

    token = create_session(user["id"])
    return {"token": token, "user_id": user["id"], "username": user["username"]}


@app.post("/api/auth/logout")
def logout(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    conn = get_db()
    conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
    conn.commit()
    conn.close()
    return {"message": "Çıkış yapıldı"}


@app.get("/api/auth/me")
def me(user=Depends(get_current_user)):
    return {"user_id": user["id"], "username": user["username"], "email": user["email"]}


# ──────────────────────────────────────────────
# SUNUCU ENDPOINTLERİ
# ──────────────────────────────────────────────

@app.post("/api/servers")
def create_server(req: CreateServerRequest, user=Depends(get_current_user)):
    server_id = str(uuid.uuid4())
    conn = get_db()
    conn.execute(
        "INSERT INTO servers (id, owner_id, name, description, created_at) VALUES (?, ?, ?, ?, ?)",
        (server_id, user["id"], req.name, req.description, datetime.utcnow().isoformat())
    )
    conn.commit()
    conn.close()
    return {"server_id": server_id, "name": req.name, "message": "Sunucu oluşturuldu"}


@app.get("/api/servers")
def list_my_servers(user=Depends(get_current_user)):
    conn = get_db()
    servers = conn.execute(
        "SELECT * FROM servers WHERE owner_id = ? ORDER BY created_at DESC",
        (user["id"],)
    ).fetchall()
    conn.close()
    return [dict(s) for s in servers]


@app.get("/api/servers/{server_id}")
def get_server(server_id: str, user=Depends(get_current_user)):
    conn = get_db()
    server = conn.execute(
        "SELECT * FROM servers WHERE id = ?", (server_id,)
    ).fetchone()
    conn.close()
    if not server:
        raise HTTPException(404, "Sunucu bulunamadı")
    return dict(server)


@app.patch("/api/servers/{server_id}")
def update_server(server_id: str, req: UpdateServerRequest, user=Depends(get_current_user)):
    conn = get_db()
    server = conn.execute(
        "SELECT * FROM servers WHERE id = ? AND owner_id = ?", (server_id, user["id"])
    ).fetchone()
    if not server:
        conn.close()
        raise HTTPException(403, "Bu sunucuya erişim izniniz yok")

    updates = {}
    if req.tunnel_url is not None:
        updates["tunnel_url"] = req.tunnel_url
    if req.status is not None:
        updates["status"] = req.status
    if req.world_backup_url is not None:
        updates["world_backup_url"] = req.world_backup_url
    updates["last_seen"] = datetime.utcnow().isoformat()

    if updates:
        set_clause = ", ".join([f"{k} = ?" for k in updates])
        values = list(updates.values()) + [server_id]
        conn.execute(f"UPDATE servers SET {set_clause} WHERE id = ?", values)
        conn.commit()
    conn.close()
    return {"message": "Sunucu güncellendi"}


@app.delete("/api/servers/{server_id}")
def delete_server(server_id: str, user=Depends(get_current_user)):
    conn = get_db()
    server = conn.execute(
        "SELECT * FROM servers WHERE id = ? AND owner_id = ?", (server_id, user["id"])
    ).fetchone()
    if not server:
        conn.close()
        raise HTTPException(403, "Bu sunucuya erişim izniniz yok")
    conn.execute("DELETE FROM servers WHERE id = ?", (server_id,))
    conn.execute("DELETE FROM invites WHERE server_id = ?", (server_id,))
    conn.execute("DELETE FROM server_members WHERE server_id = ?", (server_id,))
    conn.commit()
    conn.close()
    return {"message": "Sunucu silindi"}


# ──────────────────────────────────────────────
# DAVET ENDPOINTLERİ
# ──────────────────────────────────────────────

@app.post("/api/invites")
def create_invite(req: CreateInviteRequest, user=Depends(get_current_user)):
    conn = get_db()
    server = conn.execute(
        "SELECT * FROM servers WHERE id = ? AND owner_id = ?", (req.server_id, user["id"])
    ).fetchone()
    if not server:
        conn.close()
        raise HTTPException(403, "Bu sunucuya erişim izniniz yok")

    invite_id = str(uuid.uuid4())
    invite_code = secrets.token_urlsafe(8)
    expires_at = None
    if req.expires_hours:
        expires_at = (datetime.utcnow() + timedelta(hours=req.expires_hours)).isoformat()

    conn.execute(
        "INSERT INTO invites (id, server_id, invite_code, created_by, max_uses, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (invite_id, req.server_id, invite_code, user["id"], req.max_uses, expires_at, datetime.utcnow().isoformat())
    )
    conn.commit()
    conn.close()
    return {"invite_code": invite_code, "invite_id": invite_id}


@app.get("/api/invites/join/{invite_code}")
def join_via_invite(invite_code: str, user=Depends(get_current_user)):
    conn = get_db()
    invite = conn.execute(
        "SELECT * FROM invites WHERE invite_code = ?", (invite_code,)
    ).fetchone()

    if not invite:
        conn.close()
        raise HTTPException(404, "Davet bulunamadı")

    if invite["expires_at"] and datetime.fromisoformat(invite["expires_at"]) < datetime.utcnow():
        conn.close()
        raise HTTPException(400, "Davet süresi dolmuş")

    if invite["max_uses"] != -1 and invite["use_count"] >= invite["max_uses"]:
        conn.close()
        raise HTTPException(400, "Davet kullanım limiti doldu")

    # Zaten üye mi?
    existing = conn.execute(
        "SELECT * FROM server_members WHERE server_id = ? AND user_id = ?",
        (invite["server_id"], user["id"])
    ).fetchone()

    if not existing:
        conn.execute(
            "INSERT INTO server_members (server_id, user_id, joined_at) VALUES (?, ?, ?)",
            (invite["server_id"], user["id"], datetime.utcnow().isoformat())
        )
        conn.execute(
            "UPDATE invites SET use_count = use_count + 1 WHERE id = ?", (invite["id"],)
        )
        conn.commit()

    server = conn.execute(
        "SELECT * FROM servers WHERE id = ?", (invite["server_id"],)
    ).fetchone()
    conn.close()
    return {"message": "Sunucuya katıldın!", "server": dict(server)}


@app.get("/api/servers/joined/list")
def list_joined_servers(user=Depends(get_current_user)):
    conn = get_db()
    servers = conn.execute("""
        SELECT s.* FROM servers s
        JOIN server_members sm ON s.id = sm.server_id
        WHERE sm.user_id = ?
        ORDER BY sm.joined_at DESC
    """, (user["id"],)).fetchall()
    conn.close()
    return [dict(s) for s in servers]


# ──────────────────────────────────────────────
# BAŞLAT
# ──────────────────────────────────────────────

init_db()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
