"""
NexChat — WebSocket сервер
Запуск: pip install websockets && python server.py
"""

import asyncio
import json
import uuid
import hashlib
import time
import random
import string
from datetime import datetime
from collections import defaultdict
import websockets

# ──────────────────────────────────────────
# In-memory хранилище (замени на SQLite/PostgreSQL для продакшна)
# ──────────────────────────────────────────
users = {}          # token -> user_data
users_by_email = {} # email -> token
connections = {}    # token -> websocket
rooms = {}          # room_id -> {members, messages, type, name}
pending_2fa = {}    # email -> code
pending_email = {}  # email -> code

# ──────────────────────────────────────────
# Утилиты
# ──────────────────────────────────────────
def hash_password(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()

def gen_code(n=6) -> str:
    return "".join(random.choices(string.digits, k=n))

def gen_token() -> str:
    return str(uuid.uuid4())

def now_iso() -> str:
    return datetime.utcnow().isoformat() + "Z"

def get_room_id(uid1: str, uid2: str) -> str:
    return "dm_" + "_".join(sorted([uid1, uid2]))

async def send(ws, payload: dict):
    try:
        await ws.send(json.dumps(payload))
    except Exception:
        pass

async def broadcast_room(room_id: str, payload: dict, exclude=None):
    room = rooms.get(room_id)
    if not room:
        return
    for uid in room["members"]:
        ws = connections.get(uid)
        if ws and ws is not exclude:
            await send(ws, payload)

async def notify_online(token: str, online: bool):
    """Уведомить всех друзей об изменении статуса"""
    user = users.get(token)
    if not user:
        return
    uid = user["id"]
    for room_id, room in rooms.items():
        if uid in room["members"] and room["type"] == "dm":
            await broadcast_room(room_id, {
                "type": "user_status",
                "user_id": uid,
                "online": online,
                "last_seen": now_iso()
            }, exclude=connections.get(token))

# ──────────────────────────────────────────
# Обработчики сообщений
# ──────────────────────────────────────────
async def handle_register(ws, data: dict):
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")
    name = data.get("name", "User")
    avatar = data.get("avatar", "🦄")

    if not email or not password:
        return await send(ws, {"type": "error", "message": "Email и пароль обязательны"})
    if email in users_by_email:
        return await send(ws, {"type": "error", "message": "Email уже занят"})

    # Отправить код подтверждения почты
    code = gen_code(4)
    pending_email[email] = {"code": code, "password": hash_password(password), "name": name, "avatar": avatar}
    print(f"[EMAIL CODE] {email}: {code}")  # В продакшне отправляй через SMTP

    await send(ws, {"type": "email_code_sent", "email": email, "demo_code": code})

async def handle_verify_email(ws, data: dict):
    email = data.get("email", "").strip().lower()
    code = data.get("code", "")

    pending = pending_email.get(email)
    if not pending or pending["code"] != code:
        return await send(ws, {"type": "error", "message": "Неверный код"})

    uid = str(uuid.uuid4())
    token = gen_token()
    user = {
        "id": uid,
        "email": email,
        "password": pending["password"],
        "name": pending["name"],
        "avatar": pending["avatar"],
        "bio": "",
        "status": "online",
        "created_at": now_iso(),
        "two_fa_enabled": True,
        "two_fa_secret": gen_code(6)
    }
    users[token] = user
    users_by_email[email] = token
    del pending_email[email]

    await send(ws, {"type": "register_success", "token": token, "user": _safe_user(user)})

async def handle_login(ws, data: dict):
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")

    token = users_by_email.get(email)
    if not token or users[token]["password"] != hash_password(password):
        return await send(ws, {"type": "error", "message": "Неверный email или пароль"})

    # 2FA
    code = gen_code(6)
    pending_2fa[email] = code
    print(f"[2FA CODE] {email}: {code}")

    await send(ws, {"type": "2fa_required", "email": email, "demo_code": code})

async def handle_verify_2fa(ws, data: dict):
    email = data.get("email", "").strip().lower()
    code = data.get("code", "")

    if pending_2fa.get(email) != code:
        return await send(ws, {"type": "error", "message": "Неверный 2FA код"})

    token = users_by_email[email]
    user = users[token]
    del pending_2fa[email]

    connections[user["id"]] = ws
    ws._token = token
    ws._uid = user["id"]

    await notify_online(token, True)
    await send(ws, {"type": "login_success", "token": token, "user": _safe_user(user)})

async def handle_auth(ws, data: dict):
    """Авторизация по сохранённому токену"""
    token = data.get("token")
    user = users.get(token)
    if not user:
        return await send(ws, {"type": "error", "message": "Невалидный токен"})

    connections[user["id"]] = ws
    ws._token = token
    ws._uid = user["id"]

    await notify_online(token, True)
    await send(ws, {"type": "auth_success", "user": _safe_user(user)})

async def handle_get_contacts(ws, data: dict):
    uid = getattr(ws, "_uid", None)
    if not uid:
        return await send(ws, {"type": "error", "message": "Не авторизован"})

    contacts = []
    for room_id, room in rooms.items():
        if uid in room["members"] and room["type"] == "dm":
            peer_id = next((m for m in room["members"] if m != uid), None)
            if not peer_id:
                continue
            peer_token = users_by_email.get(next((e for e, t in users_by_email.items() if users[t]["id"] == peer_id), ""), None)
            # найти пользователя по id
            peer = next((u for u in users.values() if u["id"] == peer_id), None)
            if peer:
                last_msg = room["messages"][-1] if room["messages"] else None
                contacts.append({
                    "room_id": room_id,
                    "user": _safe_user(peer),
                    "online": peer_id in connections,
                    "last_message": last_msg,
                    "unread": 0
                })

    await send(ws, {"type": "contacts", "contacts": contacts})

async def handle_search_users(ws, data: dict):
    uid = getattr(ws, "_uid", None)
    if not uid:
        return
    query = data.get("query", "").lower()
    results = []
    for u in users.values():
        if u["id"] == uid:
            continue
        if query in u["name"].lower() or query in u["email"].lower():
            results.append(_safe_user(u))
    await send(ws, {"type": "search_results", "users": results[:20]})

async def handle_open_dm(ws, data: dict):
    uid = getattr(ws, "_uid", None)
    if not uid:
        return

    peer_id = data.get("user_id")
    if not peer_id or peer_id == uid:
        return await send(ws, {"type": "error", "message": "Неверный пользователь"})

    room_id = get_room_id(uid, peer_id)
    if room_id not in rooms:
        rooms[room_id] = {
            "type": "dm",
            "members": [uid, peer_id],
            "messages": [],
            "created_at": now_iso()
        }

    room = rooms[room_id]
    peer = next((u for u in users.values() if u["id"] == peer_id), None)
    peer_online = peer_id in connections

    await send(ws, {
        "type": "room_opened",
        "room_id": room_id,
        "peer": _safe_user(peer) if peer else None,
        "peer_online": peer_online,
        "messages": room["messages"][-50:]
    })

async def handle_send_message(ws, data: dict):
    uid = getattr(ws, "_uid", None)
    if not uid:
        return

    room_id = data.get("room_id")
    room = rooms.get(room_id)
    if not room or uid not in room["members"]:
        return await send(ws, {"type": "error", "message": "Нет доступа к комнате"})

    user = next((u for u in users.values() if u["id"] == uid), None)
    msg = {
        "id": str(uuid.uuid4()),
        "room_id": room_id,
        "sender_id": uid,
        "sender_name": user["name"] if user else "?",
        "sender_avatar": user["avatar"] if user else "❓",
        "type": data.get("msg_type", "text"),  # text|voice|sticker|gif|image
        "text": data.get("text", ""),
        "url": data.get("url", ""),
        "sticker": data.get("sticker", ""),
        "duration": data.get("duration", 0),
        "reactions": {},
        "edited": False,
        "deleted": False,
        "reply_to": data.get("reply_to"),
        "timestamp": now_iso()
    }
    room["messages"].append(msg)

    await broadcast_room(room_id, {"type": "new_message", "message": msg})

async def handle_edit_message(ws, data: dict):
    uid = getattr(ws, "_uid", None)
    room_id = data.get("room_id")
    msg_id = data.get("msg_id")
    new_text = data.get("text", "")

    room = rooms.get(room_id)
    if not room:
        return
    for msg in room["messages"]:
        if msg["id"] == msg_id and msg["sender_id"] == uid:
            msg["text"] = new_text
            msg["edited"] = True
            await broadcast_room(room_id, {"type": "message_edited", "msg_id": msg_id, "text": new_text, "room_id": room_id})
            break

async def handle_delete_message(ws, data: dict):
    uid = getattr(ws, "_uid", None)
    room_id = data.get("room_id")
    msg_id = data.get("msg_id")

    room = rooms.get(room_id)
    if not room:
        return
    for msg in room["messages"]:
        if msg["id"] == msg_id and msg["sender_id"] == uid:
            msg["deleted"] = True
            msg["text"] = "Сообщение удалено"
            await broadcast_room(room_id, {"type": "message_deleted", "msg_id": msg_id, "room_id": room_id})
            break

async def handle_react(ws, data: dict):
    uid = getattr(ws, "_uid", None)
    room_id = data.get("room_id")
    msg_id = data.get("msg_id")
    emoji = data.get("emoji")

    room = rooms.get(room_id)
    if not room:
        return
    for msg in room["messages"]:
        if msg["id"] == msg_id:
            if emoji not in msg["reactions"]:
                msg["reactions"][emoji] = []
            if uid in msg["reactions"][emoji]:
                msg["reactions"][emoji].remove(uid)
            else:
                msg["reactions"][emoji].append(uid)
            await broadcast_room(room_id, {"type": "reaction_updated", "msg_id": msg_id, "reactions": msg["reactions"], "room_id": room_id})
            break

async def handle_typing(ws, data: dict):
    uid = getattr(ws, "_uid", None)
    room_id = data.get("room_id")
    room = rooms.get(room_id)
    if not room or uid not in room["members"]:
        return
    user = next((u for u in users.values() if u["id"] == uid), None)
    await broadcast_room(room_id, {
        "type": "typing",
        "room_id": room_id,
        "user_id": uid,
        "name": user["name"] if user else "?"
    }, exclude=ws)

async def handle_create_group(ws, data: dict):
    uid = getattr(ws, "_uid", None)
    if not uid:
        return

    name = data.get("name", "Группа")
    members = list(set([uid] + data.get("members", [])))
    icon = data.get("icon", "👥")
    room_id = "group_" + str(uuid.uuid4())[:8]
    rooms[room_id] = {
        "type": "group",
        "name": name,
        "icon": icon,
        "members": members,
        "messages": [],
        "admin": uid,
        "created_at": now_iso()
    }
    for mid in members:
        ws2 = connections.get(mid)
        if ws2:
            await send(ws2, {"type": "group_created", "room": {
                "room_id": room_id, "name": name, "icon": icon, "members": members, "type": "group"
            }})

async def handle_update_profile(ws, data: dict):
    token = getattr(ws, "_token", None)
    if not token:
        return
    user = users.get(token)
    if not user:
        return
    for field in ["name", "bio", "avatar", "status"]:
        if field in data:
            user[field] = data[field]
    await send(ws, {"type": "profile_updated", "user": _safe_user(user)})
    # Уведомить контакты
    uid = user["id"]
    for room_id, room in rooms.items():
        if uid in room["members"]:
            await broadcast_room(room_id, {"type": "user_updated", "user": _safe_user(user)}, exclude=ws)

async def handle_get_history(ws, data: dict):
    uid = getattr(ws, "_uid", None)
    room_id = data.get("room_id")
    room = rooms.get(room_id)
    if not room or uid not in room["members"]:
        return
    offset = data.get("offset", 0)
    limit = data.get("limit", 50)
    msgs = room["messages"]
    sliced = msgs[max(0, len(msgs)-offset-limit):max(0, len(msgs)-offset)]
    await send(ws, {"type": "history", "room_id": room_id, "messages": sliced, "has_more": offset+limit < len(msgs)})

async def handle_call_signal(ws, data: dict):
    uid = getattr(ws, "_uid", None)
    target_id = data.get("target_id")
    ws2 = connections.get(target_id)
    user = next((u for u in users.values() if u["id"] == uid), None)
    if ws2 and user:
        await send(ws2, {
            "type": "call_signal",
            "signal_type": data.get("signal_type"),  # offer|answer|ice|end
            "from_id": uid,
            "from_name": user["name"],
            "from_avatar": user["avatar"],
            "sdp": data.get("sdp"),
            "candidate": data.get("candidate")
        })

def _safe_user(u: dict) -> dict:
    if not u:
        return {}
    return {k: u[k] for k in ["id","name","email","avatar","bio","status","created_at"] if k in u}

# ──────────────────────────────────────────
# Роутер
# ──────────────────────────────────────────
HANDLERS = {
    "register":        handle_register,
    "verify_email":    handle_verify_email,
    "login":           handle_login,
    "verify_2fa":      handle_verify_2fa,
    "auth":            handle_auth,
    "get_contacts":    handle_get_contacts,
    "search_users":    handle_search_users,
    "open_dm":         handle_open_dm,
    "send_message":    handle_send_message,
    "edit_message":    handle_edit_message,
    "delete_message":  handle_delete_message,
    "react":           handle_react,
    "typing":          handle_typing,
    "create_group":    handle_create_group,
    "update_profile":  handle_update_profile,
    "get_history":     handle_get_history,
    "call_signal":     handle_call_signal,
}

async def handler(ws):
    ws._token = None
    ws._uid = None
    print(f"[+] Подключился: {ws.remote_address}")
    try:
        async for raw in ws:
            try:
                data = json.loads(raw)
                msg_type = data.get("type", "")
                h = HANDLERS.get(msg_type)
                if h:
                    await h(ws, data)
                else:
                    await send(ws, {"type": "error", "message": f"Неизвестный тип: {msg_type}"})
            except json.JSONDecodeError:
                await send(ws, {"type": "error", "message": "Невалидный JSON"})
            except Exception as e:
                print(f"[ERROR] {e}")
                await send(ws, {"type": "error", "message": "Внутренняя ошибка"})
    except websockets.exceptions.ConnectionClosed:
        pass
    finally:
        uid = getattr(ws, "_uid", None)
        if uid and connections.get(uid) is ws:
            del connections[uid]
            token = getattr(ws, "_token", None)
            if token:
                await notify_online(token, False)
        print(f"[-] Отключился: {ws.remote_address}")

async def main():
    print("═" * 50)
    print("  NexChat WebSocket Server v1.0")
    print("  ws://localhost:8765")
    print("═" * 50)
    async with websockets.serve(handler, "0.0.0.0", 8765, ping_interval=20, ping_timeout=10):
        await asyncio.Future()  # run forever

if __name__ == "__main__":
    asyncio.run(main())
