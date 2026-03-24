"""
Shared platform helpers live here.

This file holds the plumbing that many routes need: response helpers, request
parsing, admin auth, DB bootstrap, sample seeding, static file serving, and
error logging. It is the shared tools file, not the place for route logic.
"""

import base64
import hmac as _hmac
import json
import re
import traceback
from urllib.parse import urlparse

from workers import Response

from security_utils import blind_index, encrypt, hash_password


_CORS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
}

_DDL = [
    """CREATE TABLE IF NOT EXISTS users (
        id            TEXT PRIMARY KEY,
        username_hash TEXT NOT NULL UNIQUE,
        email_hash    TEXT NOT NULL UNIQUE,
        name          TEXT NOT NULL,
        username      TEXT NOT NULL,
        email         TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        role          TEXT NOT NULL,
        created_at    TEXT NOT NULL DEFAULT (datetime('now'))
    )""",
    """CREATE TABLE IF NOT EXISTS activities (
        id            TEXT PRIMARY KEY,
        title         TEXT NOT NULL,
        description   TEXT,
        type          TEXT NOT NULL DEFAULT 'course',
        format        TEXT NOT NULL DEFAULT 'self_paced',
        schedule_type TEXT NOT NULL DEFAULT 'ongoing',
        host_id       TEXT NOT NULL,
        created_at    TEXT NOT NULL DEFAULT (datetime('now')),
        FOREIGN KEY (host_id) REFERENCES users(id)
    )""",
    """CREATE TABLE IF NOT EXISTS sessions (
        id          TEXT PRIMARY KEY,
        activity_id TEXT NOT NULL,
        title       TEXT,
        description TEXT,
        start_time  TEXT,
        end_time    TEXT,
        location    TEXT,
        created_at  TEXT NOT NULL DEFAULT (datetime('now')),
        FOREIGN KEY (activity_id) REFERENCES activities(id)
    )""",
    """CREATE TABLE IF NOT EXISTS enrollments (
        id          TEXT PRIMARY KEY,
        activity_id TEXT NOT NULL,
        user_id     TEXT NOT NULL,
        role        TEXT NOT NULL DEFAULT 'participant',
        status      TEXT NOT NULL DEFAULT 'active',
        created_at  TEXT NOT NULL DEFAULT (datetime('now')),
        UNIQUE (activity_id, user_id),
        FOREIGN KEY (activity_id) REFERENCES activities(id),
        FOREIGN KEY (user_id) REFERENCES users(id)
    )""",
    """CREATE TABLE IF NOT EXISTS session_attendance (
        id         TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        user_id    TEXT NOT NULL,
        status     TEXT NOT NULL DEFAULT 'registered',
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        UNIQUE (session_id, user_id),
        FOREIGN KEY (session_id) REFERENCES sessions(id),
        FOREIGN KEY (user_id) REFERENCES users(id)
    )""",
    """CREATE TABLE IF NOT EXISTS tags (
        id   TEXT PRIMARY KEY,
        name TEXT UNIQUE NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS activity_tags (
        activity_id TEXT NOT NULL,
        tag_id      TEXT NOT NULL,
        PRIMARY KEY (activity_id, tag_id),
        FOREIGN KEY (activity_id) REFERENCES activities(id),
        FOREIGN KEY (tag_id) REFERENCES tags(id)
    )""",
    "CREATE INDEX IF NOT EXISTS idx_activities_host ON activities(host_id)",
    "CREATE INDEX IF NOT EXISTS idx_enrollments_activity ON enrollments(activity_id)",
    "CREATE INDEX IF NOT EXISTS idx_enrollments_user ON enrollments(user_id)",
    "CREATE INDEX IF NOT EXISTS idx_sessions_activity ON sessions(activity_id)",
    "CREATE INDEX IF NOT EXISTS idx_sa_session ON session_attendance(session_id)",
    "CREATE INDEX IF NOT EXISTS idx_sa_user ON session_attendance(user_id)",
    "CREATE INDEX IF NOT EXISTS idx_at_activity ON activity_tags(activity_id)",
]

_MIME = {
    "html": "text/html; charset=utf-8",
    "css": "text/css; charset=utf-8",
    "js": "application/javascript; charset=utf-8",
    "json": "application/json",
    "png": "image/png",
    "jpg": "image/jpeg",
    "svg": "image/svg+xml",
    "ico": "image/x-icon",
}


def capture_exception(exc: Exception, req=None, _env=None, where: str = ""):
    """Best-effort exception logging with traceback and request context."""
    try:
        payload = {
            "level": "error",
            "where": where or "unknown",
            "error_type": type(exc).__name__,
            "error": str(exc),
            "traceback": "".join(
                traceback.format_exception(type(exc), exc, exc.__traceback__)
            ),
        }
        if req:
            payload["request"] = {
                "method": req.method,
                "url": req.url,
                "path": urlparse(req.url).path,
            }
        print(json.dumps(payload))
    except Exception:
        pass


def json_resp(data, status: int = 200):
    return Response(
        json.dumps(data),
        status=status,
        headers={"Content-Type": "application/json", **_CORS},
    )


def ok(data=None, msg: str = "OK"):
    body = {"success": True, "message": msg}
    if data is not None:
        body["data"] = data
    return json_resp(body, 200)


def err(msg: str, status: int = 400):
    return json_resp({"error": msg}, status)


async def parse_json_object(req):
    """Parse request JSON and ensure the payload is an object."""
    try:
        text = await req.text()
        body = json.loads(text)
    except Exception:
        return None, err("Invalid JSON body")

    if not isinstance(body, dict):
        return None, err("JSON body must be an object", 400)

    return body, None


def clean_path(value: str, default: str = "/admin") -> str:
    """Normalize an env-provided path into a safe absolute URL path."""
    raw = (value or "").strip()
    if not raw:
        return default
    parsed = urlparse(raw)
    path = (parsed.path or raw).strip()
    if not path.startswith("/"):
        path = "/" + path
    path = re.sub(r"/+", "/", path)
    if len(path) > 1 and path.endswith("/"):
        path = path[:-1]
    return path or default


def unauthorized_basic(realm: str = "EduPlatform Admin"):
    return Response(
        "Authentication required",
        status=401,
        headers={"WWW-Authenticate": f'Basic realm="{realm}"', **_CORS},
    )


def is_basic_auth_valid(req, env) -> bool:
    username = (getattr(env, "ADMIN_BASIC_USER", "") or "").strip()
    password = (getattr(env, "ADMIN_BASIC_PASS", "") or "").strip()
    if not username or not password:
        return False

    auth = req.headers.get("Authorization") or ""
    if not auth.lower().startswith("basic "):
        return False

    try:
        raw = auth.split(" ", 1)[1].strip()
        decoded = base64.b64decode(raw).decode("utf-8")
        user, pwd = decoded.split(":", 1)
    except Exception:
        return False

    return _hmac.compare_digest(user, username) and _hmac.compare_digest(pwd, password)


async def init_db(env):
    for sql in _DDL:
        await env.DB.prepare(sql).run()


async def seed_db(env, enc_key: str):
    seed_users = [
        ("alice", "alice@example.com", "password123", "host", "Alice Chen"),
        ("bob", "bob@example.com", "password123", "host", "Bob Martinez"),
        ("charlie", "charlie@example.com", "password123", "member", "Charlie Kim"),
        ("diana", "diana@example.com", "password123", "member", "Diana Patel"),
    ]
    uid_map = {}
    for uname, email, pw, role, display in seed_users:
        uid = f"usr-{uname}"
        uid_map[uname] = uid
        try:
            await env.DB.prepare(
                "INSERT INTO users "
                "(id,username_hash,email_hash,name,username,email,password_hash,role)"
                " VALUES (?,?,?,?,?,?,?,?)"
            ).bind(
                uid,
                blind_index(uname, enc_key),
                blind_index(email, enc_key),
                encrypt(display, enc_key),
                encrypt(uname, enc_key),
                encrypt(email, enc_key),
                hash_password(pw, uname),
                encrypt(role, enc_key),
            ).run()
        except Exception:
            pass

    aid = uid_map["alice"]
    bid = uid_map["bob"]
    cid = uid_map["charlie"]
    did = uid_map["diana"]

    tag_rows = [
        ("tag-python", "Python"),
        ("tag-js", "JavaScript"),
        ("tag-data", "Data Science"),
        ("tag-ml", "Machine Learning"),
        ("tag-webdev", "Web Development"),
        ("tag-db", "Databases"),
        ("tag-cloud", "Cloud"),
    ]
    for tid, tname in tag_rows:
        try:
            await env.DB.prepare("INSERT INTO tags (id,name) VALUES (?,?)").bind(
                tid, tname
            ).run()
        except Exception:
            pass

    act_rows = [
        (
            "act-py-begin",
            "Python for Beginners",
            "Learn Python programming from scratch. Master variables, loops, "
            "functions, and object-oriented design in this hands-on course.",
            "course",
            "self_paced",
            "ongoing",
            aid,
            ["tag-python"],
        ),
        (
            "act-js-meetup",
            "JavaScript Developers Meetup",
            "Monthly meetup for JavaScript enthusiasts. Share projects, "
            "discuss new frameworks, and network with fellow devs.",
            "meetup",
            "live",
            "recurring",
            bid,
            ["tag-js", "tag-webdev"],
        ),
        (
            "act-ds-workshop",
            "Data Science Workshop",
            "Hands-on workshop covering data wrangling with pandas, "
            "visualisation with matplotlib, and intro to machine learning.",
            "workshop",
            "live",
            "multi_session",
            aid,
            ["tag-data", "tag-python"],
        ),
        (
            "act-ml-study",
            "Machine Learning Study Group",
            "Collaborative study group working through ML concepts, "
            "reading papers, and implementing algorithms together.",
            "course",
            "hybrid",
            "recurring",
            bid,
            ["tag-ml", "tag-python"],
        ),
        (
            "act-webdev",
            "Web Dev Fundamentals",
            "Build modern responsive websites with HTML5, CSS3, and JavaScript. "
            "Covers Flexbox, Grid, fetch API, and accessible design.",
            "course",
            "self_paced",
            "ongoing",
            aid,
            ["tag-webdev", "tag-js"],
        ),
        (
            "act-db-design",
            "Database Design & SQL",
            "Design normalised relational schemas, write complex SQL queries, "
            "use indexes for speed, and understand transactions.",
            "workshop",
            "live",
            "one_time",
            bid,
            ["tag-db"],
        ),
    ]
    for act_id, title, desc, atype, fmt, sched, host_id, tags in act_rows:
        try:
            await env.DB.prepare(
                "INSERT INTO activities "
                "(id,title,description,type,format,schedule_type,host_id)"
                " VALUES (?,?,?,?,?,?,?)"
            ).bind(act_id, title, encrypt(desc, enc_key), atype, fmt, sched, host_id).run()
        except Exception:
            pass
        for tag_id in tags:
            try:
                await env.DB.prepare(
                    "INSERT OR IGNORE INTO activity_tags (activity_id,tag_id)"
                    " VALUES (?,?)"
                ).bind(act_id, tag_id).run()
            except Exception:
                pass

    ses_rows = [
        (
            "ses-js-1",
            "act-js-meetup",
            "April Meetup",
            "Q1 retro and React 19 deep-dive",
            "2024-04-15 18:00",
            "2024-04-15 21:00",
            "Tech Hub, 123 Main St, SF",
        ),
        (
            "ses-js-2",
            "act-js-meetup",
            "May Meetup",
            "TypeScript 5.4 and what's new in Node 22",
            "2024-05-20 18:00",
            "2024-05-20 21:00",
            "Tech Hub, 123 Main St, SF",
        ),
        (
            "ses-ds-1",
            "act-ds-workshop",
            "Session 1 - Data Wrangling",
            "Introduction to pandas DataFrames and data cleaning",
            "2024-06-01 10:00",
            "2024-06-01 14:00",
            "Online via Zoom",
        ),
        (
            "ses-ds-2",
            "act-ds-workshop",
            "Session 2 - Visualisation",
            "matplotlib, seaborn, and plotly for data storytelling",
            "2024-06-08 10:00",
            "2024-06-08 14:00",
            "Online via Zoom",
        ),
        (
            "ses-ds-3",
            "act-ds-workshop",
            "Session 3 - Intro to ML",
            "scikit-learn: regression, classification, evaluation",
            "2024-06-15 10:00",
            "2024-06-15 14:00",
            "Online via Zoom",
        ),
    ]
    for sid, act_id, title, desc, start, end, loc in ses_rows:
        try:
            await env.DB.prepare(
                "INSERT INTO sessions "
                "(id,activity_id,title,description,start_time,end_time,location)"
                " VALUES (?,?,?,?,?,?,?)"
            ).bind(
                sid,
                act_id,
                title,
                encrypt(desc, enc_key),
                start,
                end,
                encrypt(loc, enc_key),
            ).run()
        except Exception:
            pass

    enr_rows = [
        ("enr-c-py", "act-py-begin", cid, "participant"),
        ("enr-c-js", "act-js-meetup", cid, "participant"),
        ("enr-c-ds", "act-ds-workshop", cid, "participant"),
        ("enr-d-py", "act-py-begin", did, "participant"),
        ("enr-d-webdev", "act-webdev", did, "participant"),
        ("enr-b-py", "act-py-begin", bid, "instructor"),
    ]
    for eid, act_id, uid, role in enr_rows:
        try:
            await env.DB.prepare(
                "INSERT OR IGNORE INTO enrollments (id,activity_id,user_id,role)"
                " VALUES (?,?,?,?)"
            ).bind(eid, act_id, uid, role).run()
        except Exception:
            pass


async def serve_static(path: str, env):
    if path in ("/", ""):
        key = "index.html"
    else:
        key = path.lstrip("/")
        if "." not in key.split("/")[-1]:
            key += ".html"

    try:
        content = await env.__STATIC_CONTENT.get(key, "text")
    except Exception:
        content = None

    if content is None:
        try:
            content = await env.__STATIC_CONTENT.get("index.html", "text")
        except Exception:
            content = None

    if content is None:
        return Response(
            "<h1>404 - Not Found</h1>",
            status=404,
            headers={"Content-Type": "text/html"},
        )

    ext = key.rsplit(".", 1)[-1] if "." in key else "html"
    mime = _MIME.get(ext, "text/plain")
    return Response(content, headers={"Content-Type": mime, **_CORS})
