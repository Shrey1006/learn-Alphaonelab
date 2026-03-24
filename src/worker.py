"""
This is the main Cloudflare Worker entry file.

The idea is simple: keep startup, routing, and request dispatch here so this
file stays readable even as the project grows. The heavier helper logic now
lives in a few support modules, but this remains the place to understand how
requests flow through the app.
"""

"""
EduPlatform – Cloudflare Python Worker (Activities Model)
=========================================================
API Routes
  POST /api/init              – initialise DB schema
  POST /api/seed              – seed sample data
  POST /api/register          – register a new user
  POST /api/login             – authenticate -> signed token
  GET  /api/activities        – list activities (?type=&format=&q=&tag=)
  POST /api/activities        – create activity              [host]
  GET  /api/activities/:id    – activity + sessions + state
  POST /api/join              – join an activity
  GET  /api/dashboard         – personal dashboard
  POST /api/sessions          – add a session to activity    [host]
  GET  /api/tags              – list all tags
  POST /api/activity-tags     – add tags to an activity      [host]

Security model
  * ALL user PII (username, email, display name, role) is encrypted with a
    XOR stream-cipher (SHA-256 key expansion) before storage.
  * HMAC-SHA256 blind indexes (username_hash, email_hash) allow O(1) row
    lookups without ever storing plaintext PII in an indexed column.
  * Activity descriptions and session locations/descriptions are encrypted.
  * Passwords: PBKDF2-SHA256, per-user derived salt (username + global pepper).
  * Auth tokens: HMAC-SHA256 signed, stateless (JWT-lite).
  XOR stream cipher - demonstration only.  Replace encrypt()/decrypt()
    with AES-GCM via js.crypto.subtle for a production deployment.

Static HTML pages (public/) are served via Workers Sites (KV binding).
"""
import re
from urllib.parse import urlparse

from workers import Response

from api_handlers import (
    api_add_activity_tags,
    api_admin_table_counts,
    api_create_activity,
    api_create_session,
    api_dashboard,
    api_get_activity,
    api_join,
    api_list_activities,
    api_list_tags,
    api_login,
    api_register,
)
from platform_utils import (
    _CORS,
    capture_exception,
    clean_path,
    err,
    init_db,
    is_basic_auth_valid,
    ok,
    seed_db,
    serve_static,
    unauthorized_basic,
)


async def _dispatch(request, env):
    path = urlparse(request.url).path
    method = request.method.upper()
    admin_path = clean_path(getattr(env, "ADMIN_URL", ""))

    if method == "OPTIONS":
        return Response("", status=204, headers=_CORS)

    if path == admin_path and method == "GET":
        if not is_basic_auth_valid(request, env):
            return unauthorized_basic()
        return await serve_static("/admin.html", env)

    if path.startswith("/api/"):
        if path == "/api/init" and method == "POST":
            try:
                await init_db(env)
                return ok(None, "Database initialised")
            except Exception as exc:
                capture_exception(exc, request, env, "api_init")
                return err("Database init failed - check D1 binding", 500)

        if path == "/api/seed" and method == "POST":
            try:
                await init_db(env)
                await seed_db(env, env.ENCRYPTION_KEY)
                return ok(None, "Sample data seeded")
            except Exception as exc:
                capture_exception(exc, request, env, "api_seed")
                return err("Seed failed - check D1 binding and schema", 500)

        if path == "/api/register" and method == "POST":
            return await api_register(request, env)

        if path == "/api/login" and method == "POST":
            return await api_login(request, env)

        if path == "/api/activities" and method == "GET":
            return await api_list_activities(request, env)

        if path == "/api/activities" and method == "POST":
            return await api_create_activity(request, env)

        match = re.fullmatch(r"/api/activities/([A-Za-z0-9_-]+)", path)
        if match and method == "GET":
            return await api_get_activity(match.group(1), request, env)

        if path == "/api/join" and method == "POST":
            return await api_join(request, env)

        if path == "/api/dashboard" and method == "GET":
            return await api_dashboard(request, env)

        if path == "/api/sessions" and method == "POST":
            return await api_create_session(request, env)

        if path == "/api/tags" and method == "GET":
            return await api_list_tags(request, env)

        if path == "/api/activity-tags" and method == "POST":
            return await api_add_activity_tags(request, env)

        if path == "/api/admin/table-counts" and method == "GET":
            return await api_admin_table_counts(request, env)

        return err("API endpoint not found", 404)

    return await serve_static(path, env)


async def on_fetch(request, env):
    try:
        return await _dispatch(request, env)
    except Exception as exc:
        capture_exception(exc, request, env, "on_fetch_unhandled")
        return err("Internal server error", 500)
