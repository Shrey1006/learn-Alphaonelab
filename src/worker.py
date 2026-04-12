"""
Alpha One Labs - Cloudflare Python Worker (Activities Model)
"""

import re
from urllib.parse import urlparse

from workers import Response

from api_activities import (
    api_add_activity_tags,
    api_create_activity,
    api_create_session,
    api_dashboard,
    api_get_activity,
    api_join,
    api_list_activities,
    api_list_tags,
)
from api_admin import api_admin_table_counts
from api_auth import api_login, api_register
from db_utils import init_db, seed_db
from http_utils import (
    CORS,
    capture_exception,
    clean_path,
    err,
    is_basic_auth_valid,
    ok,
    unauthorized_basic,
)
from static_utils import serve_static


async def _dispatch(request, env):
    path = urlparse(request.url).path
    method = request.method.upper()
    admin_path = clean_path(getattr(env, "ADMIN_URL", ""))

    if method == "OPTIONS":
        return Response("", status=204, headers=CORS)

    if path == admin_path and method == "GET":
        if not is_basic_auth_valid(request, env):
            return unauthorized_basic()
        return await serve_static("/admin.html", env)

    if path.startswith("/api/"):
        if path == "/api/init" and method == "POST":
            try:
                await init_db(env)
                return ok(None, "Database initialised")
            except Exception as e:
                capture_exception(e, request, env, "api_init")
                return err("Database init failed - check D1 binding", 500)

        if path == "/api/seed" and method == "POST":
            try:
                await init_db(env)
                await seed_db(env, env.ENCRYPTION_KEY)
                return ok(None, "Sample data seeded")
            except Exception as e:
                capture_exception(e, request, env, "api_seed")
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
    except Exception as e:
        capture_exception(e, request, env, "on_fetch_unhandled")
        return err("Internal server error", 500)
