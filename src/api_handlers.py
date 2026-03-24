"""
Request handlers live here.

This file contains the API behavior for the app. The goal is to keep route
logic together while leaving `worker.py` small and easy to scan.
"""

from urllib.parse import parse_qs, urlparse

from platform_utils import (
    capture_exception,
    err,
    is_basic_auth_valid,
    json_resp,
    ok,
    parse_json_object,
    unauthorized_basic,
)
from security_utils import (
    blind_index,
    create_token,
    decrypt,
    encrypt,
    hash_password,
    new_id,
    verify_password,
    verify_token,
)


async def api_register(req, env):
    body, bad_resp = await parse_json_object(req)
    if bad_resp:
        return bad_resp

    username = (body.get("username") or "").strip()
    email = (body.get("email") or "").strip()
    password = body.get("password") or ""
    name = (body.get("name") or username).strip()

    if not username or not email or not password:
        return err("username, email, and password are required")
    if len(password) < 8:
        return err("Password must be at least 8 characters")

    role = "member"
    enc = env.ENCRYPTION_KEY
    uid = new_id()
    try:
        await env.DB.prepare(
            "INSERT INTO users "
            "(id,username_hash,email_hash,name,username,email,password_hash,role)"
            " VALUES (?,?,?,?,?,?,?,?)"
        ).bind(
            uid,
            blind_index(username, enc),
            blind_index(email, enc),
            encrypt(name, enc),
            encrypt(username, enc),
            encrypt(email, enc),
            hash_password(password, username),
            encrypt(role, enc),
        ).run()
    except Exception as exc:
        if "UNIQUE" in str(exc):
            return err("Username or email already registered", 409)
        capture_exception(exc, req, env, "api_register.insert_user")
        return err("Registration failed - please try again", 500)

    token = create_token(uid, username, role, env.JWT_SECRET)
    return ok(
        {
            "token": token,
            "user": {"id": uid, "username": username, "name": name, "role": role},
        },
        "Registration successful",
    )


async def api_login(req, env):
    body, bad_resp = await parse_json_object(req)
    if bad_resp:
        return bad_resp

    username = (body.get("username") or "").strip()
    password = body.get("password") or ""

    if not username or not password:
        return err("username and password are required")

    enc = env.ENCRYPTION_KEY
    u_hash = blind_index(username, enc)
    row = await env.DB.prepare(
        "SELECT id,password_hash,role,name,username FROM users WHERE username_hash=?"
    ).bind(u_hash).first()

    if not row:
        return err("Invalid username or password", 401)

    password_hash = row.password_hash
    user_id = row.id
    role_enc = row.role
    name_enc = row.name
    username_enc = row.username
    stored_username = decrypt(username_enc, enc)

    if not verify_password(password, password_hash, stored_username):
        return err("Invalid username or password", 401)

    real_role = decrypt(role_enc, enc)
    real_name = decrypt(name_enc, enc)
    token = create_token(user_id, stored_username, real_role, env.JWT_SECRET)
    return ok(
        {
            "token": token,
            "user": {
                "id": user_id,
                "username": stored_username,
                "name": real_name,
                "role": real_role,
            },
        },
        "Login successful",
    )


async def api_list_activities(req, env):
    parsed = urlparse(req.url)
    params = parse_qs(parsed.query)
    atype = (params.get("type") or [None])[0]
    fmt = (params.get("format") or [None])[0]
    search = (params.get("q") or [None])[0]
    tag = (params.get("tag") or [None])[0]
    enc = env.ENCRYPTION_KEY

    base_q = (
        "SELECT a.id,a.title,a.description,a.type,a.format,a.schedule_type,"
        "a.created_at,u.name AS host_name_enc,"
        "(SELECT COUNT(*) FROM enrollments WHERE activity_id=a.id AND status='active')"
        " AS participant_count,"
        "(SELECT COUNT(*) FROM sessions WHERE activity_id=a.id) AS session_count"
        " FROM activities a JOIN users u ON a.host_id=u.id"
    )

    if tag:
        tag_row = await env.DB.prepare("SELECT id FROM tags WHERE name=?").bind(tag).first()
        if not tag_row:
            return json_resp({"activities": []})
        res = await env.DB.prepare(
            base_q
            + " JOIN activity_tags at2 ON at2.activity_id=a.id"
              " WHERE at2.tag_id=? ORDER BY a.created_at DESC"
        ).bind(tag_row["id"]).all()
    elif atype and fmt:
        res = await env.DB.prepare(
            base_q + " WHERE a.type=? AND a.format=? ORDER BY a.created_at DESC"
        ).bind(atype, fmt).all()
    elif atype:
        res = await env.DB.prepare(
            base_q + " WHERE a.type=? ORDER BY a.created_at DESC"
        ).bind(atype).all()
    elif fmt:
        res = await env.DB.prepare(
            base_q + " WHERE a.format=? ORDER BY a.created_at DESC"
        ).bind(fmt).all()
    else:
        res = await env.DB.prepare(base_q + " ORDER BY a.created_at DESC").all()

    activities = []
    for row in res.results or []:
        desc = decrypt(row["description"] or "", enc)
        host_name = decrypt(row["host_name_enc"] or "", enc)
        if search and (
            search.lower() not in row["title"].lower()
            and search.lower() not in desc.lower()
        ):
            continue

        t_res = await env.DB.prepare(
            "SELECT t.name FROM tags t"
            " JOIN activity_tags at2 ON at2.tag_id=t.id"
            " WHERE at2.activity_id=?"
        ).bind(row["id"]).all()

        activities.append(
            {
                "id": row["id"],
                "title": row["title"],
                "description": desc,
                "type": row["type"],
                "format": row["format"],
                "schedule_type": row["schedule_type"],
                "host_name": host_name,
                "participant_count": row["participant_count"],
                "session_count": row["session_count"],
                "tags": [t["name"] for t in (t_res.results or [])],
                "created_at": row["created_at"],
            }
        )

    return json_resp({"activities": activities})


async def api_create_activity(req, env):
    user = verify_token(req.headers.get("Authorization"), env.JWT_SECRET)
    if not user:
        return err("Authentication required", 401)

    body, bad_resp = await parse_json_object(req)
    if bad_resp:
        return bad_resp

    title = (body.get("title") or "").strip()
    description = (body.get("description") or "").strip()
    atype = (body.get("type") or "course").strip()
    fmt = (body.get("format") or "self_paced").strip()
    schedule_type = (body.get("schedule_type") or "ongoing").strip()

    if not title:
        return err("title is required")
    if atype not in ("course", "meetup", "workshop", "seminar", "other"):
        atype = "course"
    if fmt not in ("live", "self_paced", "hybrid"):
        fmt = "self_paced"
    if schedule_type not in ("one_time", "multi_session", "recurring", "ongoing"):
        schedule_type = "ongoing"

    enc = env.ENCRYPTION_KEY
    act_id = new_id()
    try:
        await env.DB.prepare(
            "INSERT INTO activities "
            "(id,title,description,type,format,schedule_type,host_id)"
            " VALUES (?,?,?,?,?,?,?)"
        ).bind(
            act_id,
            title,
            encrypt(description, enc) if description else "",
            atype,
            fmt,
            schedule_type,
            user["id"],
        ).run()
    except Exception as exc:
        capture_exception(exc, req, env, "api_create_activity.insert_activity")
        return err("Failed to create activity - please try again", 500)

    for tag_name in body.get("tags") or []:
        tag_name = tag_name.strip()
        if not tag_name:
            continue
        t_row = await env.DB.prepare("SELECT id FROM tags WHERE name=?").bind(tag_name).first()
        if not t_row:
            tid = new_id()
            try:
                await env.DB.prepare("INSERT INTO tags (id,name) VALUES (?,?)").bind(
                    tid, tag_name
                ).run()
                t_row = {"id": tid}
            except Exception:
                continue
        try:
            await env.DB.prepare(
                "INSERT OR IGNORE INTO activity_tags (activity_id,tag_id) VALUES (?,?)"
            ).bind(act_id, t_row["id"]).run()
        except Exception:
            pass

    return ok({"id": act_id, "title": title}, "Activity created")


async def api_get_activity(act_id: str, req, env):
    user = verify_token(req.headers.get("Authorization") or "", env.JWT_SECRET)
    enc = env.ENCRYPTION_KEY

    act = await env.DB.prepare(
        "SELECT a.*,u.name AS host_name_enc,u.id AS host_uid"
        " FROM activities a JOIN users u ON a.host_id=u.id"
        " WHERE a.id=?"
    ).bind(act_id).first()
    if not act:
        return err("Activity not found", 404)

    enrollment = None
    is_enrolled = False
    if user:
        enrollment = await env.DB.prepare(
            "SELECT id,role,status FROM enrollments"
            " WHERE activity_id=? AND user_id=?"
        ).bind(act_id, user["id"]).first()
        is_enrolled = enrollment is not None

    is_host = bool(user and act["host_uid"] == user["id"])

    ses_res = await env.DB.prepare(
        "SELECT id,title,description,start_time,end_time,location,created_at"
        " FROM sessions WHERE activity_id=? ORDER BY start_time"
    ).bind(act_id).all()

    sessions = []
    for session in ses_res.results or []:
        sessions.append(
            {
                "id": session["id"],
                "title": session["title"],
                "description": decrypt(session["description"] or "", enc)
                if (is_enrolled or is_host)
                else None,
                "start_time": session["start_time"],
                "end_time": session["end_time"],
                "location": decrypt(session["location"] or "", enc)
                if (is_enrolled or is_host)
                else None,
            }
        )

    t_res = await env.DB.prepare(
        "SELECT t.name FROM tags t"
        " JOIN activity_tags at2 ON at2.tag_id=t.id"
        " WHERE at2.activity_id=?"
    ).bind(act_id).all()

    count_row = await env.DB.prepare(
        "SELECT COUNT(*) AS cnt FROM enrollments WHERE activity_id=? AND status='active'"
    ).bind(act_id).first()

    return json_resp(
        {
            "activity": {
                "id": act["id"],
                "title": act["title"],
                "description": decrypt(act["description"] or "", enc),
                "type": act["type"],
                "format": act["format"],
                "schedule_type": act["schedule_type"],
                "host_name": decrypt(act["host_name_enc"] or "", enc),
                "participant_count": count_row["cnt"] if count_row else 0,
                "tags": [t["name"] for t in (t_res.results or [])],
                "created_at": act["created_at"],
            },
            "sessions": sessions,
            "is_enrolled": is_enrolled,
            "is_host": is_host,
            "enrollment": {
                "role": enrollment["role"],
                "status": enrollment["status"],
            }
            if enrollment
            else None,
        }
    )


async def api_join(req, env):
    user = verify_token(req.headers.get("Authorization"), env.JWT_SECRET)
    if not user:
        return err("Authentication required", 401)

    body, bad_resp = await parse_json_object(req)
    if bad_resp:
        return bad_resp

    act_id = body.get("activity_id")
    role = (body.get("role") or "participant").strip()

    if not act_id:
        return err("activity_id is required")
    if role not in ("participant", "instructor", "organizer"):
        role = "participant"

    act = await env.DB.prepare("SELECT id FROM activities WHERE id=?").bind(act_id).first()
    if not act:
        return err("Activity not found", 404)

    enr_id = new_id()
    try:
        await env.DB.prepare(
            "INSERT OR IGNORE INTO enrollments (id,activity_id,user_id,role)"
            " VALUES (?,?,?,?)"
        ).bind(enr_id, act_id, user["id"], role).run()
    except Exception as exc:
        capture_exception(exc, req, env, "api_join.insert_enrollment")
        return err("Failed to join activity - please try again", 500)

    return ok(None, "Joined activity successfully")


async def api_dashboard(req, env):
    user = verify_token(req.headers.get("Authorization"), env.JWT_SECRET)
    if not user:
        return err("Authentication required", 401)

    enc = env.ENCRYPTION_KEY
    res = await env.DB.prepare(
        "SELECT a.id,a.title,a.type,a.format,a.schedule_type,a.created_at,"
        "(SELECT COUNT(*) FROM enrollments WHERE activity_id=a.id AND status='active')"
        " AS participant_count,"
        "(SELECT COUNT(*) FROM sessions WHERE activity_id=a.id) AS session_count"
        " FROM activities a WHERE a.host_id=? ORDER BY a.created_at DESC"
    ).bind(user["id"]).all()

    hosted = []
    for row in res.results or []:
        t_res = await env.DB.prepare(
            "SELECT t.name FROM tags t JOIN activity_tags at2 ON at2.tag_id=t.id"
            " WHERE at2.activity_id=?"
        ).bind(row["id"]).all()
        hosted.append(
            {
                "id": row["id"],
                "title": row["title"],
                "type": row["type"],
                "format": row["format"],
                "schedule_type": row["schedule_type"],
                "participant_count": row["participant_count"],
                "session_count": row["session_count"],
                "tags": [t["name"] for t in (t_res.results or [])],
                "created_at": row["created_at"],
            }
        )

    res2 = await env.DB.prepare(
        "SELECT a.id,a.title,a.type,a.format,a.schedule_type,"
        "e.role AS enr_role,e.status AS enr_status,e.created_at AS joined_at,"
        "u.name AS host_name_enc"
        " FROM enrollments e"
        " JOIN activities a ON e.activity_id=a.id"
        " JOIN users u ON a.host_id=u.id"
        " WHERE e.user_id=? ORDER BY e.created_at DESC"
    ).bind(user["id"]).all()

    joined = []
    for row in res2.results or []:
        t_res = await env.DB.prepare(
            "SELECT t.name FROM tags t JOIN activity_tags at2 ON at2.tag_id=t.id"
            " WHERE at2.activity_id=?"
        ).bind(row["id"]).all()
        joined.append(
            {
                "id": row["id"],
                "title": row["title"],
                "type": row["type"],
                "format": row["format"],
                "schedule_type": row["schedule_type"],
                "enr_role": row["enr_role"],
                "enr_status": row["enr_status"],
                "host_name": decrypt(row["host_name_enc"] or "", enc),
                "tags": [t["name"] for t in (t_res.results or [])],
                "joined_at": row["joined_at"],
            }
        )

    return json_resp(
        {"user": user, "hosted_activities": hosted, "joined_activities": joined}
    )


async def api_create_session(req, env):
    user = verify_token(req.headers.get("Authorization"), env.JWT_SECRET)
    if not user:
        return err("Authentication required", 401)

    body, bad_resp = await parse_json_object(req)
    if bad_resp:
        return bad_resp

    act_id = body.get("activity_id")
    title = (body.get("title") or "").strip()
    description = (body.get("description") or "").strip()
    start_time = (body.get("start_time") or "").strip()
    end_time = (body.get("end_time") or "").strip()
    location = (body.get("location") or "").strip()

    if not act_id or not title:
        return err("activity_id and title are required")

    owned = await env.DB.prepare(
        "SELECT id FROM activities WHERE id=? AND host_id=?"
    ).bind(act_id, user["id"]).first()
    if not owned:
        return err("Activity not found or access denied", 404)

    enc = env.ENCRYPTION_KEY
    sid = new_id()
    try:
        await env.DB.prepare(
            "INSERT INTO sessions "
            "(id,activity_id,title,description,start_time,end_time,location)"
            " VALUES (?,?,?,?,?,?,?)"
        ).bind(
            sid,
            act_id,
            title,
            encrypt(description, enc) if description else "",
            start_time,
            end_time,
            encrypt(location, enc) if location else "",
        ).run()
    except Exception as exc:
        capture_exception(exc, req, env, "api_create_session.insert_session")
        return err("Failed to create session - please try again", 500)

    return ok({"id": sid}, "Session created")


async def api_list_tags(_req, env):
    res = await env.DB.prepare("SELECT id,name FROM tags ORDER BY name").all()
    tags = [{"id": row["id"], "name": row["name"]} for row in (res.results or [])]
    return json_resp({"tags": tags})


async def api_add_activity_tags(req, env):
    user = verify_token(req.headers.get("Authorization"), env.JWT_SECRET)
    if not user:
        return err("Authentication required", 401)

    body, bad_resp = await parse_json_object(req)
    if bad_resp:
        return bad_resp

    act_id = body.get("activity_id")
    tags = body.get("tags") or []

    if not act_id:
        return err("activity_id is required")

    owned = await env.DB.prepare(
        "SELECT id FROM activities WHERE id=? AND host_id=?"
    ).bind(act_id, user["id"]).first()
    if not owned:
        return err("Activity not found or access denied", 404)

    for tag_name in tags:
        tag_name = tag_name.strip()
        if not tag_name:
            continue
        t_row = await env.DB.prepare("SELECT id FROM tags WHERE name=?").bind(tag_name).first()
        if not t_row:
            tid = new_id()
            try:
                await env.DB.prepare("INSERT INTO tags (id,name) VALUES (?,?)").bind(
                    tid, tag_name
                ).run()
                t_row = {"id": tid}
            except Exception:
                continue
        try:
            await env.DB.prepare(
                "INSERT OR IGNORE INTO activity_tags (activity_id,tag_id) VALUES (?,?)"
            ).bind(act_id, t_row["id"]).run()
        except Exception:
            pass

    return ok(None, "Tags updated")


async def api_admin_table_counts(req, env):
    if not is_basic_auth_valid(req, env):
        return unauthorized_basic()

    tables_res = await env.DB.prepare(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
    ).all()

    counts = []
    for row in tables_res.results or []:
        table_name = row["name"]
        count_row = await env.DB.prepare(
            f'SELECT COUNT(*) AS cnt FROM "{table_name.replace(chr(34), chr(34) + chr(34))}"'
        ).first()
        counts.append({"table": table_name, "count": (count_row or {}).get("cnt", 0)})

    return json_resp({"tables": counts})
