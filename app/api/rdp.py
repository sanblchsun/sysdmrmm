# app/api/rdp.py
from urllib.parse import parse_qs, urlsplit

from fastapi import APIRouter, Depends, Request, HTTPException
from fastapi.responses import Response
from fastapi.templating import Jinja2Templates
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database import get_db
from app.models import Agent
from app.core.authx import auth

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")


@router.get("/api/auth/check")
async def auth_check(request: Request):
    try:
        token = await auth.get_access_token_from_request(request)
        auth.verify_token(token, verify_csrf=False)
        return Response(status_code=200)
    except Exception:
        return Response(status_code=401)


@router.get("/api/rdp/auth-agent")
async def auth_rmm_agent(request: Request, session: AsyncSession = Depends(get_db)):
    original_uri = request.headers.get("x-original-uri", "")
    if not original_uri:
        return Response(status_code=403)

    parsed = urlsplit(original_uri)
    path_parts = parsed.path.strip("/").split("/")

    machine_uid = None
    if len(path_parts) >= 3 and path_parts[0] == "rmm-agent":
        sub = path_parts[1]
        if sub == "ingest" and len(path_parts) >= 3:
            machine_uid = path_parts[2]
        elif sub == "agents" and len(path_parts) >= 3:
            machine_uid = path_parts[2]
        elif sub == "ws" and len(path_parts) >= 5 and path_parts[2] == "control" and path_parts[3] == "agent":
            machine_uid = path_parts[4]

    if not machine_uid:
        return Response(status_code=403)

    qs = parse_qs(parsed.query)
    token = qs.get("agent_token", [None])[0]
    if not token:
        return Response(status_code=403)

    result = await session.execute(
        select(Agent).where(
            Agent.machine_uid == machine_uid,
            Agent.token == token,
            Agent.is_active.is_(True),
        )
    )
    agent = result.scalar_one_or_none()
    if not agent:
        return Response(status_code=403)

    return Response(status_code=200)


@router.get("/ui/rdp-view")
async def rdp_view(request: Request, agent_id: int, session: AsyncSession = Depends(get_db)):
    agent = await session.get(Agent, agent_id)
    if not agent:
        raise HTTPException(status_code=404)
    return templates.TemplateResponse(
        "rdp_view.html",
        {
            "request": request,
            "agent_id": agent.id,
            "machine_uid": agent.machine_uid,
            "name_pc": agent.name_pc,
        },
    )
