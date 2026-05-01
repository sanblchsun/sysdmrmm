# app/api/agent.py
from datetime import datetime
import secrets
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Form
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database import get_db
from app.models import Agent, AgentAdditionalData, Company, AgentBuild
from app.schemas.agent import AgentRegisterIn, AgentRegisterOut, AgentTelemetryIn
from app.schemas.agent_update import AgentCheckUpdateIn
from app.core.auth_agent import get_agent_by_token
from app.config import settings

router = APIRouter()

DEFAULT_COMPANY_SLUG = "default"
DIST_DIR = Path(__file__).resolve().parent.parent.parent / "dist" / "agents"


async def _ensure_default_company(session: AsyncSession) -> Company:
    result = await session.execute(
        select(Company).where(Company.slug == DEFAULT_COMPANY_SLUG)
    )
    company = result.scalar_one_or_none()
    if not company:
        company = Company(name="Default", slug=DEFAULT_COMPANY_SLUG)
        session.add(company)
        await session.flush()
    return company


@router.post("/api/agent/register", response_model=AgentRegisterOut)
async def register_agent(
    data: AgentRegisterIn, session: AsyncSession = Depends(get_db)
):
    company = await _ensure_default_company(session)

    result = await session.execute(
        select(Agent).where(Agent.machine_uid == data.machine_uid)
    )
    agent = result.scalar_one_or_none()

    if agent:
        agent.name_pc = data.name_pc
        if data.exe_version:
            agent.exe_version = data.exe_version
        agent.last_seen = datetime.utcnow()
        agent.is_active = True
        if not agent.token:
            agent.token = secrets.token_hex(32)
    else:
        agent = Agent(
            machine_uid=data.machine_uid,
            name_pc=data.name_pc,
            exe_version=data.exe_version,
            company_id=company.id,
            token=secrets.token_hex(32),
            last_seen=datetime.utcnow(),
        )
        session.add(agent)
        await session.flush()

    await session.commit()
    await session.refresh(agent)
    return AgentRegisterOut(agent_uuid=agent.uuid, token=agent.token)


@router.post("/api/agent/heartbeat")
async def heartbeat(
    agent: Agent = Depends(get_agent_by_token),
    session: AsyncSession = Depends(get_db),
):
    agent.last_seen = datetime.utcnow()
    await session.commit()
    return {"status": "ok", "telemetry_mode": agent.telemetry_mode}


@router.post("/api/agent/telemetry")
async def telemetry(
    data: AgentTelemetryIn,
    agent: Agent = Depends(get_agent_by_token),
    session: AsyncSession = Depends(get_db),
):
    agent.last_seen = datetime.utcnow()
    if data.exe_version:
        agent.exe_version = data.exe_version

    result = await session.execute(
        select(AgentAdditionalData).where(AgentAdditionalData.agent_id == agent.id)
    )
    additional = result.scalar_one_or_none()
    if not additional:
        additional = AgentAdditionalData(agent_id=agent.id)
        session.add(additional)

    additional.system = data.system
    additional.user_name = data.user_name
    additional.ip_addr = data.ip_addr
    additional.external_ip = data.external_ip
    additional.total_memory = data.total_memory
    additional.available_memory = data.available_memory
    if data.disks:
        additional.disks = [d.model_dump() for d in data.disks]

    await session.commit()
    return {"status": "ok"}


@router.post("/api/agent/check-update")
async def check_update(
    data: AgentCheckUpdateIn,
    agent: Agent = Depends(get_agent_by_token),
    session: AsyncSession = Depends(get_db),
):
    result = await session.execute(
        select(AgentBuild).where(AgentBuild.is_active.is_(True))
    )
    build = result.scalar_one_or_none()
    if not build or build.build_slug == data.build:
        return {"update": False}
    return {
        "update": True,
        "build": build.build_slug,
        "url": f"{settings.APP_HOST}/api/agent/download/{build.build_slug}",
        "sha256": build.sha256,
    }


@router.get("/api/agent/download/{build_slug}")
async def download_build(build_slug: str):
    path = DIST_DIR / f"agent_universal_{build_slug}.exe"
    if not path.exists():
        raise HTTPException(status_code=404, detail="Build not found")
    return FileResponse(str(path), filename=f"agent_universal_{build_slug}.exe")


@router.post("/api/agent/{agent_id}/telemetry-mode")
async def set_telemetry_mode(
    agent_id: int,
    telemetry_mode: str = Form(...),
    session: AsyncSession = Depends(get_db),
):
    if telemetry_mode not in ("none", "basic", "full"):
        raise HTTPException(status_code=400, detail="Invalid mode")
    agent = await session.get(Agent, agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    agent.telemetry_mode = telemetry_mode
    await session.commit()
    return {"status": "ok", "telemetry_mode": agent.telemetry_mode}
