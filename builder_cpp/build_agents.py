# builder_cpp/build_agents.py
import asyncio
import hashlib
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from sqlalchemy import select, desc, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import AsyncSessionLocal
from app.models import AgentBuild

CPP_AGENT_DIR = PROJECT_ROOT / "builder_cpp" / "agent"
DIST_DIR = PROJECT_ROOT / "dist" / "agents"
DIST_DIR.mkdir(parents=True, exist_ok=True)

CPP_ENTRYPOINT = CPP_AGENT_DIR / "cmd" / "agent" / "main.cpp"
GXX = "C:/msys64/ucrt64/bin/g++.exe"


def increment_build_slug(last: str | None) -> str:
    if not last:
        return "1.0.0"
    parts = last.split(".")
    if len(parts) != 3:
        return "1.0.0"
    major, minor, patch = map(int, parts)
    return f"{major}.{minor}.{patch + 1}"


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for c in iter(lambda: f.read(8192), b""):
            h.update(c)
    return h.hexdigest()


def build_exe(slug: str, server_host: str, server_port: int, verify_cert: bool) -> Path:
    out = DIST_DIR / f"agent_universal_{slug}.exe"
    print(f"[+] Building {out.name}")

    verify_flag = "1" if verify_cert else "0"

    cmd = [
        GXX,
        "-O2",
        "-std=c++17",
        "-static",
        "-static-libgcc",
        "-static-libstdc++",
        "-o",
        str(out),
        f'-DSERVER_HOST=\\"{server_host}\\"',
        f"-DSERVER_PORT={server_port}",
        f'-DBUILD_SLUG=\\"{slug}\\"',
        f"-DVERIFY_CERT={verify_flag}",
        "-DSECURITY_WIN32",
        str(CPP_ENTRYPOINT),
        "-lwinhttp",
        "-lws2_32",
        "-ladvapi32",
        "-luser32",
        "-lsecur32",
        "-lcrypt32",
    ]
    print("[+] " + " ".join(cmd))
    subprocess.run(" ".join(cmd), shell=True, check=True, cwd=str(CPP_AGENT_DIR))
    return out


async def activate_build(session: AsyncSession, bid: int):
    await session.execute(
        update(AgentBuild).where(AgentBuild.is_active.is_(True)).values(is_active=False)
    )
    await session.execute(
        update(AgentBuild).where(AgentBuild.id == bid).values(is_active=True)
    )
    await session.commit()


def parse_host(app_host: str) -> tuple[str, int]:
    h = app_host.replace("https://", "").replace("http://", "").strip("/")
    port = 443 if app_host.startswith("https") else 80
    if ":" in h:
        host, p = h.split(":", 1)
        port = int(p)
    else:
        host = h
    return host, port


async def main():
    async with AsyncSessionLocal() as session:
        last = (
            (await session.execute(select(AgentBuild).order_by(desc(AgentBuild.id))))
            .scalars()
            .first()
        )
        slug = increment_build_slug(last.build_slug if last else None)
        print(f"[i] Build slug: {slug}")

        host, port = parse_host(str(settings.APP_HOST))
        # В dev-окружении у нас самоподписанный сертификат => VERIFY_CERT=0
        verify_cert = False
        exe = build_exe(slug, host, port, verify_cert)

        h = sha256_file(exe)
        print(f"[i] SHA256: {h}")

        build = AgentBuild(build_slug=slug, sha256=h, is_active=False)
        session.add(build)
        await session.flush()
        await activate_build(session, build.id)
        print(f"[+] Done: {exe.name}")


if __name__ == "__main__":
    asyncio.run(main())
