# app/main.py
import os
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse

from app.api import pages, web_cookie, rdp
from app.api.agent import router as agent_router
from app.middleware.auth_html import AuthHTMLMiddleware
from app.ws import agent_ws

app = FastAPI(title="SysDM RMM")
app.add_middleware(AuthHTMLMiddleware)

current_dir = os.path.dirname(os.path.abspath(__file__))
static_path = os.path.join(current_dir, "static")
app.mount("/static", StaticFiles(directory=static_path), name="static")

app.include_router(web_cookie.router, tags=["web"])
app.include_router(pages.router)
app.include_router(agent_router)
app.include_router(rdp.router)
app.include_router(agent_ws.router)


@app.get("/")
async def root():
    return RedirectResponse(url="/login")
