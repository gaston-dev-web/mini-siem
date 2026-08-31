"""
FastAPI application: the SIEM's REST API + dashboard.

Every real SIEM has some form of this: an HTTP intake endpoint for
applications to push structured events directly (bypassing file/syslog
ingestion), and a set of read APIs the UI polls to render events, alerts,
and summary stats. Both live here.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from siem.models import Event, utcnow_iso
from siem.pipeline import Pipeline

WEB_DIR = Path(__file__).resolve().parent.parent / "web"


class IngestEventIn(BaseModel):
    source: str = "api"
    event_type: str = "unknown"
    outcome: str = "unknown"
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    user: Optional[str] = None
    message: str = ""
    timestamp: Optional[str] = None
    extra: dict = {}


def create_app(pipeline: Pipeline) -> FastAPI:
    app = FastAPI(title="mini-siem", description="A from-scratch SIEM lab", version="0.1.0")

    @app.get("/")
    def dashboard() -> FileResponse:
        return FileResponse(WEB_DIR / "dashboard.html")

    @app.post("/api/ingest")
    def ingest(payload: IngestEventIn) -> dict:
        """Push a normalized event directly, bypassing file/syslog ingestion.
        Useful for a custom app or script to report security-relevant activity
        straight into the SIEM (e.g. 'failed 2FA challenge', 'API key created')."""
        event = Event.new(
            timestamp=payload.timestamp or utcnow_iso(),
            source=payload.source,
            event_type=payload.event_type,
            outcome=payload.outcome,
            src_ip=payload.src_ip,
            dst_ip=payload.dst_ip,
            dst_port=payload.dst_port,
            user=payload.user,
            message=payload.message,
            raw="",
            extra=payload.extra,
        )
        pipeline.handle_event(event)
        return {"status": "accepted", "event_id": event.id}

    @app.get("/api/events")
    def get_events(limit: int = 100, source: Optional[str] = None) -> list[dict]:
        if limit < 1 or limit > 1000:
            raise HTTPException(400, "limit must be between 1 and 1000")
        return pipeline.store.recent_events(limit=limit, source=source)

    @app.get("/api/alerts")
    def get_alerts(limit: int = 100, severity: Optional[str] = None) -> list[dict]:
        if limit < 1 or limit > 1000:
            raise HTTPException(400, "limit must be between 1 and 1000")
        return pipeline.store.recent_alerts(limit=limit, severity=severity)

    @app.get("/api/stats")
    def get_stats() -> dict:
        return pipeline.store.stats()

    app.mount("/static", StaticFiles(directory=str(WEB_DIR)), name="static")
    return app
