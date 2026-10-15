"""Read-only administrative HTML console; no external assets or browser secrets."""
from __future__ import annotations

import hmac
from html import escape

from fastapi import APIRouter, Header, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse

from .core import Guard


def console_router(guard: Guard, admin_key: str) -> APIRouter:
    router = APIRouter()

    def authorize(value: str | None) -> None:
        if not value or not hmac.compare_digest(value, admin_key):
            raise HTTPException(401, 'Unauthorized')

    @router.get('/v1/admin/status')
    def status(x_admin_key: str | None = Header(default=None)):
        authorize(x_admin_key)
        return JSONResponse(guard.audit_status(), headers={'Cache-Control': 'no-store'})

    @router.get('/v1/admin/console')
    def console(x_admin_key: str | None = Header(default=None)):
        authorize(x_admin_key)
        with guard.lock:
            events = guard.db.execute('SELECT seq, body FROM events ORDER BY seq DESC LIMIT 50').fetchall()
        state = guard.audit_status()
        label = 'HEALTHY' if state['healthy'] else 'DEGRADED'
        rows = ''.join('<tr><td>'+str(seq)+'</td><td><code>'+escape(body)+'</code></td></tr>' for seq, body in events)
        html = ('<!doctype html><html lang="en"><head><meta charset="utf-8">'
                '<meta name="viewport" content="width=device-width,initial-scale=1">'
                '<title>AgentGuard Command Center</title>'
                '<style>body{font:16px system-ui;background:#0e1826;color:#e9f0fa;max-width:1100px;margin:auto;padding:2rem}'
                'header{border-bottom:1px solid #3b5069;padding-bottom:1rem}h1{color:#7ce3ce}'
                'table{width:100%;border-collapse:collapse}td,th{padding:12px;text-align:left;border-bottom:1px solid #3b5069}'
                'code{overflow-wrap:anywhere}strong{color:#a8f0db}</style></head><body>'
                '<header><h1>AgentGuard · Command Center</h1><p>Audit integrity: <strong>'+label+'</strong></p>'
                '<p>Local events: '+str(state['local_events'])+'</p></header>'
                '<main><h2>Recent events</h2><table><thead><tr><th>#</th><th>Event</th></tr></thead><tbody>'
                +rows+'</tbody></table></main></body></html>')
        return HTMLResponse(html, headers={'Cache-Control': 'no-store',
            'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'",
            'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY',
            'Referrer-Policy': 'no-referrer'})
    return router
