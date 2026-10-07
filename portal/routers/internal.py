"""Internal service-to-service endpoints. Never exposed through the public proxy."""

from __future__ import annotations

import hmac

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse

from portal.config import settings
from portal.program_ingest.publish_auth import MediaMTXAuthRequest, authorize_publish
from portal.program_ingest.supervisor import supervisor

router = APIRouter(include_in_schema=False)

_UNAUTHORIZED = {"detail": "Unauthorized"}


def hook_key_valid(key: str) -> bool:
    expected = settings.mediamtx_auth_hook_secret
    if not expected:
        return True
    return hmac.compare_digest(expected.encode("utf-8"), key.encode("utf-8"))


@router.post("/internal/mediamtx/auth")
async def mediamtx_auth_hook(body: MediaMTXAuthRequest, key: str = Query("")) -> JSONResponse:
    """MediaMTX ``authMethod: http`` callback.

    Any 2xx allows the action. Every denial is the same bare 401 so callers
    cannot tell a missing room from a wrong secret.
    """
    if not hook_key_valid(key):
        return JSONResponse(_UNAUTHORIZED, status_code=401)
    decision = await authorize_publish(body, can_accept_new_feed=supervisor.can_accept_new_feed)
    if not decision.allowed:
        return JSONResponse(_UNAUTHORIZED, status_code=401)
    return JSONResponse({"ok": True})
