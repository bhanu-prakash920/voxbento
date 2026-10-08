"""Internal service-to-service endpoints. Never exposed through the public proxy."""

from __future__ import annotations

import hmac
import ipaddress

from fastapi import APIRouter, Query, Request
from fastapi.responses import JSONResponse

from portal.config import settings
from portal.program_ingest.publish_auth import MediaMTXAuthRequest, authorize_publish
from portal.program_ingest.supervisor import supervisor

router = APIRouter(include_in_schema=False)

_UNAUTHORIZED = {"detail": "Unauthorized"}


def hook_caller_allowed(request: Request, key: str) -> bool:
    """Only MediaMTX may call the hook.

    With ``MEDIAMTX_AUTH_HOOK_SECRET`` set, the caller must present it. Without
    it (deployments that have not configured one yet), production only accepts
    loopback/private-network callers: MediaMTX reaches the portal over the
    Docker network, while internet clients hitting the published port keep
    their public source address. Debug mode accepts any caller.
    """
    expected = settings.mediamtx_auth_hook_secret
    if expected:
        return hmac.compare_digest(expected.encode("utf-8"), key.encode("utf-8"))
    if settings.debug:
        return True
    host = request.client.host if request.client else ""
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return address.is_loopback or address.is_private


@router.post("/internal/mediamtx/auth")
async def mediamtx_auth_hook(request: Request, body: MediaMTXAuthRequest, key: str = Query("")) -> JSONResponse:
    """MediaMTX ``authMethod: http`` callback.

    Any 2xx allows the action. Every denial is the same bare 401 so callers
    cannot tell a missing room from a wrong secret.
    """
    if not hook_caller_allowed(request, key):
        return JSONResponse(_UNAUTHORIZED, status_code=401)
    decision = await authorize_publish(body, can_accept_new_feed=supervisor.can_accept_new_feed)
    if not decision.allowed:
        return JSONResponse(_UNAUTHORIZED, status_code=401)
    return JSONResponse({"ok": True})
