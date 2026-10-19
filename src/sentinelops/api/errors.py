"""Traducción de errores a `application/problem+json` (RFC 9457).

Nunca se devuelven trazas internas al cliente (STRIDE: divulgación).
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from sentinelops.domain.errors import EventRejected, InvalidTransition, InvalidValue

logger = logging.getLogger("sentinelops.api")

PROBLEM_JSON = "application/problem+json"


def problem(
    status_code: int, title: str, detail: Any = None, headers: dict[str, str] | None = None
) -> JSONResponse:
    body: dict[str, Any] = {"type": "about:blank", "title": title, "status": status_code}
    if detail is not None:
        body["detail"] = detail
    return JSONResponse(body, status_code=status_code, media_type=PROBLEM_JSON, headers=headers)


def register_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(RequestValidationError)
    async def _validation(_: Request, exc: RequestValidationError) -> JSONResponse:
        # Se devuelven ubicación y mensaje, no el valor recibido (podría contener secretos).
        errors = [{"loc": list(e["loc"]), "msg": e["msg"], "type": e["type"]} for e in exc.errors()]
        return problem(status.HTTP_422_UNPROCESSABLE_CONTENT, "Validation error", errors)

    @app.exception_handler(StarletteHTTPException)
    async def _http(_: Request, exc: StarletteHTTPException) -> JSONResponse:
        return problem(exc.status_code, str(exc.detail), headers=getattr(exc, "headers", None))

    @app.exception_handler(EventRejected)
    async def _rejected(_: Request, exc: EventRejected) -> JSONResponse:
        return problem(status.HTTP_422_UNPROCESSABLE_CONTENT, "Event rejected", str(exc))

    @app.exception_handler(InvalidValue)
    async def _invalid(_: Request, exc: InvalidValue) -> JSONResponse:
        return problem(status.HTTP_422_UNPROCESSABLE_CONTENT, "Invalid value", str(exc))

    @app.exception_handler(InvalidTransition)
    async def _transition(_: Request, exc: InvalidTransition) -> JSONResponse:
        return problem(status.HTTP_409_CONFLICT, "Invalid transition", str(exc))

    @app.exception_handler(Exception)
    async def _unexpected(request: Request, exc: Exception) -> JSONResponse:
        logger.exception("error no controlado en %s", request.url.path)
        return problem(status.HTTP_500_INTERNAL_SERVER_ERROR, "Internal server error")
