"""
testbed/toy_api/main.py
FastAPI application with fine-grained fault injection switches:
- Header-based switches:
  - X-Fault-Delay: float seconds to sleep
  - X-Fault-Status: int HTTP status code to force
  - X-Fault-Commit-Write: bool ("true" | "false")
  - X-Fault-Quota-Exhausted: bool
"""

from __future__ import annotations

import asyncio
import time
import uuid
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import JSONResponse

app = FastAPI(title="layers Toy API")

COMMITTED_ORDERS: dict[str, dict[str, Any]] = {}


@app.get("/")
def index():
    return {"status": "ok", "service": "layers-toy-api"}


@app.get("/account")
def account(authorization: str | None = Header(default=None)):
    if not authorization or authorization == "Bearer invalid_key":
        raise HTTPException(status_code=401, detail="Invalid API key")
    if authorization == "Bearer expired_key":
        raise HTTPException(status_code=401, detail="API key expired")
    if authorization == "Bearer zero_quota_key":
        return {
            "account_email": "user@example.com",
            "total_searches_left": 0,
            "plan_searches_left": 0,
        }
    return {
        "account_email": "user@example.com",
        "total_searches_left": 500,
        "plan_searches_left": 500,
    }


@app.get("/status")
def status_feed():
    return {
        "status": {"indicator": "none", "description": "All Systems Operational"},
        "incidents": [],
    }


@app.api_route("/orders", methods=["GET", "POST"])
async def orders(
    request: Request,
    response: Response,
    x_fault_delay: float | None = Header(default=None),
    x_fault_status: int | None = Header(default=None),
    x_fault_commit_write: str | None = Header(default="false"),
    authorization: str | None = Header(default=None),
    idempotency_key: str | None = Header(default=None),
):
    if authorization == "Bearer expired_key":
        raise HTTPException(status_code=401, detail="Token expired")
    if authorization == "Bearer read_only_key" and request.method == "POST":
        raise HTTPException(status_code=403, detail="Missing write permissions")

    order_id = str(uuid.uuid4())
    should_commit = x_fault_commit_write and x_fault_commit_write.lower() == "true"

    if should_commit and request.method == "POST":
        COMMITTED_ORDERS[order_id] = {
            "id": order_id,
            "created_at": time.time(),
            "idempotency_key": idempotency_key,
        }

    if x_fault_delay and x_fault_delay > 0:
        await asyncio.sleep(x_fault_delay)

    if x_fault_status:
        if x_fault_status == 429:
            return JSONResponse(
                status_code=429,
                content={"error": {"type": "tokens", "message": "Rate limit exceeded"}},
                headers={"X-Request-Id": f"req_{uuid.uuid4().hex[:8]}"},
            )
        if x_fault_status == 500:
            return JSONResponse(
                status_code=500,
                content={"error": "InternalServerError", "message": "Backend engine crash"},
                headers={"X-Request-Id": f"req_{uuid.uuid4().hex[:8]}"},
            )
        raise HTTPException(status_code=x_fault_status, detail=f"Injected status {x_fault_status}")

    response.headers["X-Request-Id"] = f"req_{uuid.uuid4().hex[:8]}"
    return {
        "id": order_id,
        "status": "created" if request.method == "POST" else "list",
        "orders": list(COMMITTED_ORDERS.values()),
    }
