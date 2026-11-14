from __future__ import annotations

import asyncio
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).parent.parent))
import main

LIMIT = main.MAX_BODY_BYTES


def _client() -> TestClient:
    return TestClient(main.app, client=("192.168.99.90", 50000))


def test_declared_oversized_body_rejected() -> None:
    resp = _client().post("/api/auth/login", content=b"x" * (LIMIT + 1), headers={"Content-Type": "application/json"})
    assert resp.status_code == 413
    assert resp.json()["detail"] == "İstek gövdesi çok büyük."


def test_chunked_oversized_body_rejected() -> None:
    def chunks() -> Iterator[bytes]:
        for _ in range(3):
            yield b"x" * (LIMIT // 2)

    resp = _client().post("/api/servers/heartbeat", content=chunks(), headers={"Content-Type": "application/json"})
    assert resp.status_code == 413


def test_body_at_limit_not_rejected_by_middleware() -> None:
    resp = _client().post("/api/auth/login", content=b"x" * LIMIT, headers={"Content-Type": "application/json"})
    assert resp.status_code != 413


def _run(content_length: bytes | None, chunks: list[bytes]) -> tuple[int, int]:
    read = 0

    async def app(scope: Any, receive: Any, send: Any) -> None:
        nonlocal read
        while True:
            msg = await receive()
            read += len(msg.get("body", b""))
            if not msg.get("more_body"):
                break
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    messages = [{"type": "http.request", "body": c, "more_body": i < len(chunks) - 1} for i, c in enumerate(chunks)]
    sent: list[dict[str, Any]] = []

    async def receive() -> dict[str, Any]:
        return messages.pop(0)

    async def send(msg: dict[str, Any]) -> None:
        sent.append(msg)

    headers = [(b"content-length", content_length)] if content_length is not None else []
    scope = {"type": "http", "method": "POST", "path": "/x", "headers": headers}
    asyncio.run(main.BodySizeLimitMiddleware(app, max_bytes=10)(scope, receive, send))
    return sent[0]["status"], read


def test_lying_content_length_cut_by_bytes_read() -> None:
    assert _run(b"5", [b"x" * 8, b"x" * 8, b"x" * 8]) == (413, 8)


def test_invalid_content_length_cut_by_bytes_read() -> None:
    assert _run(b"abc", [b"x" * 6, b"x" * 6])[0] == 413


def test_small_body_passes() -> None:
    assert _run(b"6", [b"x" * 6]) == (200, 6)
    assert _run(None, [b"x" * 4, b"x" * 6]) == (200, 10)
