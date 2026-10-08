#!/usr/bin/env python3
"""
Mock Target Server
"""

from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict
from urllib.parse import urlparse


_MOCK_USERS: Dict[str, Dict[str, Any]] = {
    "1001": {"id": "1001", "owner": "alice", "email": "alice@example.com", "balance": 50000.0, "ssn": "111-22-1001"},
    "1002": {"id": "1002", "owner": "bob", "email": "bob@example.com", "balance": 120.0, "ssn": "222-33-1002"},
    "1003": {"id": "1003", "owner": "charlie", "email": "charlie@example.com", "balance": 9999.0, "ssn": "333-44-1003"},
}

_MOCK_ORDERS: Dict[str, Dict[str, Any]] = {
    "ord-1001": {"id": "ord-1001", "owner": "alice", "amount": 99.99, "items": ["item-a", "item-b"]},
    "ord-1002": {"id": "ord-1002", "owner": "bob", "amount": 149.50, "items": ["item-c"]},
    "ord-1003": {"id": "ord-1003", "owner": "charlie", "amount": 299.00, "items": ["item-d", "item-e"]},
}

_MOCK_ACCOUNTS: Dict[str, Dict[str, Any]] = {
    "acc-1001": {"id": "acc-1001", "owner": "alice", "type": "checking", "balance": 50000.0, "currency": "USD"},
    "acc-1002": {"id": "acc-1002", "owner": "bob", "type": "savings", "balance": 120.0, "currency": "USD"},
    "acc-1003": {"id": "acc-1003", "owner": "charlie", "type": "investment", "balance": 9999.0, "currency": "USD"},
}

_SECURE_RESOURCES: Dict[str, Dict[str, Any]] = {
    "sec-1001": {"id": "sec-1001", "owner": "alice", "secret": "alice-secret-data"},
    "sec-1002": {"id": "sec-1002", "owner": "bob", "secret": "bob-secret-data"},
}


class MockTargetHandler(BaseHTTPRequestHandler):
    def log_message(self, *args: Any) -> None:
        return

    def _bearer(self) -> str:
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            return auth[len("Bearer "):]
        return ""

    def _json(self, status: int, body: Dict[str, Any]) -> None:
        payload = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _extract_id(self, path: str) -> str:
        return path.rsplit("/", 1)[-1]

    def do_GET(self) -> None:
        path = self.path.split("?")[0]
        token = self._bearer()

        if not token:
            self._json(401, {"error": "unauthorized"})
            return

        if path.startswith("/api/v1/users/"):
            user_id = self._extract_id(path)
            if user_id in _MOCK_USERS:
                self._json(200, _MOCK_USERS[user_id])
                return
            self._json(404, {"error": "no such user"})
            return

        if path.startswith("/api/v1/orders/"):
            order_id = self._extract_id(path)
            if order_id in _MOCK_ORDERS:
                self._json(200, _MOCK_ORDERS[order_id])
                return
            self._json(404, {"error": "no such order"})
            return

        if path.startswith("/api/v1/accounts/"):
            acc_id = self._extract_id(path)
            if acc_id in _MOCK_ACCOUNTS:
                self._json(200, _MOCK_ACCOUNTS[acc_id])
                return
            self._json(404, {"error": "no such account"})
            return

        if path.startswith("/api/v1/secure/"):
            resource_id = self._extract_id(path)
            record = _SECURE_RESOURCES.get(resource_id)
            if record is None:
                self._json(404, {"error": "not found"})
                return
            expected_owner = record["owner"]
            if token == f"token-{expected_owner}":
                self._json(200, record)
            else:
                self._json(404, {"error": "not found"})
            return

        if path == "/health":
            self._json(200, {"status": "ok", "service": "mock-target"})
            return

        self._json(404, {"error": "not found"})

    def do_POST(self) -> None:
        path = self.path.split("?")[0]
        token = self._bearer()

        if not token:
            self._json(401, {"error": "unauthorized"})
            return

        length = int(self.headers.get("Content-Length", "0") or 0)
        body = self.rfile.read(length) if length else b"{}"

        if path.startswith("/api/v1/accounts/"):
            acc_id = self._extract_id(path)
            if acc_id in _MOCK_ACCOUNTS:
                try:
                    update = json.loads(body.decode("utf-8") or "{}")
                except (json.JSONDecodeError, UnicodeDecodeError):
                    update = {}
                _MOCK_ACCOUNTS[acc_id].update(
                    {k: v for k, v in update.items() if k in ("balance", "owner", "type", "currency")}
                )
                self._json(200, {"updated": True, "account": _MOCK_ACCOUNTS[acc_id]})
                return
            self._json(404, {"error": "no such account"})
            return

        self._json(404, {"error": "not found"})

    def do_PUT(self) -> None:
        self.do_POST()

    def do_DELETE(self) -> None:
        path = self.path.split("?")[0]
        token = self._bearer()

        if not token:
            self._json(401, {"error": "unauthorized"})
            return

        if path.startswith("/api/v1/orders/"):
            order_id = self._extract_id(path)
            if order_id in _MOCK_ORDERS:
                deleted = _MOCK_ORDERS.pop(order_id)
                self._json(200, {"deleted": True, "order": deleted})
                return
            self._json(404, {"error": "no such order"})
            return

        self._json(404, {"error": "not found"})


def run_server(host: str = "0.0.0.0", port: int = 18099) -> None:
    server = HTTPServer((host, port), MockTargetHandler)
    print(f"[MOCK-TARGET] Starting on {host}:{port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[MOCK-TARGET] Shutting down...", flush=True)
    finally:
        server.server_close()


if __name__ == "__main__":
    run_server()
