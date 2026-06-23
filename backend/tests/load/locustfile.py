"""Locust load test for the SDPP API.

Simulates realistic user behaviour: login, dashboard polling, audit browsing,
encrypted upload, and download. Includes a staged shape ramping 100 → 500 → 1000
concurrent users.

Run against a live server (TLS terminated at nginx or direct uvicorn):

    # headless, ramp via the built-in stages:
    locust -f tests/load/locustfile.py --host https://localhost --headless

    # or a fixed level:
    locust -f tests/load/locustfile.py --host http://localhost:8000 -u 500 -r 50 -t 2m --headless

Env:
    SDPP_LOAD_USER / SDPP_LOAD_PASSWORD  — credentials for the simulated users.
"""

from __future__ import annotations

import os

from locust import HttpUser, LoadTestShape, between, task

API = "/api/v1"
_PAYLOAD = os.urandom(64 * 1024)  # 64 KiB upload sample


class SDPPUser(HttpUser):
    wait_time = between(0.5, 2.0)

    def on_start(self) -> None:
        self.file_ids: list[str] = []
        username = os.getenv("SDPP_LOAD_USER", "admin")
        password = os.getenv("SDPP_LOAD_PASSWORD", "Adm1n-Str0ng-P@ss!")
        with self.client.post(
            f"{API}/auth/login",
            json={"identifier": username, "password": password},
            name="auth:login",
            catch_response=True,
        ) as resp:
            if resp.status_code == 200:
                self.client.headers.update(
                    {"Authorization": f"Bearer {resp.json()['access_token']}"}
                )
            else:
                resp.failure(f"login failed: {resp.status_code}")

    @task(6)
    def dashboard(self) -> None:
        self.client.get(f"{API}/security-dashboard", name="dashboard:read")

    @task(4)
    def audit_logs(self) -> None:
        self.client.get(f"{API}/audit-logs?limit=20", name="audit:list")

    @task(3)
    def upload(self) -> None:
        with self.client.post(
            f"{API}/files",
            files={"upload": ("load.bin", _PAYLOAD, "application/octet-stream")},
            data={"category": "document"},
            name="vault:upload",
            catch_response=True,
        ) as resp:
            if resp.status_code == 201:
                self.file_ids.append(resp.json()["file"]["id"])

    @task(3)
    def download(self) -> None:
        if self.file_ids:
            fid = self.file_ids[-1]
            self.client.get(f"{API}/files/{fid}/download", name="vault:download")

    @task(1)
    def verify_integrity(self) -> None:
        if self.file_ids:
            fid = self.file_ids[-1]
            self.client.post(f"{API}/files/{fid}/verify-integrity", name="integrity:verify")


class StagedRampShape(LoadTestShape):
    """Ramp through 100, 500, then 1000 users (60s each) for SLO measurement."""

    stages = [
        {"duration": 60, "users": 100, "spawn_rate": 20},
        {"duration": 120, "users": 500, "spawn_rate": 50},
        {"duration": 180, "users": 1000, "spawn_rate": 100},
    ]

    def tick(self):  # type: ignore[override]
        run_time = self.get_run_time()
        for stage in self.stages:
            if run_time < stage["duration"]:
                return stage["users"], stage["spawn_rate"]
        return None
