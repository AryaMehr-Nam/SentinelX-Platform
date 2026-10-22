"""
SentinelX — Real-Time WebSocket & Simulator Tests
"""

import pytest
from httpx import ASGITransport, AsyncClient

from api.main import create_app


@pytest.mark.asyncio
async def test_attack_simulator_controls():
    """Test start, status, and stop endpoints of the attack traffic simulator."""
    app = create_app()
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Check initial status
        res = await client.get("/api/v1/simulator/status")
        assert res.status_code == 200
        data = res.json()
        assert "running" in data
        assert "events_generated" in data

        # Start simulator
        res_start = await client.post("/api/v1/simulator/start?interval=1.0")
        assert res_start.status_code == 200
        assert res_start.json()["status"] == "running"

        # Stop simulator
        res_stop = await client.post("/api/v1/simulator/stop")
        assert res_stop.status_code == 200
        assert res_stop.json()["status"] == "stopped"
