#!/usr/bin/env bash
# SentinelX — Production Deployment Script
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "╔═══════════════════════════════════════════╗"
echo "║      SentinelX — Production Deploy        ║"
echo "╚═══════════════════════════════════════════╝"
echo ""

# ──── Pre-flight Checks ────

echo "▶ Running pre-flight checks..."

if ! command -v docker &> /dev/null; then
    echo "✗ Docker is not installed"
    exit 1
fi

if ! command -v docker compose &> /dev/null; then
    echo "✗ Docker Compose is not installed"
    exit 1
fi

if [ ! -f "$PROJECT_ROOT/.env" ]; then
    echo "✗ .env file not found"
    echo "  Run: cp .env.example .env && edit .env with your settings"
    exit 1
fi

echo "✓ All pre-flight checks passed"
echo ""

# ──── Build & Deploy ────

echo "▶ Pulling latest images..."
cd "$PROJECT_ROOT"
docker compose pull 2>/dev/null || true

echo ""
echo "▶ Building containers..."
docker compose build --no-cache

echo ""
echo "▶ Starting services..."
docker compose up -d

echo ""
echo "▶ Waiting for services to be healthy..."
sleep 5

# Health check
for i in {1..30}; do
    if curl -sf http://localhost:8000/api/v1/health > /dev/null 2>&1; then
        echo "✓ API is healthy"
        break
    fi
    if [ $i -eq 30 ]; then
        echo "✗ API health check failed after 30 attempts"
        docker compose logs api --tail 50
        exit 1
    fi
    sleep 2
done

echo ""
echo "▶ Running database migrations..."
docker compose exec -T api alembic upgrade head 2>/dev/null || echo "  (Alembic not configured yet — using auto-create)"

echo ""
echo "╔═══════════════════════════════════════════╗"
echo "║          Deployment Complete! ✓            ║"
echo "╠═══════════════════════════════════════════╣"
echo "║  API:       http://localhost:8000          ║"
echo "║  Dashboard: http://localhost:3000          ║"
echo "║  Swagger:   http://localhost:8000/docs     ║"
echo "║  Redis:     localhost:6379                 ║"
echo "║  Postgres:  localhost:5432                 ║"
echo "╚═══════════════════════════════════════════╝"
echo ""
echo "Logs: docker compose logs -f"
echo "Stop: docker compose down"
