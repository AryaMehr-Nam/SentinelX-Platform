# Contributing to SentinelX

Thank you for your interest in contributing to SentinelX! This guide will help you get started.

## Development Setup

### Prerequisites

- Python 3.13+
- Node.js 22+
- Docker & Docker Compose
- Git

### Local Development

```bash
# Clone the repo
git clone https://github.com/sentinelx/sentinelx.git
cd sentinelx

# API setup
cd api
python -m venv .venv
source .venv/bin/activate  # or .venv\Scripts\activate on Windows
pip install -r requirements.txt

# Dashboard setup
cd ../dashboard
npm install
npm run dev

# Run infrastructure
docker compose up -d postgres redis elasticsearch
```

### Running Tests

```bash
# API tests
python -m pytest api/tests/ -v --cov=api

# TypeScript type checking
cd dashboard
npx tsc --noEmit

# Linting
ruff check api/ waf/
```

## Code Style

### Python
- **Formatter**: Ruff
- **Type hints**: Required for all function signatures
- **Async**: Use `async/await` for all I/O operations
- **Docstrings**: Google-style for all public functions

### TypeScript/React
- **Strict mode**: Enabled
- **Functional components**: React hooks only (no class components)
- **State management**: Zustand for client state, TanStack Query for server state

## Adding WAF Rules

WAF rules use a Sigma-like YAML format. To add a new rule:

1. Create or edit a file in `waf/rules/`
2. Follow the existing format:

```yaml
rules:
  - id: "CATEGORY-NNN"
    name: "Descriptive Name"
    category: "category_id"
    severity: "low|medium|high|critical"
    action: "block|log|challenge"
    priority: 10  # Lower = higher priority
    conditions:
      match_type: "regex|exact|contains"
      targets: ["query_params", "body", "path", "headers"]
      patterns:
        - "(?i)(your regex pattern)"
```

3. Add tests in `api/tests/test_core.py`

## Pull Request Process

1. Fork the repository
2. Create a feature branch from `main`
3. Make your changes with clear, focused commits
4. Ensure all tests pass
5. Update documentation if needed
6. Submit a PR with a clear description

### PR Title Format

```
feat: Add new detection rule for SSRF
fix: Correct rate limiter window calculation
docs: Update API authentication guide
refactor: Extract common middleware logic
test: Add integration tests for WAF pipeline
```

## Architecture Decisions

When making architectural changes, consider:

- **WAF middleware must be non-blocking** — never perform synchronous I/O
- **AI analysis is always async** — dispatched via Celery, never in HTTP path
- **Elasticsearch is optional** — the system must function without it
- **Redis is critical** — rate limiting and IP management depend on it
- **Fail open, not closed** — WAF errors should never crash the application

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
