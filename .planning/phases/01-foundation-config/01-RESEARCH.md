# Phase 1: Foundation & Config - Research

**Researched:** 2026-03-16
**Domain:** Python configuration management, environment variables, CLI argument parsing
**Confidence:** HIGH

## Summary

Phase 1 establishes the configuration foundation for the waldo-shield monitoring system. The primary challenge is loading environment-specific configuration (staging vs production) while keeping API tokens secure. This is a well-understood domain with established patterns.

The existing scanner (`src/scanner.py`) provides a solid foundation: it uses `argparse` for CLI, follows modular design, and outputs JSON. The new monitor script will follow similar patterns but add environment awareness and externalized configuration.

**Primary recommendation:** Use `python-dotenv` for .env file loading combined with `os.environ` access. Structure configuration as a Python module with dataclasses for type safety. Support `--env` flag for environment selection.

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| CONF-01 | System loads environment-specific config (staging vs prod targets, recipients, thresholds) | python-dotenv + config module pattern with environment-keyed dictionaries |
| CONF-02 | API tokens read from environment variables, never hardcoded | python-dotenv `load_dotenv()` + `os.environ.get()` with explicit validation |
</phase_requirements>

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `python-dotenv` | `>=1.2.2` | Load .env files into environment | Industry standard for 12-factor apps. 7K+ stars, actively maintained. Compatible with Laravel Forge env var injection. |
| `argparse` | stdlib | CLI argument parsing | Built-in, no dependencies. Already used by existing scanner.py |
| `dataclasses` | stdlib | Type-safe configuration objects | Built-in since Python 3.7. Clean syntax, type hints, immutability option. |
| `os` | stdlib | Environment variable access | Standard `os.environ` and `os.getenv()` |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `typing` | stdlib | Type annotations | For config dataclass type hints |
| `pathlib` | stdlib | Path handling | For .env file path resolution |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| `python-dotenv` | `python-decouple` | decouple adds casting and defaults, but more opinionated. dotenv is simpler, more widely used. |
| `python-dotenv` | `dynaconf` | dynaconf is full config management, overkill for this use case |
| dataclasses | dict | dict lacks type safety, IDE autocomplete, validation |
| dataclasses | pydantic | pydantic adds validation but is a heavy dependency for simple config |

**Installation:**
```bash
pip install python-dotenv>=1.2.2
```

## Architecture Patterns

### Recommended Project Structure
```
src/
├── monitor.py           # Main entry point (new)
├── scanner.py           # Existing scanner
├── config/              # Configuration module (new)
│   ├── __init__.py     # Exports Config class
│   ├── settings.py     # Environment definitions
│   └── loader.py       # .env loading logic
└── modules/             # Existing analysis modules
```

### Pattern 1: Environment-Keyed Configuration
**What:** Define all environment-specific values (targets, recipients, thresholds) in a dictionary keyed by environment name.
**When to use:** When you have a fixed set of known environments (staging, prod).
**Example:**
```python
# Source: Project-specific pattern based on requirements
from dataclasses import dataclass
from typing import List

@dataclass(frozen=True)
class EnvironmentConfig:
    """Configuration for a specific environment."""
    name: str
    targets: List[str]
    recipients: List[str]
    mailgun_domain: str

ENVIRONMENTS = {
    "staging": EnvironmentConfig(
        name="staging",
        targets=[
            "https://api.waldoclick.dev",
            "https://dashboard.waldoclick.dev",
            "https://www.waldoclick.dev",
        ],
        recipients=["security@waldoclick.dev"],
        mailgun_domain="waldoclick.dev",
    ),
    "prod": EnvironmentConfig(
        name="prod",
        targets=[
            "https://api.waldo.click",
            "https://dashboard.waldo.click",
            "https://www.waldo.click",
        ],
        recipients=["security@waldo.click"],
        mailgun_domain="waldo.click",
    ),
}
```

### Pattern 2: Secret Loading with Validation
**What:** Load secrets from environment variables with explicit validation and clear error messages.
**When to use:** Always for API tokens and credentials.
**Example:**
```python
# Source: python-dotenv official docs + 12-factor best practices
import os
from dotenv import load_dotenv

def load_secrets() -> dict:
    """Load and validate required secrets from environment."""
    load_dotenv()  # Load .env file if present, doesn't override existing env vars
    
    required = [
        "CLOUDFLARE_API_TOKEN",
        "MAILGUN_API_KEY",
    ]
    
    secrets = {}
    missing = []
    
    for key in required:
        value = os.environ.get(key)
        if not value:
            missing.append(key)
        else:
            secrets[key] = value
    
    if missing:
        raise EnvironmentError(
            f"Missing required environment variables: {', '.join(missing)}\n"
            f"Set them in .env file or environment."
        )
    
    return secrets
```

### Pattern 3: CLI with Environment Selection
**What:** Use argparse with --env flag that maps to predefined environments.
**When to use:** For the main entry point script.
**Example:**
```python
# Source: Based on existing scanner.py pattern
import argparse

def parse_args():
    parser = argparse.ArgumentParser(
        description="Security monitor for waldo.click infrastructure"
    )
    parser.add_argument(
        "--env", "-e",
        choices=["staging", "prod"],
        required=True,
        help="Environment to monitor (staging or prod)"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Run checks but don't send email"
    )
    return parser.parse_args()
```

### Anti-Patterns to Avoid
- **Hardcoded secrets:** Never put API keys in code, even in "example" form
- **Config in code comments:** Comments get committed; use .env.example instead
- **Mutable config objects:** Use `frozen=True` dataclasses to prevent accidental mutation
- **Silent fallbacks:** Don't default to empty string for required secrets; fail loudly
- **Logging secrets:** Never log API tokens, even at debug level

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| .env file parsing | Custom parser | `python-dotenv` | Handles edge cases: quotes, escapes, comments, variable expansion |
| CLI argument parsing | Manual sys.argv parsing | `argparse` | Type conversion, help text, validation, error handling |
| Environment validation | Ad-hoc checks | Explicit validation function | Consistent error messages, early failure |

**Key insight:** Environment variable loading seems simple but has edge cases (quoted values, comments, multiline, variable expansion). python-dotenv handles all of these correctly.

## Common Pitfalls

### Pitfall 1: .env Loaded After Code Reads Environment
**What goes wrong:** Code reads `os.environ` before `load_dotenv()` is called.
**Why it happens:** Import-time configuration, global variables initialized at module load.
**How to avoid:** Call `load_dotenv()` at the very start of main(), before any config reading.
**Warning signs:** Config works with env vars but not .env file.

### Pitfall 2: .env File Committed to Git
**What goes wrong:** Secrets end up in repository history, visible to anyone with access.
**Why it happens:** Developer creates .env, forgets to add to .gitignore.
**How to avoid:** .gitignore already has `.env`. Create `.env.example` with placeholder values for documentation.
**Warning signs:** git status shows .env as untracked (should be ignored).

### Pitfall 3: Override Behavior Confusion
**What goes wrong:** .env values don't take effect because env var already set.
**Why it happens:** `load_dotenv()` defaults to `override=False`.
**How to avoid:** For production, this is correct (env vars from Forge take precedence). Document this behavior.
**Warning signs:** Works in Forge but not local dev, or vice versa.

### Pitfall 4: Missing Secrets Cause Runtime Errors
**What goes wrong:** Script starts, runs for minutes, then fails when trying to send email.
**Why it happens:** Secrets loaded lazily when first used.
**How to avoid:** Validate all required secrets at startup, fail fast.
**Warning signs:** Partial execution before failure.

### Pitfall 5: Relative .env Path Issues
**What goes wrong:** .env not found when script run from different directory.
**Why it happens:** `load_dotenv()` looks relative to script location by default.
**How to avoid:** Use `find_dotenv()` or explicit path based on `__file__`.
**Warning signs:** Works from project root but fails from cron.

## Code Examples

Verified patterns from official sources:

### Loading .env with Explicit Path
```python
# Source: python-dotenv README
from pathlib import Path
from dotenv import load_dotenv

# Get the directory containing this script
BASE_DIR = Path(__file__).resolve().parent.parent

# Load .env from project root
env_path = BASE_DIR / ".env"
load_dotenv(dotenv_path=env_path)
```

### Safe Environment Variable Access
```python
# Source: python-dotenv documentation
import os
from dotenv import load_dotenv

load_dotenv()

# Required variable - will raise KeyError if not set
api_token = os.environ["CLOUDFLARE_API_TOKEN"]

# Optional variable with default
log_level = os.environ.get("LOG_LEVEL", "INFO")
```

### Complete Config Module Example
```python
# Source: Composite pattern from python-dotenv docs + dataclasses
# File: src/config/__init__.py
from dataclasses import dataclass
from typing import List
import os
from pathlib import Path
from dotenv import load_dotenv

@dataclass(frozen=True)
class Config:
    """Application configuration."""
    environment: str
    targets: List[str]
    recipients: List[str]
    cloudflare_token: str
    mailgun_api_key: str
    mailgun_domain: str
    
    @classmethod
    def load(cls, env_name: str) -> "Config":
        """Load configuration for specified environment."""
        # Load .env file
        project_root = Path(__file__).resolve().parent.parent.parent
        load_dotenv(project_root / ".env")
        
        # Environment-specific settings
        env_settings = _get_env_settings(env_name)
        
        # Load secrets with validation
        cloudflare_token = os.environ.get("CLOUDFLARE_API_TOKEN")
        mailgun_key = os.environ.get("MAILGUN_API_KEY")
        
        if not cloudflare_token:
            raise EnvironmentError("CLOUDFLARE_API_TOKEN not set")
        if not mailgun_key:
            raise EnvironmentError("MAILGUN_API_KEY not set")
        
        return cls(
            environment=env_name,
            targets=env_settings["targets"],
            recipients=env_settings["recipients"],
            cloudflare_token=cloudflare_token,
            mailgun_api_key=mailgun_key,
            mailgun_domain=env_settings["mailgun_domain"],
        )

def _get_env_settings(env_name: str) -> dict:
    """Get environment-specific (non-secret) settings."""
    settings = {
        "staging": {
            "targets": [
                "https://api.waldoclick.dev",
                "https://dashboard.waldoclick.dev", 
                "https://www.waldoclick.dev",
            ],
            "recipients": ["security@waldoclick.dev"],
            "mailgun_domain": "waldoclick.dev",
        },
        "prod": {
            "targets": [
                "https://api.waldo.click",
                "https://dashboard.waldo.click",
                "https://www.waldo.click",
            ],
            "recipients": ["security@waldo.click"],
            "mailgun_domain": "waldo.click",
        },
    }
    
    if env_name not in settings:
        raise ValueError(f"Unknown environment: {env_name}. Use: staging, prod")
    
    return settings[env_name]
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Config files (INI, YAML) | Environment variables | 12-factor principles (~2012) | Simplifies deployment, separates code from config |
| Global config dicts | Dataclasses with typing | Python 3.7+ (2018) | Type safety, IDE support, immutability |
| Manual .env parsing | python-dotenv | Package matured ~2020 | Handles edge cases, widely adopted |

**Deprecated/outdated:**
- `ConfigParser` for secrets: Still works, but env vars are preferred for secrets
- `python-decouple`: Still maintained, but python-dotenv is more widely used

## Open Questions

1. **Recipients List Source**
   - What we know: Need different recipients for staging vs prod
   - What's unclear: Should recipients also come from env var (more flexible) or stay hardcoded in settings?
   - Recommendation: Hardcode in settings.py for v1, can move to env var if needed later

2. **Thresholds Definition**
   - What we know: CONF-01 mentions thresholds for staging vs prod
   - What's unclear: What thresholds? Risk score? Issue count? These aren't defined yet.
   - Recommendation: Plan for threshold config structure, defer values to implementation

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | pytest (not yet installed) |
| Config file | none - Wave 0 |
| Quick run command | `pytest tests/test_config.py -x` |
| Full suite command | `pytest tests/ -v` |

### Phase Requirements to Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| CONF-01 | Load staging config with correct targets | unit | `pytest tests/test_config.py::test_staging_config -x` | Wave 0 |
| CONF-01 | Load prod config with correct targets | unit | `pytest tests/test_config.py::test_prod_config -x` | Wave 0 |
| CONF-01 | Reject unknown environment name | unit | `pytest tests/test_config.py::test_invalid_env -x` | Wave 0 |
| CONF-02 | Load secrets from environment variables | unit | `pytest tests/test_config.py::test_secrets_from_env -x` | Wave 0 |
| CONF-02 | Fail fast when required secret missing | unit | `pytest tests/test_config.py::test_missing_secret_error -x` | Wave 0 |
| CONF-02 | Never log or expose secret values | manual | Code review | N/A |

### Sampling Rate
- **Per task commit:** `pytest tests/test_config.py -x`
- **Per wave merge:** `pytest tests/ -v`
- **Phase gate:** Full suite green before `/gsd-verify-work`

### Wave 0 Gaps
- [ ] `tests/test_config.py` - covers CONF-01, CONF-02
- [ ] `tests/conftest.py` - fixtures for env var mocking
- [ ] `pytest` dependency in requirements.txt (dev dependency)
- [ ] Framework install: `pip install pytest>=8.0`

## Sources

### Primary (HIGH confidence)
- https://github.com/theskumar/python-dotenv - Official README, API documentation
- https://pypi.org/project/python-dotenv/ - Package info, changelog, version 1.2.2
- Python stdlib documentation - argparse, dataclasses, os.environ

### Secondary (MEDIUM confidence)
- 12-factor.net - Environment variable configuration principles
- Existing scanner.py in codebase - Established project patterns

### Tertiary (LOW confidence)
- None - all findings verified with primary sources

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH - python-dotenv is well-documented, widely used
- Architecture: HIGH - Patterns based on official docs and existing codebase
- Pitfalls: HIGH - Common issues documented in python-dotenv issues/docs

**Research date:** 2026-03-16
**Valid until:** 2026-04-16 (30 days - stable domain)
