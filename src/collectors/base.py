"""Base utilities for collectors."""

import json
import os
from datetime import datetime
from pathlib import Path


def get_reports_dir() -> Path:
    """Get the reports directory path."""
    project_root = Path(__file__).resolve().parent.parent.parent
    return project_root / "reports"


def save_report(source: str, domain: str, data: dict) -> Path:
    """Save a collector report as JSON.
    
    Args:
        source: Collector name (http, github, sentry, codacy, websentry)
        domain: Domain being scanned (waldo.click or waldoclick.dev)
        data: Report data to save
        
    Returns:
        Path to saved file
    """
    # Determine environment from domain
    env = "prod" if domain == "waldo.click" else "staging"
    
    # Create directory structure: reports/{source}/{env}/
    reports_dir = get_reports_dir() / source / env
    reports_dir.mkdir(parents=True, exist_ok=True)
    
    # Generate filename with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{source}_{timestamp}.json"
    filepath = reports_dir / filename
    
    # Add metadata
    data["_meta"] = {
        "source": source,
        "domain": domain,
        "environment": env,
        "scanned_at": datetime.now().isoformat(),
        "timestamp": timestamp,
    }
    
    # Save
    with open(filepath, "w") as f:
        json.dump(data, f, indent=2, default=str)
    
    return filepath


def get_latest_report(source: str, env: str) -> dict | None:
    """Get the most recent report for a source.
    
    Args:
        source: Collector name
        env: Environment (prod or staging)
        
    Returns:
        Report data or None if not found
    """
    reports_dir = get_reports_dir() / source / env
    
    if not reports_dir.exists():
        return None
    
    # Find most recent file
    files = sorted(reports_dir.glob(f"{source}_*.json"), reverse=True)
    
    if not files:
        return None
    
    with open(files[0]) as f:
        return json.load(f)


def get_all_latest_reports(env: str) -> dict[str, dict]:
    """Get latest reports from all sources.
    
    Args:
        env: Environment (prod or staging)
        
    Returns:
        Dict mapping source name to report data
    """
    sources = ["http", "github", "sentry", "codacy", "websentry"]
    reports = {}
    
    for source in sources:
        report = get_latest_report(source, env)
        if report:
            reports[source] = report
    
    return reports
