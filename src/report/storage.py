"""Scan result persistence for historical comparison.

Saves and loads scan results as JSON files for comparing between scans
to identify new and fixed issues.
"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Optional

REPORTS_DIR = Path("reports")
RETENTION_DAYS = 7


def get_scan_history_path(environment: str) -> Path:
    """Get the directory path for scan history files.
    
    Args:
        environment: "staging" or "prod"
    
    Returns:
        Path to the environment's scan history directory
    """
    return REPORTS_DIR / environment


def save_scan(environment: str, scan_data: dict) -> Path:
    """Save scan results to JSON file.
    
    Args:
        environment: "staging" or "prod"
        scan_data: Complete scan data dict
    
    Returns:
        Path to saved file
    """
    # Get the directory path
    env_dir = get_scan_history_path(environment)
    
    # Create directory if it doesn't exist
    env_dir.mkdir(parents=True, exist_ok=True)
    
    # Generate timestamped filename
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"scan_{timestamp}.json"
    filepath = env_dir / filename
    
    # Write the JSON file
    with open(filepath, "w") as f:
        json.dump(scan_data, f, indent=2)
    
    return filepath


def load_latest_scan(environment: str) -> Optional[dict]:
    """Load the most recent scan result for an environment.
    
    Args:
        environment: "staging" or "prod"
    
    Returns:
        Scan data dict or None if no previous scan exists
    """
    env_dir = get_scan_history_path(environment)
    
    # Check if directory exists
    if not env_dir.exists():
        return None
    
    # Find all scan_*.json files
    scan_files = sorted(env_dir.glob("scan_*.json"))
    
    # No files found
    if not scan_files:
        return None
    
    # Get the most recent file (last in sorted list, since filenames are timestamped)
    latest_file = scan_files[-1]
    
    # Load and return the JSON data
    try:
        with open(latest_file) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None
