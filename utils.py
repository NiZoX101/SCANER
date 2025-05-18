import json
import os
from typing import Dict, Any, Optional

def save_last_scan(session: Dict[str, Any]) -> None:
    """
    Save the scan session data to a JSON file.
    
    Args:
        session: Dictionary containing scan session data.
    """
    try:
        with open('last_scan.json', 'w', encoding='utf-8') as f:
            json.dump(session, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f"Failed to save last scan: {e}")

def load_last_scan() -> Optional[Dict[str, Any]]:
    """
    Load the last scan session data from a JSON file.
    
    Returns:
        Dictionary with session data or None if file doesn't exist or is invalid.
    """
    try:
        if os.path.exists('last_scan.json'):
            with open('last_scan.json', 'r', encoding='utf-8') as f:
                return json.load(f)
        return None
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Failed to load last scan: {e}")
        return None
