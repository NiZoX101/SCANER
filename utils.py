import json
import os

def save_last_scan(session, filename="last_scan.json"):
    try:
        with open(filename, "w") as f:
            json.dump(session, f, indent=4)
    except Exception as e:
        print(f"Error saving session: {e}")

def load_last_scan(filename="last_scan.json"):
    if os.path.exists(filename):
        try:
            with open(filename, "r") as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading session: {e}")
    return None
