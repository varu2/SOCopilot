import json
from pathlib import Path

# Finds the data folder relative to this file, so it works from any directory
DATA_DIR = Path(__file__).resolve().parent.parent / "data"


def _load(filename):
    with open(DATA_DIR / filename, encoding="utf-8") as f:
        return json.load(f)


def load_alerts():
    return _load("alerts.json")


def load_lookups():
    return {
        "users": _load("users.json"),
        "assets": _load("assets.json"),
        "ips": _load("ip_reputation.json"),
    }


def enrich_alert(alert, lookups):
    """Attach user, asset and source-IP context to one alert."""
    return {
        "alert": alert,
        "user_context": lookups["users"].get(
            alert["username"], {"note": "No record for this user"}
        ),
        "asset_context": lookups["assets"].get(
            alert["destination_host"], {"note": "No record for this asset"}
        ),
        "source_ip_context": lookups["ips"].get(
            alert["source_ip"], {"reputation": "unknown", "note": "No record for this IP"}
        ),
    }


if __name__ == "__main__":
    alerts = load_alerts()
    lookups = load_lookups()
    print(f"Loaded {len(alerts)} alerts\n")
    print(json.dumps(enrich_alert(alerts[1], lookups), indent=2))