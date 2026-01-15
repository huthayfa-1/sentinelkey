import os
import sys
import requests
import json
import argparse
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

def send_alert(secret_type, location, commit_hash=None):
    webhook_url = os.getenv("DISCORD_WEBHOOK_URL")
    if not webhook_url:
        print("Error: DISCORD_WEBHOOK_URL environment variable not set.")
        return

    description = f"**Type:** {secret_type}\n**Location:** {location}"
    if commit_hash:
        description += f"\n**Commit:** {commit_hash}"
    description += "\n**Action:** Revoke this key immediately!"

    payload = {
        "content": "🚨 **CRITICAL: API Key Exposure Detected!**",
        "embeds": [
            {
                "title": "Secret Leak Details",
                "description": description,
                "color": 16711680  # Red
            }
        ]
    }

    try:
        response = requests.post(webhook_url, json=payload)
        response.raise_for_status()
        print("Alert sent successfully.")
    except requests.exceptions.RequestException as e:
        print(f"Failed to send alert: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Send security alerts to Discord.")
    parser.add_argument("--ci", action="store_true", help="Run in CI mode (simulated data for now)")
    args = parser.parse_args()

    if args.ci:
        # In a real CI environment, you would parse TruffleHog's JSON output.
        # For this demonstration, we are alerting that a leak was found during the scan.
        send_alert("Potential Secret Found (CI Scan)", "See GitHub Action Logs")
    else:
        # Testing mode
        send_alert("Test Secret", "Local Environment")
