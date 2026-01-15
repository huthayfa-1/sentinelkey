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
    parser.add_argument("--ci", action="store_true", help="Run in CI mode")
    parser.add_argument("--input", help="Path to TruffleHog JSON output file")
    parser.add_argument("--repo-url", help="URL of the scanned repository for linking")
    args = parser.parse_args()

    if args.ci and args.input:
        try:
            with open(args.input, 'r') as f:
                for line in f:
                    if not line.strip():
                        continue
                    try:
                        finding = json.loads(line)
                        
                        # Check if this is a finding (has DetectorName) or just a log message
                        if 'DetectorName' not in finding:
                            continue

                        # Extract details
                        secret_type = finding.get('DetectorName', 'Unknown Secret')
                        raw_secret = finding.get('Raw', 'REDACTED')
                        
                        # Extract Git metadata
                        source_meta = finding.get('SourceMetadata', {}).get('Data', {}).get('Git', {})
                        file_path = source_meta.get('file', 'Unknown File')
                        line_number = source_meta.get('line', 0)
                        commit_hash = source_meta.get('commit', None)
                        
                        # Format location with link if repo_url is known (heuristic)
                        location = f"`{file_path}:{line_number}`"
                        
                        description = f"**Type:** {secret_type}\n**File:** `{file_path}`\n**Line:** {line_number}"
                        if commit_hash:
                            description += f"\n**Commit:** `{commit_hash[:7]}`"
                        
                        description += f"\n**Secret:** `{raw_secret}`"
                        description += "\n\n⚠️ **Action:** Revoke this key immediately!"

                        # Send the alert
                        webhook_url = os.getenv("DISCORD_WEBHOOK_URL")
                        if not webhook_url:
                            print("Error: DISCORD_WEBHOOK_URL not set.")
                            continue

                        payload = {
                            "content": "🚨 **CRITICAL: Secret Detected!**",
                            "embeds": [{
                                "title": f"Exposed {secret_type}",
                                "description": description,
                                "color": 16711680
                            }]
                        }
                        
                        try:
                            response = requests.post(webhook_url, json=payload)
                            response.raise_for_status()
                            print(f"Alert sent for {secret_type} in {file_path}")
                        except Exception as e:
                            print(f"Failed to send alert: {e}")

                    except json.JSONDecodeError:
                        continue
        except FileNotFoundError:
            print(f"Error: Could not find results file: {args.input}")
    else:
        # Testing mode
        send_alert("Test Secret", "Local Environment")
