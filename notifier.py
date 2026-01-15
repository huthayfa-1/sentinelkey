import os
import sys
import requests
import argparse
from dotenv import load_dotenv

load_dotenv()

def send_alert(title, content):
    webhook_url = os.getenv("DISCORD_WEBHOOK_URL")
    if not webhook_url:
        print("Error: DISCORD_WEBHOOK_URL environment variable not set.")
        return False

    # Discord has a 2000 char limit for content, 4096 for embed description
    # Truncate if needed
    if len(content) > 4000:
        content = content[:4000] + "\n... (truncated)"

    payload = {
        "content": "🚨 **CRITICAL: Secret Detected!**",
        "embeds": [{
            "title": title,
            "description": f"```\n{content}\n```",
            "color": 16711680  # Red
        }]
    }

    try:
        response = requests.post(webhook_url, json=payload)
        response.raise_for_status()
        print("Alert sent successfully.")
        return True
    except requests.exceptions.RequestException as e:
        print(f"Failed to send alert: {e}")
        return False

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Send security alerts to Discord.")
    parser.add_argument("--ci", action="store_true", help="Run in CI mode")
    parser.add_argument("--input", help="Path to TruffleHog output file")
    args = parser.parse_args()

    if args.ci and args.input:
        try:
            with open(args.input, 'r') as f:
                raw_output = f.read().strip()
            
            if raw_output:
                send_alert("TruffleHog Scan Results", raw_output)
            else:
                print("No secrets found in scan output.")
        except FileNotFoundError:
            print(f"Error: Could not find results file: {args.input}")
    else:
        # Testing mode
        send_alert("Test Alert", "This is a test notification.")
