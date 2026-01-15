# SentinelKey

**Cloud API Key Exposure Prevention and Monitoring System**

SentinelKey is a "Zero Trust" security tool designed to prevent API key leaks during development and monitor repositories for exposures in real-time.

## Features

- **Local Prevention**: Uses `pre-commit` and `detect-secrets` to block commits containing secrets.
- **CI/CD Monitoring**: Runs `TruffleHog` scans on every push and pull request via GitHub Actions.
- **Real-time Alerting**: Sends critical security alerts to a Discord Webhook.

## Installation

1.  **Clone the repository:**
    ```bash
    git clone <repo-url>
    cd sentinelkey
    ```

2.  **Install Dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

3.  **Install Pre-commit Hooks:**
    ```bash
    pre-commit install
    ```

4.  **Configuration:**
    - Copy `.env.example` to `.env` and set your `DISCORD_WEBHOOK_URL`.

## Architecture

1.  **Prevention Layer**: Developers run `pre-commit` locally. High-entropy strings are blocked.
2.  **Monitoring Layer**: GitHub Actions runs `TruffleHog` to scan the codebase remotely.
3.  **Alerting Layer**: If a leak is detected, `notifier.py` triggers an alert to Discord.

## How to Respond to a Leak

1.  **Revoke**: Immediately revoke the exposed key in the provider's console (AWS, Google, etc.).
2.  **Rotate**: Generate a new key and update your environment variables.
3.  **Clean**: Rewrite git history if necessary (using BFG Repo-Cleaner or git-filter-repo) to remove the secret from history. **Warning:** This updates commit hashes.

## License

MIT
