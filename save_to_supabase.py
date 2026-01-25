import os
import json
from datetime import datetime, timezone
from supabase import create_client, Client
from dotenv import load_dotenv

# Load env vars for local testing
load_dotenv()

def save_to_supabase():
    print("=" * 50)
    print("save_to_supabase.py - Starting...")
    print("=" * 50)
    
    url = os.environ.get("SUPABASE_URL")
    key = os.environ.get("SUPABASE_KEY")
    target_repo = os.environ.get("TARGET_REPO_URL", "Unknown")
    
    print(f"Target Repo: {target_repo}")
    print(f"Supabase URL configured: {'Yes' if url else 'No'}")
    print(f"Supabase Key configured: {'Yes' if key else 'No'}")
    
    if not url or not key:
        print("ERROR: Supabase credentials not found!")
        return
    
    try:
        supabase: Client = create_client(url, key)
        print("Supabase client created successfully")
    except Exception as e:
        print(f"ERROR creating Supabase client: {e}")
        return
    
    # Load results - handle all cases
    results = []
    status = "clean"  # Default: clean (no secrets)
    
    print("Checking for results.json...")
    if os.path.exists('results.json'):
        print("results.json found, reading...")
        try:
            with open('results.json', 'r') as f:
                content = f.read().strip()
                print(f"File content length: {len(content)} chars")
                if content:
                    parsed = json.loads(content)
                    if isinstance(parsed, list):
                        results = parsed
                        if len(results) > 0:
                            status = "secrets_found"
                            print(f"ALERT: Found {len(results)} secret(s)!")
                        else:
                            print("Scan completed - no secrets found (empty array)")
                    else:
                        print(f"Unexpected format: {type(parsed)}")
                else:
                    print("results.json is empty - scan clean")
        except json.JSONDecodeError as e:
            print(f"JSON parse error: {e}")
            status = "error"
        except Exception as e:
            print(f"Error reading results.json: {e}")
            status = "error"
    else:
        print("results.json not found - assuming clean scan")
    
    # ALWAYS save a record to the database
    data = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "repo": target_repo,
        "results": results,
        "status": status  # New field: "clean", "secrets_found", or "error"
    }
    
    print(f"Saving to Supabase: status={status}, results_count={len(results)}")
    
    try:
        response = supabase.table("scan_history").insert(data).execute()
        print("=" * 50)
        print("SUCCESS: Saved to Supabase!")
        print("=" * 50)
    except Exception as e:
        print("=" * 50)
        print(f"FAILED to save to Supabase: {e}")
        print("=" * 50)

if __name__ == "__main__":
    save_to_supabase()
