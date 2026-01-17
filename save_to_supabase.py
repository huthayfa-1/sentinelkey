import os
import json
from datetime import datetime
from supabase import create_client, Client
from dotenv import load_dotenv

# Load env vars for local testing
load_dotenv()

def save_to_supabase():
    url = os.environ.get("SUPABASE_URL")
    key = os.environ.get("SUPABASE_KEY")
    
    if not url or not key:
        print("Error: Supabase credentials not found.")
        return

    supabase: Client = create_client(url, key)
    
    # Load results
    results = []
    if os.path.exists('results.json'):
        try:
            with open('results.json', 'r') as f:
                content = f.read().strip()
                if content:
                    results = json.loads(content)
        except:
            pass
            
    # Prepare payload
    data = {
        "timestamp": datetime.now().isoformat(),
        "repo": os.environ.get("TARGET_REPO_URL", "Unknown"),
        "results": results
    }
    
    try:
        response = supabase.table("scan_history").insert(data).execute()
        print("Successfully saved to Supabase!")
    except Exception as e:
        print(f"Failed to save to Supabase: {e}")

if __name__ == "__main__":
    save_to_supabase()
