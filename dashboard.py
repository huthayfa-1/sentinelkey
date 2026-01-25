import streamlit as st
import pandas as pd
import json
import plotly.express as px
from datetime import datetime
from supabase import create_client, Client
import requests
import time

# Page Config
st.set_page_config(
    page_title="SentinelKey Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ============================================
# INITIALIZE SUPABASE FIRST (before any usage)
# ============================================
@st.cache_resource
def init_connection():
    try:
        url = st.secrets["SUPABASE_URL"]
        key = st.secrets["SUPABASE_KEY"]
        return create_client(url, key)
    except Exception as e:
        return None

supabase = init_connection()

# Load Data Function
@st.cache_data(ttl=10)
def load_data():
    if not supabase:
         return []
    try:
        response = supabase.table("scan_history").select("*").order("timestamp", desc=True).limit(50).execute()
        return response.data
    except Exception as e:
        st.error(f"Error connecting to database: {e}")
        return []

# ============================================
# HEADER
# ============================================
st.title("🛡️ SentinelKey Security Dashboard")
st.markdown("### Real-time Monitoring & Secret Exposure Analysis")
st.markdown("---")

# ============================================
# MAIN UI: TRIGGER SCAN
# ============================================
col_input, col_btn = st.columns([5, 1])
with col_input:
    target_repo = st.text_input("Target Repository URL", placeholder="https://github.com/user/repo", label_visibility="collapsed")

with col_btn:
    analyze_btn = st.button("Analyze", type="primary", use_container_width=True)

if analyze_btn:
    if not target_repo:
        st.warning("Please enter a URL first.")
    elif not supabase:
        st.error("Supabase not connected. Cannot poll for results.")
    else:
        try:
            # Get current latest timestamp BEFORE triggering
            current_data = load_data()
            latest_ts = current_data[0].get('timestamp') if current_data else None
            
            # GitHub API config
            pat = st.secrets.get("GITHUB_PAT")
            owner = st.secrets.get("GITHUB_OWNER", "HamDQan1") 
            repo_name = st.secrets.get("GITHUB_REPO", "sentinelkey")
            workflow_file = "on_demand_scan.yml"
            ref = "master"
            
            if not pat:
                st.error("GITHUB_PAT missing in secrets!")
            else:
                headers = {
                    "Authorization": f"Bearer {pat}",
                    "Accept": "application/vnd.github.v3+json"
                }
                payload = {  # Fixed: renamed from 'data' to 'payload'
                    "ref": ref,
                    "inputs": {
                        "target_repo_url": target_repo
                    }
                }
                api_url = f"https://api.github.com/repos/{owner}/{repo_name}/actions/workflows/{workflow_file}/dispatches"
                
                response = requests.post(api_url, json=payload, headers=headers)
                if response.status_code == 204:
                    st.success("✅ Scan triggered! Waiting for results...")
                    
                    # Poll for up to 120 seconds
                    progress_text = "Scanning in progress... (this may take a minute)"
                    my_bar = st.progress(0, text=progress_text)
                    
                    found_new = False
                    new_scan_result = None
                    # 24 checks * 5 seconds = 120 seconds max
                    for i in range(24):
                        time.sleep(5)
                        my_bar.progress(min((i + 1) * 4, 100), text=f"{progress_text} ({(i+1)*5}s)")
                        
                        # Check DB for new records (bypass cache)
                        try:
                            check_resp = supabase.table("scan_history").select("*").order("timestamp", desc=True).limit(1).execute()
                            if check_resp.data:
                                new_record = check_resp.data[0]
                                new_ts = new_record.get('timestamp')
                                # Compare timestamps
                                if latest_ts is None or (new_ts and new_ts > latest_ts):
                                    found_new = True
                                    new_scan_result = new_record
                                    break
                        except Exception as poll_err:
                            pass
                    
                    my_bar.empty()
                    
                    if found_new and new_scan_result:
                        st.balloons()
                        # Check if scan found anything
                        results = new_scan_result.get('results', [])
                        if isinstance(results, str):
                            try:
                                results = json.loads(results)
                            except:
                                results = []
                        
                        if results:
                            st.error(f"🚨 **Alert!** Found {len(results)} exposed secret(s)!")
                        else:
                            st.success(f"✅ **Scan Complete**: No secrets found in `{target_repo}`")
                        
                        st.cache_data.clear()
                        time.sleep(2)
                        st.rerun()
                    else:
                        st.warning("Scan is taking longer than expected. The workflow may be queued. Click 'Refresh Data' in a minute.")

                else:
                    st.error(f"Failed to trigger: {response.status_code}")
                    try:
                        st.json(response.json())
                    except:
                        st.write(response.text)
                    with st.expander("Debug Info"):
                        st.write(f"URL: {api_url}")
                        st.write(f"Ref: {ref}")
                        st.write("Check if your PAT has 'workflow' scope and if the repo/workflow names are correct.")
        except Exception as e:
            st.error(f"Error triggering scan: {e}")

st.markdown("---")

# ============================================
# SIDEBAR
# ============================================
data = load_data()

with st.sidebar:
    st.header("Controls")
    if st.button("🔄 Refresh Data"):
        st.cache_data.clear()
        st.rerun()

    st.header("Debug Info")
    if st.checkbox("Show Raw JSON History"):
        st.json(data)
    
    st.markdown("---")
    st.markdown("Built with SentinelKey 🛡️")

# ============================================
# VISUALIZATION
# ============================================
if not data:
    if not supabase:
        st.error("Supabase not connected. Please set SUPABASE_URL and SUPABASE_KEY in Streamlit secrets.")
    else:
        st.info("No scan history found yet. Enter a repo URL above to start!")
else:
    # Check latest scan for feedback
    latest_scan = data[0]
    ls_results = latest_scan.get('results', [])
    if isinstance(ls_results, str):
        try: 
            ls_results = json.loads(ls_results)
        except: 
            ls_results = []
    
    # Show latest scan status
    if not ls_results:
        st.success(f"✅ **Latest Scan**: Clean! No secrets found in `{latest_scan.get('repo', 'repository')}`")
    
    # Process ALL Data
    all_findings = []
    for scan in data:
        scan_time = scan.get('timestamp', 'Unknown')
        repo = scan.get('repo', 'Unknown')
        
        results = scan.get('results', [])
        if isinstance(results, str):
            try:
                results = json.loads(results)
            except:
                results = []
                
        if isinstance(results, list):
            for item in results:
                if 'RuleID' in item:
                    finding = {
                        "Time": scan_time,
                        "Repository": repo,
                        "Type": item.get('Description', item.get('RuleID')),
                        "File": item.get('File'),
                        "Line": item.get('StartLine'),
                        "Secret": item.get('Secret'),
                        "Author": item.get('Author', 'Unknown'),
                        "Commit": item.get('Commit', 'Unknown')
                    }
                    all_findings.append(finding)

    if not all_findings:
        st.success("🎉 No secrets found in recorded history!")
    else:
        df = pd.DataFrame(all_findings)

        # KPI Metrics
        col1, col2, col3 = st.columns(3)
        col1.metric("Total Leaks Detected", len(df))
        col2.metric("Unique Repositories Scanned", df['Repository'].nunique())
        col3.metric("Most Common Secret Type", df['Type'].mode()[0] if not df['Type'].empty else "N/A")

        # Visualizations
        col_left, col_right = st.columns(2)
        
        with col_left:
            st.subheader("Leaks Over Time")
            df['Date'] = pd.to_datetime(df['Time']).dt.date
            daily_counts = df.groupby('Date').size().reset_index(name='Counts')
            fig_line = px.line(daily_counts, x='Date', y='Counts', markers=True)
            st.plotly_chart(fig_line, use_container_width=True)

        with col_right:
            st.subheader("Secrets by Type")
            type_counts = df['Type'].value_counts().reset_index()
            type_counts.columns = ['Type', 'Count']
            fig_pie = px.pie(type_counts, values='Count', names='Type', hole=0.4)
            st.plotly_chart(fig_pie, use_container_width=True)

        # Detailed Table
        st.subheader("🔍 Detailed Findings")
        st.dataframe(
            df, 
            column_config={
                "Secret": st.column_config.TextColumn("Secret", help="The exposed secret content"),
                "Repository": st.column_config.LinkColumn("Repository")
            },
            use_container_width=True
        )
