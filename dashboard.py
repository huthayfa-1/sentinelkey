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

# Title and Header
st.title("🛡️ SentinelKey Security Dashboard")
st.markdown("### Real-time Monitoring & Secret Exposure Analysis")
st.markdown("---")

# Main UI Action Trigger
col_input, col_btn = st.columns([5, 1])
with col_input:
    target_repo = st.text_input("Target Repository URL", placeholder="https://github.com/user/repo", label_visibility="collapsed")

with col_btn:
    analyze_btn = st.button("Analyze", type="primary", use_container_width=True)

if analyze_btn:
    if not target_repo:
        st.warning("Please enter a URL first.")
    else:
        try:
            # Use secrets for PAT and Repo info
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
                data = {
                    "ref": ref,
                    "inputs": {
                        "target_repo_url": target_repo
                    }
                }
                api_url = f"https://api.github.com/repos/{owner}/{repo_name}/actions/workflows/{workflow_file}/dispatches"
                
                # Capture current latest timestamp to know when new data arrives
                latest_ts = None
                if data:
                    try:
                       latest_ts = data[0].get('timestamp')
                    except:
                       pass

                response = requests.post(api_url, json=data, headers=headers)
                if response.status_code == 204:
                    st.success("✅ Scan triggered! Waiting for results...")
                    
                    # Poll for up to 60 seconds
                    progress_text = "Scanning in progress. Please wait..."
                    my_bar = st.progress(0, text=progress_text)
                    
                    found_new = False
                    for i in range(20):
                        time.sleep(3)
                        my_bar.progress((i + 1) * 5, text=f"{progress_text} ({i*3}s)")
                        
                        # Check DB for new records
                        try:
                            check_resp = supabase.table("scan_history").select("timestamp").order("timestamp", desc=True).limit(1).execute()
                            if check_resp.data:
                                current_ts = check_resp.data[0].get('timestamp')
                                if current_ts != latest_ts:
                                    found_new = True
                                    break
                        except:
                            pass
                    
                    my_bar.empty()
                    if found_new:
                        st.success("🚀 New scan results found!")
                        st.cache_data.clear()
                        time.sleep(1)
                        st.rerun()
                    else:
                        st.warning("Scan triggered, but results are taking longer than expected. Please refresh manually in a moment.")

                else:
                    st.error(f"Failed to trigger: {response.status_code}")
                    st.json(response.json())
                    with st.expander("Debug Info"):
                        st.write(f"URL: {api_url}")
                        st.write(f"Ref: {ref}")
                        st.write("Check if your PAT has 'workflow' scope and if the repo/workflow names are correct.")
        except Exception as e:
            st.error(f"Error triggering scan: {e}")

st.markdown("---")

# Initialize connection
@st.cache_resource
def init_connection():
    try:
        url = st.secrets["SUPABASE_URL"]
        key = st.secrets["SUPABASE_KEY"]
        return create_client(url, key)
    except Exception as e:
        return None

supabase = init_connection()

# Load Data
@st.cache_data(ttl=10)
def load_data():
    if not supabase:
         return []
    try:
        response = supabase.table("scan_history").select("*").order("timestamp", desc=True).execute()
        return response.data
    except Exception as e:
        st.error(f"Error connecting to database: {e}")
        return []

data = load_data()

# Sidebar (Only Controls & Debug)
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

# Visualization Logic
if not data:
    if not supabase:
        st.error("Supabase not connected. Please set SUPABASE_URL and SUPABASE_KEY in Streamlit secrets.")
    else:
        st.info("No scan history found yet. Enter a repo URL above to start!")
else:
    # Process Data
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
                # Gitleaks format
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
            # Convert time to date for grouping
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
