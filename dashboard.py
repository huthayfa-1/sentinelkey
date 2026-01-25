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
    initial_sidebar_state="collapsed"
)

# ============================================
# INITIALIZE SUPABASE
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

# ============================================
# SESSION STATE - Track current scan only
# ============================================
if 'scan_result' not in st.session_state:
    st.session_state.scan_result = None
if 'scan_status' not in st.session_state:
    st.session_state.scan_status = 'idle'  # idle, scanning, complete
if 'scanned_repo' not in st.session_state:
    st.session_state.scanned_repo = None

# ============================================
# HEADER
# ============================================
st.title("🛡️ SentinelKey")
st.markdown("### Secret Scanner for GitHub Repositories")
st.markdown("---")

# ============================================
# MAIN UI: SCAN INPUT
# ============================================
col_input, col_btn, col_reset = st.columns([5, 1, 1])

with col_input:
    target_repo = st.text_input(
        "Repository URL", 
        placeholder="https://github.com/user/repo", 
        label_visibility="collapsed",
        disabled=(st.session_state.scan_status == 'scanning')
    )

with col_btn:
    analyze_btn = st.button(
        "🔍 Analyze", 
        type="primary", 
        use_container_width=True,
        disabled=(st.session_state.scan_status == 'scanning')
    )

with col_reset:
    if st.button("🔄 New", use_container_width=True):
        st.session_state.scan_result = None
        st.session_state.scan_status = 'idle'
        st.session_state.scanned_repo = None
        st.rerun()

# ============================================
# TRIGGER SCAN
# ============================================
if analyze_btn and target_repo:
    if not supabase:
        st.error("Database not connected. Check Streamlit secrets.")
    else:
        st.session_state.scan_status = 'scanning'
        st.session_state.scanned_repo = target_repo
        
        try:
            # Get current latest timestamp BEFORE triggering
            try:
                before_resp = supabase.table("scan_history").select("timestamp").order("timestamp", desc=True).limit(1).execute()
                latest_ts = before_resp.data[0].get('timestamp') if before_resp.data else None
            except:
                latest_ts = None
            
            # GitHub API config
            pat = st.secrets.get("GITHUB_PAT")
            owner = st.secrets.get("GITHUB_OWNER", "HamDQan1") 
            repo_name = st.secrets.get("GITHUB_REPO", "sentinelkey")
            workflow_file = "on_demand_scan.yml"
            
            if not pat:
                st.error("GITHUB_PAT missing in secrets!")
                st.session_state.scan_status = 'idle'
            else:
                headers = {
                    "Authorization": f"Bearer {pat}",
                    "Accept": "application/vnd.github.v3+json"
                }
                payload = {
                    "ref": "master",
                    "inputs": {"target_repo_url": target_repo}
                }
                api_url = f"https://api.github.com/repos/{owner}/{repo_name}/actions/workflows/{workflow_file}/dispatches"
                
                response = requests.post(api_url, json=payload, headers=headers)
                
                if response.status_code == 204:
                    # Poll for results
                    progress_text = "Scanning repository..."
                    my_bar = st.progress(0, text=progress_text)
                    
                    found_new = False
                    new_scan_result = None
                    
                    for i in range(30):  # 150 seconds max
                        time.sleep(5)
                        my_bar.progress(min((i + 1) * 3, 100), text=f"{progress_text} ({(i+1)*5}s)")
                        
                        try:
                            check_resp = supabase.table("scan_history").select("*").order("timestamp", desc=True).limit(1).execute()
                            if check_resp.data:
                                new_record = check_resp.data[0]
                                new_ts = new_record.get('timestamp')
                                if latest_ts is None or (new_ts and new_ts > latest_ts):
                                    found_new = True
                                    new_scan_result = new_record
                                    break
                        except:
                            pass
                    
                    my_bar.empty()
                    
                    if found_new and new_scan_result:
                        st.session_state.scan_result = new_scan_result
                        st.session_state.scan_status = 'complete'
                        st.balloons()
                        st.rerun()
                    else:
                        st.warning("Scan is taking longer than expected. Try clicking 'New' and scanning again.")
                        st.session_state.scan_status = 'idle'
                else:
                    st.error(f"Failed to trigger scan: {response.status_code}")
                    st.session_state.scan_status = 'idle'
                    
        except Exception as e:
            st.error(f"Error: {e}")
            st.session_state.scan_status = 'idle'

elif analyze_btn and not target_repo:
    st.warning("Please enter a repository URL first.")

# ============================================
# DISPLAY RESULTS (Current Session Only)
# ============================================
st.markdown("---")

if st.session_state.scan_status == 'idle' and st.session_state.scan_result is None:
    # Initial state - show instructions
    st.markdown("""
    <div style="text-align: center; padding: 50px; color: #888;">
        <h2>👆 Enter a GitHub repository URL above</h2>
        <p>SentinelKey will scan for exposed secrets, API keys, and credentials</p>
    </div>
    """, unsafe_allow_html=True)

elif st.session_state.scan_status == 'complete' and st.session_state.scan_result:
    # Show results from current scan
    scan = st.session_state.scan_result
    repo = scan.get('repo', 'Unknown')
    timestamp = scan.get('timestamp', 'Unknown')
    
    results = scan.get('results', [])
    if isinstance(results, str):
        try:
            results = json.loads(results)
        except:
            results = []
    
    # Header with scan info
    st.markdown(f"### Scan Results for `{repo}`")
    st.caption(f"Scanned at: {timestamp}")
    
    if not results:
        # Clean scan
        st.success("## ✅ No secrets found!")
        st.markdown("""
        This repository appears to be clean. No exposed:
        - API Keys
        - Passwords
        - Tokens
        - Private Keys
        """)
    else:
        # Secrets found
        st.error(f"## 🚨 Found {len(results)} exposed secret(s)!")
        
        # Parse findings
        findings = []
        for item in results:
            if 'RuleID' in item:
                findings.append({
                    "Type": item.get('Description', item.get('RuleID')),
                    "File": item.get('File'),
                    "Line": item.get('StartLine'),
                    "Secret": item.get('Secret', '')[0:50] + "..." if len(item.get('Secret', '')) > 50 else item.get('Secret', ''),
                    "Author": item.get('Author', 'Unknown'),
                    "Commit": item.get('Commit', 'Unknown')[:8] if item.get('Commit') else 'Unknown'
                })
        
        if findings:
            df = pd.DataFrame(findings)
            
            # Metrics
            col1, col2 = st.columns(2)
            col1.metric("Total Secrets", len(df))
            col2.metric("Secret Types", df['Type'].nunique())
            
            # Chart
            st.subheader("Secrets by Type")
            type_counts = df['Type'].value_counts().reset_index()
            type_counts.columns = ['Type', 'Count']
            fig = px.pie(type_counts, values='Count', names='Type', hole=0.4)
            st.plotly_chart(fig, use_container_width=True)
            
            # Table
            st.subheader("🔍 Detailed Findings")
            st.dataframe(df, use_container_width=True)

# Hidden debug in sidebar
with st.sidebar:
    st.header("Debug")
    if st.checkbox("Show Session State"):
        st.json({
            "status": st.session_state.scan_status,
            "scanned_repo": st.session_state.scanned_repo,
            "has_result": st.session_state.scan_result is not None
        })
