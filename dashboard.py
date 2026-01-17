import streamlit as st
import pandas as pd
import json
import plotly.express as px
from datetime import datetime
from supabase import create_client, Client

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

# Initialize connection
@st.cache_resource
def init_connection():
    url = st.secrets["SUPABASE_URL"]
    key = st.secrets["SUPABASE_KEY"]
    return create_client(url, key)

supabase = init_connection()

# Load Data
@st.cache_data(ttl=10)
def load_data():
    try:
        response = supabase.table("scan_history").select("*").order("timestamp", desc=True).execute()
        return response.data
    except Exception as e:
        st.error(f"Error connecting to database: {e}")
        return []

data = load_data()

# Sidebar
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

if not data:
    st.info("No scan history found yet. Run a scan to populate data!")
else:
    # Process Data
    all_findings = []
    for scan in data:
        scan_time = scan.get('timestamp', 'Unknown')
        repo = scan.get('repo', 'Unknown')
        
        # Determine if it's Gitleaks format or TruffleHog (legacy fallback)
        results = scan.get('results', [])
        # If results is a string/jsonb, it might come correctly parsed or needs loading
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
