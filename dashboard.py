import streamlit as st
import pandas as pd
import time
import os
import matplotlib.pyplot as plt
import seaborn as sns

st.set_page_config(layout="wide")

st.title("🛡️ AI Security Agent Dashboard")

LOG_FILE = "logs.csv"

if not os.path.exists(LOG_FILE):
    st.warning("No logs yet. Start the agent first.")
    st.stop()

# Auto-refresh every 10 seconds
st_autorefresh = st.empty()
st_autorefresh.markdown(
    "<meta http-equiv='refresh' content='10'>", unsafe_allow_html=True
)

df = pd.read_csv(LOG_FILE)

st.subheader("🔔 Latest Security Alerts")
st.dataframe(df.tail(10), use_container_width=True)

alert_count = df[df['alert'] != ""].shape[0]
st.metric("🚨 Total Alerts", alert_count)

# Plot by IP
st.subheader("📊 Alerts by Source IP")
alert_data = df[df['alert'] != ""]
if not alert_data.empty:
    top_ips = alert_data['src'].value_counts().head(5)
    fig, ax = plt.subplots()
    sns.barplot(x=top_ips.values, y=top_ips.index, ax=ax)
    st.pyplot(fig)
else:
    st.info("No alerts detected yet.")

# Download Logs
st.download_button("📥 Download Logs CSV", df.to_csv(index=False), file_name="logs.csv")
