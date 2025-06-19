AI Security Agent - Documentation
AI SECURITY AGENT - PROJECT DOCUMENTATION


Overview:
An intelligent, real-time security agent that monitors network traffic, detects anomalies using Machine
Learning, logs alerts, and provides a web-based dashboard for analysis.


Technologies Used:
- Scapy (packet sniffing)
- Isolation Forest (ML)
- Streamlit (dashboard)
- pyttsx3 (text-to-speech)
- pandas, matplotlib, seaborn

Features:
- Real-time IP packet sniffing
- ML-based port/protocol anomaly detection
- Blacklisted IP detection
- Voice alerts for suspicious traffic
- CSV log storage
- Streamlit dashboard for visualization
- Export logs



Installation Steps:
1. Install Python from https://www.python.org/downloads/
2. Install Npcap from https://nmap.org/npcap/ (Windows only)
- Enable "WinPcap Compatibility Mode" and "Support loopback traffic"
3. Clone or download the project
4. Install dependencies:
pip install -r requirements.txt
AI Security Agent - Documentation



Usage:
- Run the security agent:
python ai_security_agent.py
- Launch the dashboard in another terminal:
streamlit run dashboard.py
- Open http://localhost:8501 to view the dashboard.



File Structure:
- ai_security_agent.py (Main detection script)
- dashboard.py (Streamlit dashboard)
- logs.csv (Auto-generated logs)
- ml_model.pkl (Trained ML model)
- README.md (Documentation)
- requirements.txt (Dependencies)


Common Issues:
- EOFError (delete ml_model.pkl and rerun)
- KeyError 'alert' (delete logs.csv and rerun agent)
- Npcap errors (reinstall with required options)


License:
MIT License



Author:
Param Jani
Computer Engineering Student, SVIT Vasad