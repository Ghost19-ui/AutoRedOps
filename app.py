import streamlit as st
import time
import os
from auto_pentest import AutoRedOps
from ai_brain import AIBrain

# Page Configuration
st.set_page_config(page_title="AutoRedOps Pro", layout="wide", page_icon="💀")

# --- Sidebar: Configuration ---
with st.sidebar:
    st.title("⚙️ Mission Config")
    target_ip = st.text_input("Target IP", "192.168.1.15")
    
    # Securely handle API Key
    default_key = os.getenv("OPENAI_API_KEY", "")
    api_key = st.text_input("OpenAI API Key", value=default_key, type="password")
    
    lhost = st.text_input("LHOST (Your IP)", "192.168.1.5")
    
    st.divider()
    
    # Initialize Button
    if st.button("🚀 Initialize System"):
        with st.spinner("Booting Core Systems..."):
            try:
                # Initialize Backend
                st.session_state['ops'] = AutoRedOps()
                st.session_state['ai'] = AIBrain(api_key)
                st.success("System Online: Metasploit & AI Ready")
            except Exception as e:
                st.error(f"Initialization Failed: {e}")

# --- Main Dashboard ---
st.title("💀 AutoRedOps: AI-Powered Red Team")

# Tabs for different phases
tab1, tab2, tab3 = st.tabs(["🔍 Reconnaissance", "⚔️ Exploitation", "📊 AI Report"])

with tab1:
    st.header("Target Discovery & Scanning")
    if st.button("Start Full Scan"):
        ops = st.session_state.get('ops')
        if ops:
            with st.spinner(f"Scanning {target_ip}... (This may take 60s)"):
                scan_data = ops.scanner.scan_target(target_ip)
                st.session_state['scan_data'] = scan_data
                
                # Display Results
                st.json(scan_data)
                
                # Visual Metrics
                ports = len(scan_data.get('ports', []))
                os_name = scan_data.get('os', 'Unknown')
                st.metric(label="Open Ports", value=ports)
                st.metric(label="OS Detected", value=os_name)
                
                st.success("Scan Complete!")
        else:
            st.error("⚠️ Please Click 'Initialize System' in the sidebar first.")

with tab2:
    st.header("Attack Vector Analysis")
    scan_data = st.session_state.get('scan_data')
    
    if scan_data:
        ops = st.session_state['ops']
        attacks = ops.plan_attacks(scan_data)
        
        if not attacks:
            st.warning("No standard exploits found in Knowledge Base.")
            if st.button("🧠 Ask AI for Custom Vectors"):
                ai = st.session_state.get('ai')
                if ai:
                    with st.spinner("Consulting AI War Room..."):
                        # Example usage: Analyze the first open port found
                        p = scan_data['ports'][0]
                        advice = ai.analyze_vulnerability(p['service'], p['port'], p['cves'])
                        st.info(advice)
        else:
            st.success(f"Identified {len(attacks)} vectors!")
            
            # Attack Cards
            for i, attack in enumerate(attacks):
                with st.expander(f"🔴 Vector {i+1}: {attack['name']}"):
                    st.write(f"**Module:** `{attack['module']}`")
                    st.write(f"**Source:** {attack.get('source', 'Static KB')}")
                    
                    if st.button(f"🔥 Launch Attack {i+1}", key=f"btn_{i}"):
                        st.warning(f"Launching {attack['module']} against {target_ip}...")
                        
                        # Execute Exploit Logic
                        exploit_data = {
                            'msf_module': attack['module'],
                            'payload': attack['payload'],
                            'target_port': int(attack['port'])
                        }
                        
                        # Run via RPC
                        result = ops.rpc.execute_exploit(exploit_data, target_ip, lhost)
                        st.session_state['exploit_result'] = result
                        
                        if result['success']:
                            st.balloons()
                            st.success(f"Session Opened! ID: {result['session_id']}")
                        else:
                            st.error("Exploit Failed.")

with tab3:
    st.header("Executive Summary")
    if st.button("📝 Generate AI Report"):
        ai = st.session_state.get('ai')
        scan = st.session_state.get('scan_data')
        res = st.session_state.get('exploit_result')
        
        if ai and scan:
            with st.spinner("Drafting report with OpenAI..."):
                summary = ai.generate_executive_summary(scan, res)
                st.markdown("### Mission Executive Summary")
                st.write(summary)
                st.download_button("Download Report.txt", summary)
        else:
            st.warning("No scan data available or AI not initialized.")