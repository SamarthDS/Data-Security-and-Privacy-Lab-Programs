import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import json
import random
import time
from datetime import datetime
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple

# Import the simulator classes from 1.py
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
import random

@dataclass
class Document:
    name: str
    content: str
    has_macro: bool = False
    macro_behavior: Optional[str] = None

@dataclass
class Email:
    sender: str
    recipient: str
    subject: str
    body: str
    attachment: Optional[Document] = None
    link: Optional[str] = None

@dataclass
class Node:
    id: str
    user: str
    compromised: bool = False
    compromise_vector: Optional[str] = None
    files: List[Document] = field(default_factory=list)
    mailbox: List[Email] = field(default_factory=list)
    detection_alerts: List[Dict] = field(default_factory=list)

    def receive_email(self, email: Email):
        self.mailbox.append(email)

    def open_email(self, index: int) -> Optional[Email]:
        try:
            return self.mailbox[index]
        except IndexError:
            return None

class Attacker:
    def __init__(self, name: str = "Attacker"):
        self.name = name

    def craft_phishing_email(self, target_user: str, lure: str = "invoice") -> Email:
        subj = f"{lure.title()} - Action Required"
        body = (
            f"Hi {target_user},\n\nPlease see the attached {lure}. If you have issues, reply to this email.\n\nThanks\n{self.name}"
        )
        doc = Document(
            name=f"{lure}_{random.randint(100,999)}.docm",
            content=f"Simulated {lure} content for {target_user}",
            has_macro=True,
            macro_behavior="exfiltrate_simulated_credentials"
        )
        return Email(sender=self.name, recipient=target_user, subject=subj, body=body, attachment=doc)

    def craft_malicious_link_email(self, target_user: str, domain: str = "bad.example") -> Email:
        subj = "Security Alert - Verify Your Account"
        body = f"Dear {target_user}, please verify here: http://{domain}/verify"
        return Email(sender=self.name, recipient=target_user, subject=subj, body=body, link=f"http://{domain}/verify")

class SignatureDetector:
    KNOWN_SIGNATURES = [
        "exfiltrate_simulated_credentials",
        "evil_macro",
        "drop_ransom_note",
        "keylogger_stub",
    ]

    def scan_document(self, doc: Document) -> Optional[str]:
        if doc.macro_behavior and doc.macro_behavior in self.KNOWN_SIGNATURES:
            return f"signature:{doc.macro_behavior}"
        for sig in self.KNOWN_SIGNATURES:
            if sig in doc.content:
                return f"signature_in_content:{sig}"
        return None

    def scan_email(self, email: Email) -> Optional[str]:
        if email.attachment:
            return self.scan_document(email.attachment)
        if email.link and "bad.example" in (email.link or ""):
            return "signature:malicious-link-bad-example"
        return None

class HeuristicDetector:
    SHORT_URL_DOMAINS = {"bit.ly", "t.co", "tinyurl.com"}

    def score_email(self, email: Email) -> Tuple[float, List[str]]:
        score = 0.0
        reasons = []
        subj = (email.subject or "").lower()
        body = (email.body or "").lower()

        if any(word in subj for word in ["action required", "verify", "urgent", "security alert"]):
            score += 0.3
            reasons.append("suspicious-subject")
        if email.link:
            score += 0.3
            reasons.append("contains-link")
            if any(s in email.link for s in self.SHORT_URL_DOMAINS):
                score += 0.2
                reasons.append("shortener-link")
            if "bad.example" in email.link:
                score += 0.5
                reasons.append("known-bad-domain")
        if email.attachment:
            score += 0.25
            reasons.append("attachment-present")
            if email.attachment.has_macro:
                score += 0.4
                reasons.append("macro-attachment")
        score = min(score, 1.0)
        return score, reasons

class AnomalyDetector:
    def __init__(self):
        self.baseline_message_counts = {}

    def update_baseline(self, user: str, count: int):
        self.baseline_message_counts[user] = int(round(count))

    def is_anomalous(self, user: str, current_count: int) -> Tuple[bool, float]:
        baseline = self.baseline_message_counts.get(user, max(1, current_count))
        ratio = current_count / (baseline if baseline > 0 else 1)
        return ratio > 3.0, ratio

class Simulator:
    def __init__(self, num_nodes: int = 10, seed: Optional[int] = None):
        self.nodes: Dict[str, Node] = {}
        self.attacker = Attacker()
        self.sig = SignatureDetector()
        self.heur = HeuristicDetector()
        self.ano = AnomalyDetector()
        self.time = 0
        if seed is not None:
            random.seed(seed)

        for i in range(num_nodes):
            user = f"user{i+1}@example.com"
            node = Node(id=f"node{i+1}", user=user)
            node.files.append(Document(name="welcome.txt", content="Welcome user"))
            self.nodes[node.id] = node

    def send_email(self, target_node_id: str, email: Email):
        node = self.nodes[target_node_id]
        node.receive_email(email)

    def simulate_phishing_campaign(self, targets: List[str], lure: str = "invoice", click_rate: float = 0.2):
        events = []
        for t in targets:
            email = self.attacker.craft_phishing_email(self.nodes[t].user, lure=lure)
            self.send_email(t, email)
            events.append((t, "sent_phishing", email.subject))

            sig = self.sig.scan_email(email)
            score, reasons = self.heur.score_email(email)

            if sig:
                self.nodes[t].detection_alerts.append({"time": self.time, "type": "signature", "detail": sig})
                events.append((t, "detected_by_signature", sig))
            elif score >= 0.7:
                self.nodes[t].detection_alerts.append({"time": self.time, "type": "heuristic", "detail": reasons})
                events.append((t, "detected_by_heuristic", reasons))

            if random.random() < click_rate:
                doc = email.attachment
                exec_result = self._simulate_attachment_execution(t, doc)
                events.append((t, "attachment_executed", exec_result))
        return events

    def simulate_link_campaign(self, targets: List[str], click_rate: float = 0.15):
        events = []
        for t in targets:
            email = self.attacker.craft_malicious_link_email(self.nodes[t].user)
            self.send_email(t, email)
            events.append((t, "sent_link_phishing", email.link))
            sig = self.sig.scan_email(email)
            score, reasons = self.heur.score_email(email)
            if sig:
                self.nodes[t].detection_alerts.append({"time": self.time, "type": "signature", "detail": sig})
                events.append((t, "detected_by_signature", sig))
            elif score >= 0.7:
                self.nodes[t].detection_alerts.append({"time": self.time, "type": "heuristic", "detail": reasons})
                events.append((t, "detected_by_heuristic", reasons))

            if random.random() < click_rate:
                result = self._simulate_link_visit(t, email.link)
                events.append((t, "link_visited", result))
        return events

    def _simulate_attachment_execution(self, node_id: str, doc: Document) -> str:
        node = self.nodes[node_id]
        sig = self.sig.scan_document(doc)
        if sig:
            node.detection_alerts.append({"time": self.time, "type": "signature", "detail": sig})
            return f"blocked_by_signature:{sig}"
        score, reasons = self.heur.score_email(Email(sender="unknown", recipient=node.user, subject="", body="", attachment=doc))
        if score > 0.8:
            node.detection_alerts.append({"time": self.time, "type": "heuristic", "detail": reasons})
            return f"blocked_by_heuristic:{reasons}"

        if doc.has_macro and doc.macro_behavior:
            behavior = doc.macro_behavior
            if behavior == "exfiltrate_simulated_credentials":
                node.compromised = True
                node.compromise_vector = "malicious_macro_attachment"
                node.files.append(Document(name="creds_leak_marker.txt", content="SIMULATED: stolen-creds"))
                return "macro_executed:exfiltrate_simulated_credentials"
            elif behavior == "drop_ransom_note":
                node.compromised = True
                node.compromise_vector = "ransom_note_macro"
                return "macro_executed:drop_ransom_note"
            else:
                node.detection_alerts.append({"time": self.time, "type": "suspicious_macro", "detail": behavior})
                return f"macro_executed:unknown_behavior:{behavior}"
        return "no_macro_or_no_action"

    def _simulate_link_visit(self, node_id: str, link: str) -> str:
        node = self.nodes[node_id]
        if "bad.example" in (link or ""):
            if random.random() < 0.6:
                node.compromised = True
                node.compromise_vector = "drive_by_link"
                node.files.append(Document(name="drive_by_marker.txt", content="SIMULATED: drive-by compromise"))
                return "compromised_by_drive_by"
            else:
                node.detection_alerts.append({"time": self.time, "type": "suspicious_link_visit", "detail": link})
                return "suspicious_link_but_not_compromised"
        return "safe_link_or_unknown_behavior"

    def propagate(self, propagation_chance: float = 0.05):
        events = []
        compromised_nodes = [n for n in self.nodes.values() if n.compromised]
        for node in compromised_nodes:
            targets = [n for n in self.nodes.values() if not n.compromised and n.id != node.id]
            for target in random.sample(targets, min(2, len(targets))):
                subj = "Invoice follow-up"
                body = "Please see attached document."
                doc = Document(name=f"fwd_{random.randint(10,99)}.docm", content="forwarded doc", has_macro=True, macro_behavior="exfiltrate_simulated_credentials")
                email = Email(sender=node.user, recipient=target.user, subject=subj, body=body, attachment=doc)
                target.receive_email(email)
                events.append((node.id, "propagated_to", target.id))
        return events

    def summary(self) -> Dict:
        s = {
            "time": self.time,
            "total_nodes": len(self.nodes),
            "compromised": [n.id for n in self.nodes.values() if n.compromised],
            "alerts": {n.id: n.detection_alerts for n in self.nodes.values() if n.detection_alerts},
        }
        return s

# Streamlit App Configuration
st.set_page_config(
    page_title="🛡️ Email & Document Virus Simulator",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling
st.markdown("""
<style>
    .main-header {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        padding: 2rem;
        border-radius: 10px;
        text-align: center;
        margin-bottom: 2rem;
    }
    .metric-container {
        background: #f8f9fa;
        padding: 1rem;
        border-radius: 8px;
        border-left: 4px solid #007bff;
    }
    .danger-zone {
        background: #fff5f5;
        border: 1px solid #feb2b2;
        border-radius: 8px;
        padding: 1rem;
    }
    .success-zone {
        background: #f0fff4;
        border: 1px solid #9ae6b4;
        border-radius: 8px;
        padding: 1rem;
    }
    .warning-zone {
        background: #fffbeb;
        border: 1px solid #f6e05e;
        border-radius: 8px;
        padding: 1rem;
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state
if 'simulator' not in st.session_state:
    st.session_state.simulator = None
if 'simulation_history' not in st.session_state:
    st.session_state.simulation_history = []
if 'current_round' not in st.session_state:
    st.session_state.current_round = 0

# Main header
st.markdown("""
<div class="main-header">
    <h1>🛡️ Email & Document Virus Simulator</h1>
    <p>Educational cybersecurity simulation for studying phishing attacks, malware behavior, and detection strategies</p>
</div>
""", unsafe_allow_html=True)

# Sidebar for navigation and controls
with st.sidebar:
    st.header("🎮 Simulation Control")
    
    page = st.selectbox(
        "Choose Page",
        ["🏠 Dashboard", "⚙️ Setup Simulation", "📧 Attack Campaigns", "📊 Analytics", "🔍 Detection Lab", "📚 Educational Content"]
    )
    
    st.divider()
    
    # Quick stats if simulation is active
    if st.session_state.simulator:
        sim = st.session_state.simulator
        summary = sim.summary()
        
        st.metric("Total Nodes", summary['total_nodes'])
        st.metric("Compromised Nodes", len(summary['compromised']), 
                 delta=len(summary['compromised']) - st.session_state.get('prev_compromised', 0))
        st.metric("Current Round", st.session_state.current_round)
        
        # Compromise rate
        compromise_rate = (len(summary['compromised']) / summary['total_nodes'] * 100) if summary['total_nodes'] > 0 else 0
        st.metric("Compromise Rate", f"{compromise_rate:.1f}%")

# Main content area
if page == "🏠 Dashboard":
    st.header("📊 Simulation Dashboard")
    
    if st.session_state.simulator is None:
        st.info("👆 Please set up a simulation first using the 'Setup Simulation' page in the sidebar.")
        
        # Quick setup option
        col1, col2 = st.columns(2)
        with col1:
            if st.button("🚀 Quick Start (10 nodes)", type="primary"):
                st.session_state.simulator = Simulator(num_nodes=10, seed=42)
                st.session_state.current_round = 0
                st.rerun()
        
        with col2:
            if st.button("🎯 Advanced Setup"):
                st.switch_page
    else:
        sim = st.session_state.simulator
        summary = sim.summary()
        
        # Key metrics
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Total Nodes", summary['total_nodes'])
        
        with col2:
            compromised_count = len(summary['compromised'])
            st.metric("Compromised", compromised_count, 
                     delta=compromised_count - st.session_state.get('prev_compromised', 0))
        
        with col3:
            safe_count = summary['total_nodes'] - compromised_count
            st.metric("Safe Nodes", safe_count)
        
        with col4:
            compromise_rate = (compromised_count / summary['total_nodes'] * 100) if summary['total_nodes'] > 0 else 0
            st.metric("Compromise Rate", f"{compromise_rate:.1f}%")
        
        # Network visualization
        st.subheader("🌐 Network Status")
        
        # Create network visualization using plotly
        nodes_data = []
        for node_id, node in sim.nodes.items():
            status = "Compromised" if node.compromised else "Safe"
            color = "#ff4444" if node.compromised else "#44ff44"
            
            nodes_data.append({
                'Node': node_id,
                'User': node.user,
                'Status': status,
                'Color': color,
                'Emails': len(node.mailbox),
                'Alerts': len(node.detection_alerts),
                'Compromise Vector': node.compromise_vector or "None"
            })
        
        df_nodes = pd.DataFrame(nodes_data)
        
        # Network scatter plot
        fig = px.scatter(df_nodes, 
                        x='Node', 
                        y=['Status'], 
                        color='Status',
                        size='Emails',
                        hover_data=['User', 'Alerts', 'Compromise Vector'],
                        title="Network Node Status",
                        color_discrete_map={"Safe": "#44ff44", "Compromised": "#ff4444"})
        
        fig.update_layout(height=400)
        st.plotly_chart(fig, use_container_width=True)
        
        # Recent alerts
        st.subheader("🚨 Recent Alerts")
        
        all_alerts = []
        for node_id, node in sim.nodes.items():
            for alert in node.detection_alerts:
                all_alerts.append({
                    'Time': alert['time'],
                    'Node': node_id,
                    'Type': alert['type'],
                    'Detail': str(alert['detail'])
                })
        
        if all_alerts:
            df_alerts = pd.DataFrame(all_alerts)
            df_alerts = df_alerts.sort_values('Time', ascending=False)
            st.dataframe(df_alerts, use_container_width=True)
        else:
            st.info("No alerts detected yet.")

elif page == "⚙️ Setup Simulation":
    st.header("⚙️ Simulation Setup")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("🏗️ Network Configuration")
        
        num_nodes = st.slider("Number of Nodes", min_value=5, max_value=50, value=10)
        seed = st.number_input("Random Seed (for reproducibility)", value=42, step=1)
        
        if st.button("🎯 Initialize Simulation", type="primary"):
            st.session_state.simulator = Simulator(num_nodes=num_nodes, seed=seed)
            st.session_state.current_round = 0
            st.session_state.simulation_history = []
            st.success(f"✅ Simulation initialized with {num_nodes} nodes!")
            st.rerun()
    
    with col2:
        st.subheader("📋 Current Configuration")
        
        if st.session_state.simulator:
            sim = st.session_state.simulator
            summary = sim.summary()
            
            st.json({
                "Total Nodes": summary['total_nodes'],
                "Simulation Time": summary['time'],
                "Current Round": st.session_state.current_round,
                "Nodes": list(sim.nodes.keys())[:10]  # Show first 10
            })
            
            if st.button("🔄 Reset Simulation"):
                st.session_state.simulator = None
                st.session_state.current_round = 0
                st.session_state.simulation_history = []
                st.rerun()
        else:
            st.info("No simulation active")

elif page == "📧 Attack Campaigns":
    st.header("📧 Attack Campaign Simulation")
    
    if st.session_state.simulator is None:
        st.warning("⚠️ Please set up a simulation first!")
        st.stop()
    
    sim = st.session_state.simulator
    
    # Attack configuration
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("🎯 Phishing Campaign")
        
        # Target selection
        available_nodes = list(sim.nodes.keys())
        safe_nodes = [node_id for node_id, node in sim.nodes.items() if not node.compromised]
        
        target_count = st.slider("Number of targets", 1, len(safe_nodes), min(5, len(safe_nodes)))
        lure_type = st.selectbox("Lure Type", ["invoice", "payment", "receipt", "security alert", "prize notification"])
        click_rate = st.slider("Click Rate", 0.0, 1.0, 0.3, 0.05)
        
        if st.button("🚀 Launch Phishing Campaign", type="primary"):
            targets = random.sample(safe_nodes, min(target_count, len(safe_nodes)))
            
            # Store previous state
            st.session_state.prev_compromised = len([n for n in sim.nodes.values() if n.compromised])
            
            # Run campaign
            sim.time += 1
            st.session_state.current_round += 1
            events = sim.simulate_phishing_campaign(targets, lure=lure_type, click_rate=click_rate)
            
            # Store results
            campaign_result = {
                "round": st.session_state.current_round,
                "type": "phishing",
                "targets": len(targets),
                "events": len(events),
                "lure": lure_type,
                "click_rate": click_rate
            }
            st.session_state.simulation_history.append(campaign_result)
            
            st.success(f"✅ Phishing campaign completed! {len(events)} events generated.")
            
            # Show immediate results
            with st.expander("📋 Campaign Results"):
                for event in events:
                    node, action, detail = event
                    if action == "attachment_executed":
                        st.error(f"🔴 {node}: {action} - {detail}")
                    elif "detected" in action:
                        st.warning(f"🟡 {node}: {action} - {detail}")
                    else:
                        st.info(f"🔵 {node}: {action} - {detail}")
    
    with col2:
        st.subheader("🔗 Link-based Campaign")
        
        link_targets = st.slider("Link campaign targets", 1, len(safe_nodes), min(3, len(safe_nodes)))
        link_click_rate = st.slider("Link click rate", 0.0, 1.0, 0.15, 0.05)
        
        if st.button("🎣 Launch Link Campaign"):
            targets = random.sample(safe_nodes, min(link_targets, len(safe_nodes)))
            
            sim.time += 1
            st.session_state.current_round += 1
            events = sim.simulate_link_campaign(targets, click_rate=link_click_rate)
            
            campaign_result = {
                "round": st.session_state.current_round,
                "type": "link",
                "targets": len(targets),
                "events": len(events),
                "click_rate": link_click_rate
            }
            st.session_state.simulation_history.append(campaign_result)
            
            st.success(f"✅ Link campaign completed! {len(events)} events generated.")
    
    # Propagation simulation
    st.subheader("🔄 Lateral Movement Simulation")
    
    compromised_nodes = [n for n in sim.nodes.values() if n.compromised]
    
    if compromised_nodes:
        col3, col4 = st.columns(2)
        
        with col3:
            propagation_chance = st.slider("Propagation Success Rate", 0.0, 0.5, 0.05, 0.01)
        
        with col4:
            if st.button("⚡ Simulate Propagation"):
                events = sim.propagate(propagation_chance=propagation_chance)
                
                if events:
                    st.success(f"📈 Propagation attempt: {len(events)} lateral movement events")
                    for event in events:
                        source, action, target = event
                        st.info(f"🔄 {source} → {target}")
                else:
                    st.info("No successful propagation occurred")
    else:
        st.info("No compromised nodes available for propagation simulation")

elif page == "📊 Analytics":
    st.header("📊 Simulation Analytics")
    
    if st.session_state.simulator is None or not st.session_state.simulation_history:
        st.warning("⚠️ No simulation data available. Run some attack campaigns first!")
        st.stop()
    
    sim = st.session_state.simulator
    history = st.session_state.simulation_history
    
    # Campaign history
    st.subheader("📈 Campaign History")
    
    df_history = pd.DataFrame(history)
    
    if not df_history.empty:
        # Campaign types over time
        fig1 = px.line(df_history, x='round', y='events', color='type', 
                      title="Events Generated by Campaign Type Over Time")
        st.plotly_chart(fig1, use_container_width=True)
        
        # Success rates
        col1, col2 = st.columns(2)
        
        with col1:
            phishing_data = df_history[df_history['type'] == 'phishing']
            if not phishing_data.empty:
                fig2 = px.bar(phishing_data, x='round', y='targets', 
                             title="Phishing Campaign Targets by Round")
                st.plotly_chart(fig2, use_container_width=True)
        
        with col2:
            if 'click_rate' in df_history.columns:
                fig3 = px.scatter(df_history, x='targets', y='events', size='click_rate',
                                color='type', title="Campaign Effectiveness")
                st.plotly_chart(fig3, use_container_width=True)
    
    # Network analysis
    st.subheader("🌐 Network Analysis")
    
    # Compromise timeline
    compromised_nodes = [n for n in sim.nodes.values() if n.compromised]
    compromise_vectors = {}
    
    for node in compromised_nodes:
        vector = node.compromise_vector or "Unknown"
        compromise_vectors[vector] = compromise_vectors.get(vector, 0) + 1
    
    if compromise_vectors:
        col3, col4 = st.columns(2)
        
        with col3:
            fig4 = px.pie(values=list(compromise_vectors.values()), 
                         names=list(compromise_vectors.keys()),
                         title="Compromise Vectors Distribution")
            st.plotly_chart(fig4, use_container_width=True)
        
        with col4:
            # Detection effectiveness
            all_alerts = []
            for node in sim.nodes.values():
                for alert in node.detection_alerts:
                    all_alerts.append(alert['type'])
            
            if all_alerts:
                alert_counts = pd.Series(all_alerts).value_counts()
                fig5 = px.bar(x=alert_counts.index, y=alert_counts.values,
                            title="Detection Method Effectiveness")
                st.plotly_chart(fig5, use_container_width=True)

elif page == "🔍 Detection Lab":
    st.header("🔍 Detection Laboratory")
    
    if st.session_state.simulator is None:
        st.warning("⚠️ Please set up a simulation first!")
        st.stop()
    
    sim = st.session_state.simulator
    
    tab1, tab2, tab3 = st.tabs(["📝 Email Analysis", "🔍 Signature Detection", "📊 Heuristic Analysis"])
    
    with tab1:
        st.subheader("📧 Email Analysis Tool")
        
        # Create sample emails for testing
        col1, col2 = st.columns(2)
        
        with col1:
            st.write("**Create Test Email:**")
            sender = st.text_input("From", value="attacker@malicious.com")
            recipient = st.text_input("To", value="user1@example.com")
            subject = st.text_input("Subject", value="URGENT: Account Verification Required")
            body = st.text_area("Body", value="Dear user, click here to verify: http://bad.example/verify")
            has_attachment = st.checkbox("Has Attachment")
            
            if has_attachment:
                att_name = st.text_input("Attachment Name", value="invoice.docm")
                has_macro = st.checkbox("Contains Macro")
                if has_macro:
                    macro_behavior = st.selectbox("Macro Behavior", 
                                                 ["exfiltrate_simulated_credentials", "drop_ransom_note", "keylogger_stub"])
        
        with col2:
            st.write("**Analysis Results:**")
            
            if st.button("🔍 Analyze Email"):
                # Create test email
                attachment = None
                if has_attachment:
                    attachment = Document(
                        name=att_name,
                        content="Test content",
                        has_macro=has_macro,
                        macro_behavior=macro_behavior if has_macro else None
                    )
                
                test_email = Email(
                    sender=sender,
                    recipient=recipient,
                    subject=subject,
                    body=body,
                    attachment=attachment,
                    link="http://bad.example/verify" if "bad.example" in body else None
                )
                
                # Run detection
                sig_result = sim.sig.scan_email(test_email)
                heur_score, heur_reasons = sim.heur.score_email(test_email)
                
                # Display results
                if sig_result:
                    st.error(f"🚨 **SIGNATURE DETECTED:** {sig_result}")
                else:
                    st.success("✅ No signatures matched")
                
                st.info(f"🎯 **Heuristic Score:** {heur_score:.2f}")
                if heur_reasons:
                    st.warning(f"📋 **Risk Factors:** {', '.join(heur_reasons)}")
                
                # Risk assessment
                if heur_score >= 0.8:
                    st.error("⚠️ **HIGH RISK** - Likely malicious")
                elif heur_score >= 0.5:
                    st.warning("🟡 **MEDIUM RISK** - Suspicious")
                else:
                    st.success("🟢 **LOW RISK** - Appears benign")
    
    with tab2:
        st.subheader("🎯 Signature Detection System")
        
        # Display current signatures
        st.write("**Known Signatures:**")
        for sig in sim.sig.KNOWN_SIGNATURES:
            st.code(sig)
        
        # Signature management
        st.write("**Add Custom Signature:**")
        new_sig = st.text_input("New Signature Pattern")
        if st.button("➕ Add Signature"):
            if new_sig and new_sig not in sim.sig.KNOWN_SIGNATURES:
                sim.sig.KNOWN_SIGNATURES.append(new_sig)
                st.success(f"✅ Added signature: {new_sig}")
            else:
                st.warning("⚠️ Signature already exists or is empty")
    
    with tab3:
        st.subheader("📈 Heuristic Rule Engine")
        
        # Show heuristic rules
        st.write("**Current Heuristic Rules:**")
        
        rules_info = {
            "Suspicious Subject Keywords": 0.3,
            "Contains Link": 0.3,
            "Short URL Domain": 0.2,
            "Known Bad Domain": 0.5,
            "Has Attachment": 0.25,
            "Macro Attachment": 0.4
        }
        
        for rule, weight in rules_info.items():
            col1, col2 = st.columns([3, 1])
            with col1:
                st.write(f"• {rule}")
            with col2:
                st.metric("Weight", weight)

elif page == "📚 Educational Content":
    st.header("📚 Educational Resources")
    
    tab1, tab2, tab3, tab4 = st.tabs(["🎯 Attack Vectors", "🛡️ Detection Methods", "📊 Case Studies", "🔬 Research"])
    
    with tab1:
        st.subheader("🎯 Common Attack Vectors")
        
        st.markdown("""
        ### 📧 Phishing Emails
        
        **Characteristics:**
        - Urgent or threatening language
        - Requests for sensitive information
        - Suspicious sender addresses
        - Generic greetings ("Dear Customer")
        - Poor spelling/grammar
        
        **Examples in Simulation:**
        - Invoice requests with malicious attachments
        - Account verification emails with malicious links
        - Prize notifications requiring personal information
        """)
        
        st.markdown("""
        ### 📎 Malicious Attachments
        
        **Common Types:**
        - Microsoft Office documents with macros
        - Executable files disguised as documents
        - Archive files containing malware
        
        **Macro Behaviors Simulated:**
        - Credential exfiltration
        - Ransomware deployment
        - System reconnaissance
        """)
        
        st.markdown("""
        ### 🔗 Drive-by Downloads
        
        **Mechanism:**
        - Malicious websites hosting exploit kits
        - Compromised legitimate websites
        - Social engineering to visit malicious URLs
        """)
    
    with tab2:
        st.subheader("🛡️ Detection and Prevention")
        
        st.markdown("""
        ### 🔍 Signature-Based Detection
        
        **How it Works:**
        - Maintains database of known malicious patterns
        - Scans emails/attachments for exact matches
        - Fast and accurate for known threats
        
        **Limitations:**
        - Cannot detect new/unknown threats
        - Easily bypassed with minor modifications
        - Requires frequent signature updates
        """)
        
        st.markdown("""
        ### 🧠 Heuristic Analysis
        
        **Approach:**
        - Analyzes email characteristics and behaviors
        - Assigns risk scores based on suspicious indicators
        - Can detect previously unknown threats
        
        **Risk Factors:**
        - Suspicious subject lines
        - Presence of attachments or links
        - Known malicious domains
        - Social engineering indicators
        """)
        
        st.markdown("""
        ### 📊 Anomaly Detection
        
        **Method:**
        - Establishes baseline behavior patterns
        - Detects deviations from normal activity
        - Useful for identifying compromised accounts
        
        **Applications:**
        - Unusual email volume patterns
        - Abnormal file access behavior
        - Suspicious network communications
        """)
    
    with tab3:
        st.subheader("📊 Real-World Case Studies")
        
        st.markdown("""
        ### 🏢 Corporate Email Compromise
        
        **Scenario:** A mid-size company receives targeted phishing emails
        
        **Attack Chain:**
        1. **Reconnaissance:** Attackers research company structure
        2. **Spear Phishing:** Targeted emails to executives
        3. **Credential Harvesting:** Fake login pages collect passwords
        4. **Lateral Movement:** Compromised accounts spread malware
        5. **Data Exfiltration:** Sensitive documents stolen
        
        **Detection Points:**
        - Email gateway scans catch some attachments
        - Heuristic analysis flags suspicious emails
        - Anomaly detection notices unusual login patterns
        
        **Lessons Learned:**
        - Multi-layered security is essential
        - User training significantly reduces success rates
        - Incident response planning is critical
        """)
        
        st.markdown("""
        ### 🏥 Healthcare Ransomware Attack
        
        **Scenario:** Hospital network compromised via email attachment
        
        **Timeline:**
        1. **Day 0:** Nurse opens malicious invoice attachment
        2. **Day 1:** Ransomware spreads to medical devices
        3. **Day 2:** Patient systems become unavailable
        4. **Day 3:** Hospital diverts emergency cases
        5. **Week 1:** Gradual system restoration begins
        
        **Impact:**
        - Patient safety at risk
        - Significant financial losses
        - Regulatory investigations
        - Reputation damage
        """)
    
    with tab4:
        st.subheader("🔬 Research and Development")
        
        st.markdown("""
        ### 🤖 AI-Powered Detection
        
        **Machine Learning Approaches:**
        - Natural Language Processing for email content analysis
        - Behavioral analysis using deep learning
        - Graph neural networks for attack pattern recognition
        
        **Advantages:**
        - Can adapt to new attack methods
        - Reduced false positive rates
        - Automated threat hunting capabilities
        
        **Challenges:**
        - Requires large training datasets
        - Adversarial attacks on ML models
        - Explainability and interpretability issues
        """)
        
        st.markdown("""
        ### 🔐 Zero Trust Architecture
        
        **Principles:**
        - "Never trust, always verify"
        - Least privilege access
        - Continuous monitoring and validation
        
        **Implementation:**
        - Identity and access management
        - Micro-segmentation
        - Encrypted communications
        - Real-time risk assessment
        """)
    
    # Interactive learning section
    st.divider()
    st.subheader("🧪 Interactive Learning")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        **📝 Quick Quiz:**
        
        Test your knowledge with these questions:
        """)
        
        q1 = st.radio("What is the most effective way to prevent phishing attacks?", 
                     ["Email filters only", "User education + technology", "Signature-based detection only"])
        
        if q1 == "User education + technology":
            st.success("✅ Correct! Layered security is most effective.")
        else:
            st.error("❌ Incorrect. Try again!")
    
    with col2:
        st.markdown("""
        **🎯 Best Practices:**
        
        - Verify sender identity before clicking links
        - Keep software and signatures updated
        - Use multi-factor authentication
        - Regular security awareness training
        - Implement comprehensive backup strategies
        - Develop and test incident response plans
        """)

# Footer
st.divider()
st.markdown("""
<div style='text-align: center; color: #666; padding: 1rem;'>
    <p>🛡️ <strong>Email & Document Virus Simulator</strong> - Educational Cybersecurity Tool</p>
    <p><em>This is a safe, educational simulation. No real malware or network operations are performed.</em></p>
</div>
""", unsafe_allow_html=True)