"""
Enhanced Virus Simulation with Streamlit Interface

This Streamlit app provides an interactive web interface for the educational virus simulation.
Features:
- Interactive parameter controls
- Real-time visualization
- Network topology display
- Host status monitoring
- Defense system analytics
"""

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import networkx as nx
import random
import time
from collections import defaultdict
import json

# Import the original simulation classes
from pathlib import Path
import sys
sys.path.append(str(Path(__file__).parent))

# Import classes from the original file
import importlib.util
spec = importlib.util.spec_from_file_location("virus_sim", "3.py")
virus_sim = importlib.util.module_from_spec(spec)
spec.loader.exec_module(virus_sim)

# Use the classes from the original file
Host = virus_sim.Host
BehaviorProfile = virus_sim.BehaviorProfile
Defender = virus_sim.Defender
NetworkSimulator = virus_sim.NetworkSimulator

class StreamlitNetworkSimulator(NetworkSimulator):
    """Enhanced NetworkSimulator with Streamlit-specific features."""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.host_status_history = defaultdict(list)
        self.alert_history = []
        
    def step(self):
        """Enhanced step method that tracks more detailed statistics."""
        infections_this_step = super().step()
        
        # Track individual host statuses
        for nid, data in self.graph.nodes(data=True):
            host = data["obj"]
            self.host_status_history[nid].append({
                'time': self.time,
                'infected': host.infected,
                'quarantined': host.quarantined,
                'patched': host.patched,
                'cpu': host.cpu,
                'infection_age': host.infection_age if host.infected else 0
            })
        
        # Track alerts
        if hasattr(self.defender, 'alerts') and self.defender.alerts:
            latest_alerts = self.defender.alerts[-len(infections_this_step):] if infections_this_step else []
            for alert in latest_alerts:
                alert['time'] = self.time
                self.alert_history.append(alert)
        
        return infections_this_step

def create_network_graph(G, pos=None):
    """Create a Plotly network graph visualization."""
    if pos is None:
        pos = nx.spring_layout(G, seed=42)
    
    # Extract node information
    node_info = []
    edge_info = []
    
    for node in G.nodes():
        host = G.nodes[node]['obj']
        x, y = pos[node]
        
        # Determine node color based on status
        color = 'green'  # healthy
        if host.quarantined:
            color = 'gray'
        elif host.infected:
            color = 'red'
        elif host.patched:
            color = 'blue'
        
        node_info.append({
            'x': x, 'y': y, 'id': node, 'color': color,
            'cpu': host.cpu, 'infected': host.infected,
            'quarantined': host.quarantined, 'patched': host.patched
        })
    
    # Extract edge information
    for edge in G.edges():
        x0, y0 = pos[edge[0]]
        x1, y1 = pos[edge[1]]
        edge_info.append({'x0': x0, 'y0': y0, 'x1': x1, 'y1': y1})
    
    return node_info, edge_info, pos

def plot_network(node_info, edge_info):
    """Create Plotly network visualization."""
    fig = go.Figure()
    
    # Add edges
    for edge in edge_info:
        fig.add_trace(go.Scatter(
            x=[edge['x0'], edge['x1'], None],
            y=[edge['y0'], edge['y1'], None],
            mode='lines',
            line=dict(width=0.5, color='lightgray'),
            hoverinfo='none',
            showlegend=False
        ))
    
    # Add nodes
    colors = [node['color'] for node in node_info]
    fig.add_trace(go.Scatter(
        x=[node['x'] for node in node_info],
        y=[node['y'] for node in node_info],
        mode='markers',
        marker=dict(
            size=10,
            color=colors,
            line=dict(width=1, color='black')
        ),
        text=[f"Host {node['id']}<br>CPU: {node['cpu']:.1f}%<br>Status: {'Infected' if node['infected'] else 'Quarantined' if node['quarantined'] else 'Patched' if node['patched'] else 'Healthy'}" 
              for node in node_info],
        hoverinfo='text',
        name='Hosts'
    ))
    
    fig.update_layout(
        title="Network Topology and Infection Status",
        showlegend=True,
        height=500,
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False)
    )
    
    return fig

def plot_infection_timeline(history):
    """Create interactive timeline of infection spread."""
    times = [h["time"] for h in history]
    infected = [h["infected"] for h in history]
    quarantined = [h["quarantined"] for h in history]
    
    fig = go.Figure()
    
    fig.add_trace(go.Scatter(
        x=times, y=infected,
        mode='lines+markers',
        name='Infected Hosts',
        line=dict(color='red', width=2)
    ))
    
    fig.add_trace(go.Scatter(
        x=times, y=quarantined,
        mode='lines+markers',
        name='Quarantined Hosts',
        line=dict(color='gray', width=2)
    ))
    
    fig.update_layout(
        title="Infection Spread Over Time",
        xaxis_title="Time Step",
        yaxis_title="Number of Hosts",
        height=400
    )
    
    return fig

def plot_cpu_heatmap(host_status_history, current_time):
    """Create CPU usage heatmap."""
    if not host_status_history:
        return go.Figure()
    
    # Prepare data for heatmap
    hosts = list(host_status_history.keys())
    times = list(range(max(1, current_time - 19), current_time + 1))  # Last 20 time steps
    
    cpu_data = []
    for host in hosts:
        cpu_row = []
        for t in times:
            # Find CPU data for this host at this time
            cpu_val = 0
            for record in host_status_history[host]:
                if record['time'] == t:
                    cpu_val = record['cpu']
                    break
            cpu_row.append(cpu_val)
        cpu_data.append(cpu_row)
    
    fig = go.Figure(data=go.Heatmap(
        z=cpu_data,
        x=[f"T-{current_time-t}" for t in times],
        y=[f"Host {h}" for h in hosts],
        colorscale='Reds',
        showscale=True
    ))
    
    fig.update_layout(
        title="CPU Usage Heatmap (Last 20 Steps)",
        xaxis_title="Time (relative to current)",
        yaxis_title="Hosts",
        height=400
    )
    
    return fig

def main():
    st.set_page_config(
        page_title="Virus Simulation Dashboard",
        page_icon="🦠",
        layout="wide"
    )
    
    st.title("🦠 Educational Virus Simulation Dashboard")
    st.markdown("Interactive network security simulation for educational purposes")
    
    # Sidebar for parameters
    st.sidebar.header("Simulation Parameters")
    
    # Network parameters
    n_hosts = st.sidebar.slider("Number of Hosts", 20, 200, 80)
    network_degree = st.sidebar.slider("Network Connectivity", 2, 8, 4)
    
    # Infection parameters
    n_seeds = st.sidebar.slider("Initial Infected Hosts", 1, 10, 3)
    
    # Defender parameters
    anomaly_threshold = st.sidebar.slider("Anomaly Detection Threshold", 10.0, 50.0, 20.0)
    known_signatures = st.sidebar.multiselect(
        "Known Malware Signatures",
        ["stealthy_keylogger", "noisy_ransomish"],
        default=["noisy_ransomish"]
    )
    
    # Simulation control
    st.sidebar.header("Simulation Control")
    max_steps = st.sidebar.slider("Max Simulation Steps", 10, 200, 60)
    
    # Initialize simulation button
    if st.sidebar.button("Initialize New Simulation"):
        st.session_state.simulation_initialized = True
        st.session_state.current_step = 0
        
        # Create behavior profiles
        stealthy = BehaviorProfile(name="stealthy_keylogger", peak_cpu=30.0, stealthy=True)
        noisy = BehaviorProfile(name="noisy_ransomish", peak_cpu=80.0, stealthy=False)
        profiles = {stealthy.name: stealthy, noisy.name: noisy}
        
        # Create defender
        defender = Defender(signature_db=known_signatures, anomaly_threshold=anomaly_threshold)
        
        # Build network
        G = virus_sim.build_random_network(n_hosts=n_hosts, degree=network_degree)
        
        # Create simulator
        simulator = StreamlitNetworkSimulator(graph=G, defender=defender, behavior_profiles=profiles)
        
        # Infect seed hosts
        seed_hosts = random.sample(list(G.nodes()), k=n_seeds)
        for s in seed_hosts:
            profile = random.choice([stealthy, noisy])
            G.nodes[s]["obj"].apply_infection(profile)
        
        # Store in session state
        st.session_state.simulator = simulator
        st.session_state.network_pos = nx.spring_layout(G, seed=42)
        
        st.success(f"Simulation initialized with {n_hosts} hosts and {n_seeds} initial infections!")
    
    # Main simulation interface
    if hasattr(st.session_state, 'simulation_initialized') and st.session_state.simulation_initialized:
        
        # Simulation controls
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            if st.button("Step Forward"):
                if st.session_state.current_step < max_steps:
                    st.session_state.simulator.step()
                    st.session_state.current_step += 1
        
        with col2:
            if st.button("Run 5 Steps"):
                for _ in range(min(5, max_steps - st.session_state.current_step)):
                    st.session_state.simulator.step()
                    st.session_state.current_step += 1
        
        with col3:
            if st.button("Run to End"):
                while st.session_state.current_step < max_steps:
                    st.session_state.simulator.step()
                    st.session_state.current_step += 1
        
        with col4:
            st.metric("Current Step", st.session_state.current_step)
        
        # Display current statistics
        if st.session_state.simulator.infection_history:
            latest_stats = st.session_state.simulator.infection_history[-1]
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                st.metric("Infected Hosts", latest_stats['infected'])
            with col2:
                st.metric("Quarantined Hosts", latest_stats['quarantined'])
            with col3:
                total_patched = sum(1 for _, d in st.session_state.simulator.graph.nodes(data=True) 
                                  if d["obj"].patched)
                st.metric("Patched Hosts", total_patched)
            with col4:
                healthy_hosts = n_hosts - latest_stats['infected'] - latest_stats['quarantined']
                st.metric("Healthy Hosts", healthy_hosts)
        
        # Visualizations
        if st.session_state.current_step > 0:
            
            # Network topology
            node_info, edge_info, _ = create_network_graph(
                st.session_state.simulator.graph, 
                st.session_state.network_pos
            )
            network_fig = plot_network(node_info, edge_info)
            st.plotly_chart(network_fig, use_container_width=True)
            
            # Timeline and heatmap in columns
            col1, col2 = st.columns(2)
            
            with col1:
                timeline_fig = plot_infection_timeline(st.session_state.simulator.infection_history)
                st.plotly_chart(timeline_fig, use_container_width=True)
            
            with col2:
                cpu_fig = plot_cpu_heatmap(
                    st.session_state.simulator.host_status_history,
                    st.session_state.current_step
                )
                st.plotly_chart(cpu_fig, use_container_width=True)
            
            # Alert history
            if st.session_state.simulator.alert_history:
                st.subheader("Security Alerts")
                alerts_df = pd.DataFrame(st.session_state.simulator.alert_history)
                st.dataframe(alerts_df, use_container_width=True)
            
            # Host details
            st.subheader("Host Status Details")
            
            # Create summary table
            host_data = []
            for nid, data in st.session_state.simulator.graph.nodes(data=True):
                host = data["obj"]
                host_data.append({
                    'Host ID': nid,
                    'Status': 'Quarantined' if host.quarantined else 'Infected' if host.infected else 'Patched' if host.patched else 'Healthy',
                    'CPU Usage': f"{host.cpu:.1f}%",
                    'Infection Age': host.infection_age if host.infected else 0,
                    'Recent Logs': '; '.join(list(host.logs)[-2:]) if host.logs else 'No recent activity'
                })
            
            hosts_df = pd.DataFrame(host_data)
            st.dataframe(hosts_df, use_container_width=True)
    
    else:
        st.info("👈 Use the sidebar to configure and initialize a new simulation.")
        
        # Show some information about the simulation
        st.header("About This Simulation")
        st.markdown("""
        This educational virus simulation demonstrates:
        
        - **Network Topology**: Hosts connected in a small-world network
        - **Infection Spread**: Malware propagates between connected hosts
        - **Behavior Profiles**: Different types of malware with varying characteristics
        - **Defense Systems**: Signature-based and anomaly-based detection
        - **Mitigation**: Quarantine and patching responses
        
        ### Features:
        - 🌐 Interactive network visualization
        - 📊 Real-time infection tracking
        - 🔥 CPU usage heatmaps
        - 🚨 Security alert monitoring
        - ⚙️ Configurable parameters
        """)

if __name__ == "__main__":
    main()
