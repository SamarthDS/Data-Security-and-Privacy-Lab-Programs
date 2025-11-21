# Enhanced Virus Simulation with Streamlit

This project provides an interactive educational virus simulation with a web-based interface built using Streamlit.

## Features

### 🌐 Interactive Network Visualization
- Real-time network topology display
- Color-coded host status (healthy, infected, quarantined, patched)
- Hover information for detailed host stats

### 📊 Real-time Analytics
- Infection spread timeline
- CPU usage heatmaps
- Security alert monitoring
- Host status tracking

### ⚙️ Configurable Parameters
- Network size and connectivity
- Initial infection parameters
- Defender sensitivity settings
- Simulation duration

### 🔍 Enhanced Monitoring
- Individual host logs
- Alert history
- Performance metrics
- Status summaries

## Installation

1. Create and activate a virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

1. Run the Streamlit application:
```bash
streamlit run streamlit_app.py
```

2. Open your web browser and navigate to the provided URL (typically http://localhost:8501)

3. Use the sidebar to configure simulation parameters:
   - Adjust network size and connectivity
   - Set initial infection parameters
   - Configure defender settings

4. Click "Initialize New Simulation" to start

5. Use the simulation controls to:
   - Step through the simulation manually
   - Run multiple steps at once
   - Run to completion

## Simulation Components

### Host Types
- **Healthy**: Normal operation with baseline CPU usage
- **Infected**: Compromised hosts showing malicious behavior
- **Quarantined**: Isolated hosts removed from network
- **Patched**: Protected hosts immune to infection

### Malware Profiles
- **Stealthy Keylogger**: Low CPU usage, harder to detect
- **Noisy Ransomware**: High CPU usage, easier to detect

### Defense Mechanisms
- **Signature Detection**: Identifies known malware patterns
- **Anomaly Detection**: Flags unusual CPU usage patterns
- **Response Actions**: Quarantine or patch affected hosts

## Educational Purpose

This simulation is designed for educational use to demonstrate:
- Network security concepts
- Malware propagation patterns
- Defense system effectiveness
- Incident response strategies

**Note**: This is a completely safe, in-memory simulation that performs no real file or network operations.
