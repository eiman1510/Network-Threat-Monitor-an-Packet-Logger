# Network Attack Simulation and Intrusion Detection System

A comprehensive web-based tool for simulating various network attacks and monitoring network traffic in real-time. This project provides both educational value for understanding different types of network attacks and practical utility for testing intrusion detection capabilities.

## Features

- **Real-time Network Monitoring**: Monitor network traffic with detailed packet analysis
- **Attack Simulation**: Simulate various types of network attacks:
  - Phishing Attempts
  - SQL Injection
  - Port Scanning (TCP/UDP)
  - DDoS Attacks
  - TCP/UDP Traffic Analysis

- **Web Interface**: User-friendly web dashboard for:
  - Starting/stopping packet sniffing
  - Viewing real-time logs
  - Filtering traffic by attack type
  - Clearing logs
  - Running attack simulations

## Prerequisites

- Python 3.x
- Flask
- Scapy
- psutil

## Installation

1. Clone the repository:
```bash
git clone [repository-url]
cd network-attack-simulation-and-intrusion-detection
```

2. Install required Python packages:
```bash
pip install flask scapy psutil
```

## Usage

1. Start the web application:
```bash
python app.py
```

2. Access the web interface:
   - Open your browser and navigate to `http://localhost:5000`
   - The dashboard will be available for monitoring and control

3. Running Attack Simulations:
   - Select an attack type from the web interface
   - Click "Start Simulation" to begin the attack
   - Monitor the results in real-time through the log viewer

## Project Structure

- `app.py` - Flask web application
- `script.py` - Network monitoring and attack detection script
- `scripts/` - Individual attack simulation scripts
- `static/` - Web interface assets
- `templates/` - HTML templates
- `logs/` - Network traffic and attack logs

## Attack Types

1. **Phishing Detection**
   - Monitors for suspicious URLs and common phishing patterns
   - Detects potential credential harvesting attempts

2. **SQL Injection**
   - Identifies common SQL injection patterns
   - Monitors for suspicious SQL commands in network traffic

3. **Port Scanning**
   - Detects various types of port scans:
     - TCP CONNECT scan
     - NULL scan
     - XMAS scan
     - FIN scan
     - UDP scan

4. **DDoS Detection**
   - Monitors for high-frequency traffic patterns
   - Identifies potential distributed denial of service attacks

## Security Notice

This tool is designed for educational and testing purposes only. Do not use it to perform attacks on systems you don't own or have explicit permission to test. Unauthorized network attacks are illegal and unethical.

## Contributing

Contributions are welcome! Please feel free to submit pull requests, report bugs, or suggest new features.

## License

[Add appropriate license information] 