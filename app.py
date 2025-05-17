from flask import Flask, render_template, request, jsonify, send_from_directory
import subprocess
import os
import platform
import sys
import signal
import psutil
import time

app = Flask(__name__)
LOG_FILE = "logs/network_traffic.log"

# Create logs directory if it doesn't exist
os.makedirs("logs", exist_ok=True)
if not os.path.exists(LOG_FILE):
    with open(LOG_FILE, "w") as f:
        f.write("")

PYTHON_EXECUTABLE = sys.executable
sniffer_process = None

# Dictionary that maps attack type to script path
SCRIPTS = {
    "phishing": "scripts/phishing.py",
    "sql": "scripts/sql.py",
    "scan": "scripts/scan.py",
    "tcp": "scripts/tcp.py",
    "udp": "scripts/udp.py",
    "ddos": "scripts/ddos.py"
}

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/static/<path:path>")
def serve_static(path):
    return send_from_directory("static", path)

@app.route("/status", methods=["GET"])
def check_status():
    global sniffer_process
    is_running = False
    current_mode = "none"

    if sniffer_process is not None:
        try:
            process = psutil.Process(sniffer_process.pid)
            is_running = process.is_running()
            # Check if there's a filter applied by inspecting command line arguments
            cmdline = process.cmdline()
            for arg in cmdline:
                if arg.startswith("--attack="):
                    current_mode = arg.split("=")[1]
        except (psutil.NoSuchProcess, AttributeError):
            sniffer_process = None
            is_running = False

    return jsonify({
        "status": "running" if is_running else "stopped",
        "mode": current_mode
    })

@app.route("/start_sniffer", methods=["POST"])
def start_sniffer():
   
    global sniffer_process
    
    attack_type = request.json.get("filter")  # Get optional filter
    
    try:
        if sniffer_process is not None:
            stop_sniffer()  # stop any running instance first
        
        # Clear logs before starting
        if request.json.get("clear_logs", False):
            with open(LOG_FILE, "w") as f:
                f.write("")
        
        cmd = [PYTHON_EXECUTABLE, "script.py", "--start"]  # Add the start flag
        
        # Add attack filter if provided
        if attack_type and attack_type in SCRIPTS.keys():
            cmd.append(f"--attack={attack_type}")
        
        # Determine how to start the script based on OS
        if platform.system() == "Windows":
            sniffer_process = subprocess.Popen(
                cmd,
                creationflags=subprocess.CREATE_NEW_CONSOLE
            )
        else:
            sniffer_process = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                preexec_fn=os.setsid
            )
        
        # Small delay to ensure process starts properly
        time.sleep(0.5)
        
        if attack_type:
            return jsonify({
                "status": "success", 
                "message": f"Packet sniffer started with {attack_type.upper()} filter."
            })
        else:
            return jsonify({
                "status": "success", 
                "message": "Packet sniffer started successfully."
            })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route("/stop_sniffer", methods=["POST"])
def stop_sniffer():
    global sniffer_process

    try:
        if sniffer_process is not None:
            if platform.system() == "Windows":
                sniffer_process.terminate()
            else:
                os.killpg(os.getpgid(sniffer_process.pid), signal.SIGTERM)
            sniffer_process = None
            return jsonify({"status": "success", "message": "Packet sniffer stopped."})
        else:
            return jsonify({"status": "warning", "message": "No sniffer was running."})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route("/run_attack", methods=["POST"])
def run_attack():
    attack_type = request.json.get("attack")
    script = SCRIPTS.get(attack_type)

    if script and os.path.exists(script):
        try:
            # Start the sniffer with the current attack mode if not already running
            if sniffer_process is None:
                start_sniffer_result = start_sniffer()
                response_data = start_sniffer_result.get_json()
                if response_data.get("status") != "success":
                    return jsonify({
                        "status": "error", 
                        "message": "Failed to start packet sniffer before attack."
                    })
            
            # Run the attack script
            subprocess.Popen([PYTHON_EXECUTABLE, script])
            
            return jsonify({
                "status": "success", 
                "message": f"{attack_type.upper()} simulation running."
            })
        except Exception as e:
            return jsonify({
                "status": "error", 
                "message": f"Error executing {attack_type} script: {str(e)}"
            })
    return jsonify({
        "status": "error", 
        "message": "Invalid attack type or script not found."
    })

@app.route("/filter_logs", methods=["POST"])
def filter_logs():
    attack_type = request.json.get("filter")
    
    # Restart the sniffer with the new filter
    result = start_sniffer()
    return result

@app.route("/logs", methods=["GET"])
def read_logs():
    if os.path.exists(LOG_FILE):
        try:
            with open(LOG_FILE, "r") as f:
                lines = f.readlines()[-500:]  # Get last 500 lines
            return jsonify({"logs": lines})
        except Exception as e:
            return jsonify({"status": "error", "message": f"Error reading logs: {str(e)}"})
    return jsonify({"logs": []})

@app.route("/clear_logs", methods=["POST"])
def clear_logs():
    try:
        with open(LOG_FILE, "w") as f:
            f.write("")
        return jsonify({"status": "success", "message": "Logs cleared successfully."})
    except Exception as e:
        return jsonify({"status": "error", "message": f"Error clearing logs: {str(e)}"})

if __name__ == "__main__":
    app.run(debug=True, use_reloader=False)
