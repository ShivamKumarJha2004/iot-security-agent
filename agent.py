"""
Agentic IoT Security - Python Agent
Collects system metrics and sends to n8n/backend for AI analysis
"""

import os
import psutil
import requests
import time
import socket
import subprocess
import platform
import json
from datetime import datetime

# Try to load environment variables from .env file
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # python-dotenv not installed, use defaults

# Configuration (with environment variable fallback)
N8N_WEBHOOK_URL = os.getenv(
    "N8N_WEBHOOK_URL",
    "https://n8n.unifostedu.com/webhook/5dde489c-3ed6-4e04-a8ec-d9b659504330"
)
BACKEND_URL = os.getenv(
    "BACKEND_URL",
    "https://iot-security-backend-kzze.onrender.com/api/logs/iot"
)
BACKEND_BASE_URL = os.getenv(
    "BACKEND_BASE_URL",
    "https://iot-security-backend-kzze.onrender.com"
)
DEVICE_ID = os.getenv("DEVICE_ID", "Laptop-01")
DEVICE_NAME = os.getenv("DEVICE_NAME", "IoT Security Agent")
COLLECTION_INTERVAL = int(os.getenv("COLLECTION_INTERVAL", "10"))  # seconds

# Simulated attack data (for demo purposes)
simulated_attacks = {
    "failed_logins": 0,
    "suspicious_ports": [],
    "suspicious_process": None
}

def get_network_info():
    """Get network connection details"""
    connections = psutil.net_connections(kind='inet')
    active_connections = len([c for c in connections if c.status == 'ESTABLISHED'])
    
    # Get local IP
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except:
        local_ip = "127.0.0.1"
    
    return {
        "local_ip": local_ip,
        "active_connections": active_connections
    }

def get_open_ports():
    """Get list of open/listening ports"""
    open_ports = []
    for conn in psutil.net_connections(kind='inet'):
        if conn.status == 'LISTEN' and conn.laddr:
            open_ports.append(conn.laddr.port)
    return list(set(open_ports))

def get_running_processes():
    """Get list of running processes"""
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent']):
        try:
            processes.append({
                "pid": proc.info['pid'],
                "name": proc.info['name'],
                "cpu": proc.info['cpu_percent']
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return processes

def check_suspicious_processes():
    """Check for suspicious/unknown processes"""
    suspicious_keywords = ['nc.exe', 'netcat', 'mimikatz', 'pwdump', 'keylogger']
    
    for proc in psutil.process_iter(['name']):
        try:
            name = proc.info['name'].lower()
            for keyword in suspicious_keywords:
                if keyword in name:
                    return name
        except:
            pass
    
    return simulated_attacks.get("suspicious_process")

def collect_data():
    """Collect system metrics for security analysis"""
    network = get_network_info()
    open_ports = get_open_ports()
    
    # Add simulated attack ports if any
    for port in simulated_attacks.get("suspicious_ports", []):
        if port not in open_ports:
            open_ports.append(port)
    
    data = {
        "device": DEVICE_ID,
        "device_name": DEVICE_NAME,
        "timestamp": datetime.now().isoformat(),
        
        # System metrics
        "cpu": psutil.cpu_percent(interval=1),
        "memory": psutil.virtual_memory().percent,
        "disk_usage": psutil.disk_usage('/').percent if platform.system() != 'Windows' else psutil.disk_usage('C:\\').percent,
        
        # Network metrics
        "local_ip": network["local_ip"],
        "network_connections": network["active_connections"],
        "open_ports": open_ports,
        
        # Security indicators (simulated + real)
        "failed_logins": simulated_attacks.get("failed_logins", 0),
        "suspicious_process": check_suspicious_processes(),
        
        # System info
        "os": platform.system(),
        "hostname": socket.gethostname()
    }
    
    return data

def send_to_n8n(data):
    """Send data to n8n webhook and return AI analysis"""
    try:
        response = requests.post(N8N_WEBHOOK_URL, json=data, timeout=30)
        print(f"[n8n] Status: {response.status_code}")
        
        if response.status_code == 200:
            try:
                # Get the analysis from n8n response
                n8n_data = response.json()
                
                # Handling n8n response structure (sometimes it's a list, sometimes dict)
                if isinstance(n8n_data, list) and len(n8n_data) > 0:
                    analysis = n8n_data[0]
                else:
                    analysis = n8n_data
                
                # Merge original data with n8n analysis for complete context
                n8n_response_payload = {
                    **data,  # Include original device data
                    **analysis  # Include n8n analysis (isAttack, attack_type, severity, etc.)
                }
                
                # Send complete n8n response to backend for agentic response logging
                try:
                    backend_response = requests.post(
                        f"{BACKEND_BASE_URL}/api/logs/n8n-response",
                        json=n8n_response_payload,
                        timeout=10
                    )
                    if backend_response.status_code == 201:
                        print("✅ Agentic response logged to backend")
                    else:
                        print(f"⚠️ Backend response: {backend_response.status_code}")
                except Exception as e:
                    print(f"❌ Failed to send agentic response to backend: {e}")
                    
                # If n8n detected an attack, show alert
                if analysis.get('isAttack') == True or analysis.get('isAttack') == 'true':
                    print(f"🚨 AGENTIC AI ALERT: {analysis.get('attack_type', 'Threat')} detected!")
                    print(f"👉 Severity: {analysis.get('severity', 'high')}")
                    print(f"👉 Recommendation: {analysis.get('recommendation', 'Take action')}")
                    print(f"👉 Action: {analysis.get('action_taken', analysis.get('action', 'notified'))}")
                else:
                    print(f"✅ Agentic AI: No threats detected - System Normal")
                
                return analysis
            except Exception as e:
                print(f"⚠️ Failed to parse n8n response: {e}")
        return None
    except requests.exceptions.RequestException as e:
        print(f"[n8n] Error: {e}")
        return None

def send_to_backend(data):
    """Send raw metrics to backend for logging"""
    try:
        requests.post(BACKEND_URL, json=data, timeout=10)
        return True
    except requests.exceptions.RequestException as e:
        print(f"[Backend] Error: {e}")
        return False

def print_status(data):
    """Print current system status"""
    print(f"""
╔══════════════════════════════════════════════════════════╗
║           🖥️  IoT Security Agent - {data['device']:<15}    ║
╠══════════════════════════════════════════════════════════╣
║  Time: {data['timestamp'][:19]:<20}                     ║
║  CPU: {data['cpu']:.1f}%  |  Memory: {data['memory']:.1f}%  |  Disk: {data['disk_usage']:.1f}%       ║
║  Network Connections: {data['network_connections']:<5}                          ║
║  Open Ports: {str(data['open_ports'][:5]):<30}         ║
║  Failed Logins: {data['failed_logins']:<5}                               ║
╚══════════════════════════════════════════════════════════╝
    """)

def main():
    """Main agent loop"""
    print("""
╔══════════════════════════════════════════════════════════╗
║         🛡️  Agentic IoT Security Agent Started 🛡️         ║
║                                                          ║
║  Device: {:<20}                           ║
║  Sending to: n8n + Backend                              ║
║  Interval: {} seconds                                    ║
╚══════════════════════════════════════════════════════════╝
    """.format(DEVICE_ID, COLLECTION_INTERVAL))
    
    # Keep running indefinitely (for Render background worker)
    iteration = 0
    while True:
        try:
            iteration += 1
            print(f"\n[Iteration {iteration}] Collecting data...")
            
            # Collect system data
            payload = collect_data()
            
            # Print status
            print_status(payload)
            
            # Send to both n8n and backend
            send_to_n8n(payload)
            send_to_backend(payload)
            
            print(f"✅ Data sent successfully. Waiting {COLLECTION_INTERVAL} seconds...")
            
            # Wait for next collection
            time.sleep(COLLECTION_INTERVAL)
            
        except KeyboardInterrupt:
            print("\n👋 Agent stopped by user")
            break
        except Exception as e:
            print(f"❌ Error: {e}")
            import traceback
            traceback.print_exc()
            print(f"⏳ Retrying in 5 seconds...")
            time.sleep(5)

if __name__ == "__main__":
    main()
