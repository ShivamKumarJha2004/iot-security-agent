"""
Attack Simulator for IoT Security Testing
Simulates various cyber attacks for demo purposes
"""

import os
import requests
import time
import random
import argparse
import socket
import threading
from datetime import datetime

# Try to load environment variables
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# Configuration (with environment variable fallback)
BACKEND_URL = os.getenv(
    "BACKEND_URL",
    "https://iot-security-backend-kzze.onrender.com/api/logs/iot"
)
N8N_WEBHOOK_URL = os.getenv(
    "N8N_WEBHOOK_URL",
    "https://n8n.unifostedu.com/webhook/5dde489c-3ed6-4e04-a8ec-d9b659504330"
)
N8N_RESPONSE_ENDPOINT = os.getenv(
    "N8N_RESPONSE_ENDPOINT",
    "https://iot-security-backend-kzze.onrender.com/api/logs/n8n-response"
)
BACKEND_BASE_URL = os.getenv(
    "BACKEND_BASE_URL",
    "https://iot-security-backend-kzze.onrender.com"
)
DEVICE_ID = os.getenv("DEVICE_ID", "Laptop-01")

def simulate_brute_force(intensity="medium"):
    """
    Simulate a Brute Force Attack
    - Sends increasing failed login attempts
    """
    print("""
╔═══════════════════════════════════════════════════════════╗
║           🔓 BRUTE FORCE ATTACK SIMULATION 🔓              ║
╠═══════════════════════════════════════════════════════════╣
║  Attack Type: SSH/Login Brute Force                       ║
║  Intensity: {:<10}                                       ║
║  Target: {}                                     ║
╚═══════════════════════════════════════════════════════════╝
    """.format(intensity, DEVICE_ID))
    
    attempts_map = {
        "low": [3, 4, 5],
        "medium": [6, 8, 10, 12],
        "high": [15, 20, 25, 30]
    }
    
    attempts = attempts_map.get(intensity, attempts_map["medium"])
    
    for i, failed_count in enumerate(attempts, 1):
        payload = {
            "device": DEVICE_ID,
            "device_name": "Attack Simulator",
            "timestamp": datetime.now().isoformat(),
            "cpu": random.uniform(20, 40),
            "memory": random.uniform(30, 50),
            "failed_logins": failed_count,
            "open_ports": [22, 80, 443],
            "network_connections": random.randint(10, 30),
            "attack_simulation": True,
            "attack_type": "brute_force"
        }
        
        print(f"  ⚡ Wave {i}/{len(attempts)}: Sending {failed_count} failed login attempts...")
        
        try:
            # Step 1: Send to n8n webhook for AI analysis
            print(f"     📤 Sending to n8n webhook...")
            n8n_response = requests.post(N8N_WEBHOOK_URL, json=payload, timeout=30)
            
            if n8n_response.status_code == 200:
                # Step 2: Get n8n analysis response
                n8n_data = n8n_response.json()
                
                # Handle n8n response structure (sometimes list, sometimes dict)
                if isinstance(n8n_data, list) and len(n8n_data) > 0:
                    analysis = n8n_data[0]
                else:
                    analysis = n8n_data
                
                # Step 3: Merge original payload with n8n analysis
                complete_response = {
                    **payload,  # Original data
                    **analysis  # n8n analysis (isAttack, attack_type, severity, etc.)
                }
                
                # Step 4: Send complete response to backend
                print(f"     📥 Forwarding n8n response to backend...")
                backend_response = requests.post(N8N_RESPONSE_ENDPOINT, json=complete_response, timeout=10)
                
                if backend_response.status_code == 201:
                    result = backend_response.json()
                    if result.get("agenticResponse", {}).get("isAttack"):
                        print(f"     🚨 AGENTIC AI DETECTED: {result['agenticResponse']['attackType']} - {result['agenticResponse']['severity']}")
                        print(f"     💡 Recommendation: {result['agenticResponse']['recommendation']}")
                    else:
                        print(f"     ✅ No attack detected")
                else:
                    print(f"     ⚠️ Backend response: {backend_response.status_code}")
            else:
                print(f"     ❌ n8n response error: {n8n_response.status_code}")
            
        except Exception as e:
            print(f"  ❌ Error: {e}")
        
        time.sleep(3)
    
    print("\n  ✅ Brute Force simulation complete!")

def simulate_port_scan():
    """
    Simulate a Port Scanning Attack
    - Sends suspicious port activity
    """
    print("""
╔═══════════════════════════════════════════════════════════╗
║              🔍 PORT SCAN ATTACK SIMULATION 🔍             ║
╠═══════════════════════════════════════════════════════════╣
║  Attack Type: Network Reconnaissance                       ║
║  Target: All common ports                                  ║
╚═══════════════════════════════════════════════════════════╝
    """)
    
    suspicious_ports = [
        [4444],  # Metasploit default
        [4444, 5555],
        [4444, 5555, 6666],
        [4444, 5555, 6666, 31337],  # Elite hacker port
        [4444, 5555, 6666, 31337, 12345]  # NetBus
    ]
    
    for i, ports in enumerate(suspicious_ports, 1):
        payload = {
            "device": DEVICE_ID,
            "device_name": "Attack Simulator",
            "timestamp": datetime.now().isoformat(),
            "cpu": random.uniform(25, 45),
            "memory": random.uniform(35, 55),
            "failed_logins": 0,
            "open_ports": ports,
            "unknown_port": ports[-1],
            "network_connections": random.randint(50, 100),
            "attack_simulation": True,
            "attack_type": "port_scan"
        }
        
        print(f"  🔎 Scan {i}/{len(suspicious_ports)}: Probing ports {ports}...")
        
        try:
            # Send to n8n and forward response to backend
            n8n_response = requests.post(N8N_WEBHOOK_URL, json=payload, timeout=30)
            
            if n8n_response.status_code == 200:
                n8n_data = n8n_response.json()
                if isinstance(n8n_data, list) and len(n8n_data) > 0:
                    analysis = n8n_data[0]
                else:
                    analysis = n8n_data
                
                complete_response = {**payload, **analysis}
                backend_response = requests.post(N8N_RESPONSE_ENDPOINT, json=complete_response, timeout=10)
                
                if backend_response.status_code == 201:
                    result = backend_response.json()
                    if result.get("agenticResponse", {}).get("isAttack"):
                        print(f"  🚨 AGENTIC AI DETECTED: {result['agenticResponse']['attackType']} - {result['agenticResponse']['severity']}")
            
        except Exception as e:
            print(f"  ❌ Error: {e}")
        
        time.sleep(2)
    
    print("\n  ✅ Port Scan simulation complete!")

def simulate_ddos():
    """
    Simulate a DDoS Attack
    - Sends high CPU and network traffic indicators
    """
    print("""
╔═══════════════════════════════════════════════════════════╗
║                🌊 DDoS ATTACK SIMULATION 🌊                ║
╠═══════════════════════════════════════════════════════════╣
║  Attack Type: Distributed Denial of Service               ║
║  Effect: CPU spike + High network traffic                 ║
╚═══════════════════════════════════════════════════════════╝
    """)
    
    # Gradual CPU and connection increase
    stages = [
        {"cpu": 50, "connections": 50},
        {"cpu": 70, "connections": 100},
        {"cpu": 85, "connections": 150},
        {"cpu": 92, "connections": 200},
        {"cpu": 98, "connections": 300}
    ]
    
    for i, stage in enumerate(stages, 1):
        payload = {
            "device": DEVICE_ID,
            "device_name": "Attack Simulator",
            "timestamp": datetime.now().isoformat(),
            "cpu": stage["cpu"],
            "memory": random.uniform(70, 90),
            "failed_logins": 0,
            "open_ports": [80, 443, 8080],
            "network_connections": stage["connections"],
            "attack_simulation": True,
            "attack_type": "ddos"
        }
        
        print(f"  💥 Stage {i}/{len(stages)}: CPU {stage['cpu']}% | Connections: {stage['connections']}...")
        
        try:
            n8n_response = requests.post(N8N_WEBHOOK_URL, json=payload, timeout=30)
            
            if n8n_response.status_code == 200:
                n8n_data = n8n_response.json()
                if isinstance(n8n_data, list) and len(n8n_data) > 0:
                    analysis = n8n_data[0]
                else:
                    analysis = n8n_data
                
                complete_response = {**payload, **analysis}
                backend_response = requests.post(N8N_RESPONSE_ENDPOINT, json=complete_response, timeout=10)
                
                if backend_response.status_code == 201:
                    result = backend_response.json()
                    if result.get("agenticResponse", {}).get("isAttack"):
                        print(f"  🚨 AGENTIC AI DETECTED: {result['agenticResponse']['attackType']} - {result['agenticResponse']['severity']}")
            
        except Exception as e:
            print(f"  ❌ Error: {e}")
        
        time.sleep(2)
    
    print("\n  ✅ DDoS simulation complete!")

def simulate_malware():
    """
    Simulate Malware/Suspicious Process Detection
    """
    print("""
╔═══════════════════════════════════════════════════════════╗
║             🦠 MALWARE DETECTION SIMULATION 🦠             ║
╠═══════════════════════════════════════════════════════════╣
║  Attack Type: Suspicious Process Execution                 ║
║  Effect: Unknown process detected                          ║
╚═══════════════════════════════════════════════════════════╝
    """)
    
    suspicious_processes = [
        "keylogger.exe",
        "mimikatz.exe",
        "nc.exe",
        "cryptominer.exe",
        "backdoor.exe"
    ]
    
    for i, process in enumerate(suspicious_processes, 1):
        payload = {
            "device": DEVICE_ID,
            "device_name": "Attack Simulator",
            "timestamp": datetime.now().isoformat(),
            "cpu": random.uniform(40, 70),
            "memory": random.uniform(50, 75),
            "failed_logins": 0,
            "open_ports": [80, 443],
            "suspicious_process": process,
            "unknown_process": process,
            "network_connections": random.randint(20, 50),
            "attack_simulation": True,
            "attack_type": "malware"
        }
        
        print(f"  🦠 Detection {i}/{len(suspicious_processes)}: Found '{process}'...")
        
        try:
            n8n_response = requests.post(N8N_WEBHOOK_URL, json=payload, timeout=30)
            
            if n8n_response.status_code == 200:
                n8n_data = n8n_response.json()
                if isinstance(n8n_data, list) and len(n8n_data) > 0:
                    analysis = n8n_data[0]
                else:
                    analysis = n8n_data
                
                complete_response = {**payload, **analysis}
                backend_response = requests.post(N8N_RESPONSE_ENDPOINT, json=complete_response, timeout=10)
                
                if backend_response.status_code == 201:
                    result = backend_response.json()
                    if result.get("agenticResponse", {}).get("isAttack"):
                        print(f"  🚨 AGENTIC AI DETECTED: {result['agenticResponse']['attackType']} - {result['agenticResponse']['severity']}")
            
        except Exception as e:
            print(f"  ❌ Error: {e}")
        
        time.sleep(3)
    
    print("\n  ✅ Malware simulation complete!")

def run_all_attacks():
    """Run all attack simulations in sequence"""
    print("""
╔═══════════════════════════════════════════════════════════╗
║        🎭 FULL ATTACK SIMULATION SUITE 🎭                  ║
║               Running all attack types                     ║
╚═══════════════════════════════════════════════════════════╝
    """)
    
    print("\n[1/4] Starting Brute Force Attack...")
    simulate_brute_force("medium")
    time.sleep(2)
    
    print("\n[2/4] Starting Port Scan Attack...")
    simulate_port_scan()
    time.sleep(2)
    
    print("\n[3/4] Starting DDoS Attack...")
    simulate_ddos()
    time.sleep(2)
    
    print("\n[4/4] Starting Malware Detection...")
    simulate_malware()
    
    print("""
╔═══════════════════════════════════════════════════════════╗
║        ✅ ALL ATTACK SIMULATIONS COMPLETE ✅               ║
║                                                            ║
║  Check your dashboard for alerts and AI responses!         ║
╚═══════════════════════════════════════════════════════════╝
    """)

def main():
    parser = argparse.ArgumentParser(description='IoT Security Attack Simulator')
    parser.add_argument('attack', nargs='?', default='all',
                        choices=['brute_force', 'port_scan', 'ddos', 'malware', 'all'],
                        help='Type of attack to simulate')
    parser.add_argument('--intensity', default='medium',
                        choices=['low', 'medium', 'high'],
                        help='Attack intensity (for brute force)')
    
    args = parser.parse_args()
    
    print(f"""
╔═══════════════════════════════════════════════════════════╗
║         🔥 IoT Security Attack Simulator 🔥                ║
╠═══════════════════════════════════════════════════════════╣
║  Target Backend: {BACKEND_URL:<30}      ║
║  Target n8n: {N8N_WEBHOOK_URL[:35]}...║
╚═══════════════════════════════════════════════════════════╝
    """)
    
    if args.attack == 'brute_force':
        simulate_brute_force(args.intensity)
    elif args.attack == 'port_scan':
        simulate_port_scan()
    elif args.attack == 'ddos':
        simulate_ddos()
    elif args.attack == 'malware':
        simulate_malware()
    else:
        run_all_attacks()

if __name__ == "__main__":
    main()
