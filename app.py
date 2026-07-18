from flask import Flask
from flask_socketio import SocketIO
import os
import sys

# Ensure the root directory is in python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from database.connection import init_db
from services.log_monitoring_service import LogSimulatorThread, FileMonitorThread, NetworkMonitorThread

# Initialize Flask App
app = Flask(__name__)
app.config['SECRET_KEY'] = 'dev-secret-key'

# Initialize SocketIO for real-time updates
socketio = SocketIO(app, async_mode='threading')

# Import blueprints (routes)
from routes.views import views_bp
from routes.api import api_bp
app.register_blueprint(views_bp)
app.register_blueprint(api_bp)

def handle_new_log(log_data):
    """Callback function that receives a new simulated log and sends it to the frontend via Socket.IO."""
    # Send to the web browser
    socketio.emit('new_log', log_data)
    
    # If it's a WARNING, also treat it as a quick mock alert
    if log_data['log_level'] == 'WARNING':
        alert_data = {
            'time': log_data['timestamp'],
            'severity': 'High' if 'Suspicious' in log_data['message'] else 'Medium',
            'rule': log_data['message'],
            'score': '85' if 'Suspicious' in log_data['message'] else '60'
        }
        socketio.emit('new_alert', alert_data)

import psutil
import time

def process_monitor_thread():
    """Background task to send top running processes to the dashboard."""
    while True:
        try:
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'memory_info']):
                try:
                    processes.append({
                        'pid': proc.info['pid'],
                        'name': proc.info['name'],
                        'memory': round(proc.info['memory_info'].rss / (1024 * 1024), 1) # MB
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            
            # Sort by memory usage descending and get top 15
            processes.sort(key=lambda x: x['memory'], reverse=True)
            top_processes = processes[:15]
            
            socketio.emit('live_processes', top_processes)
        except Exception as e:
            print(f"Error in process monitor: {e}")
        
        socketio.sleep(3) # Update every 3 seconds

import platform

if __name__ == '__main__':
    print("Starting AI-Powered SOC Assistant...")
    # Initialize the database immediately before starting the server
    with app.app_context():
        init_db()
        print("Database initialized successfully.")
    
    # Only start PC monitoring threads if running on a local Windows PC.
    # Cloud servers (Linux) will crash if they try to run Windows commands.
    if platform.system() == 'Windows':
        # Start the background log generator (Windows events and apps)
        log_thread = LogSimulatorThread(callback=handle_new_log)
        log_thread.start()
        print("Background log simulator started.")
        
        # Start the File Integrity Monitor thread
        file_thread = FileMonitorThread(callback=handle_new_log)
        file_thread.start()
        print("File Monitor started on Documents folder.")
        
        # Start the Network Threat Monitor thread
        net_thread = NetworkMonitorThread(callback=handle_new_log)
        net_thread.start()
        print("Network Threat Monitor started.")
        
        # Start live process monitor
        socketio.start_background_task(process_monitor_thread)
        print("Live Process Monitor started.")
    else:
        print("Running in Cloud (Linux). PC-specific monitoring disabled. Core features active.")
    
    port = int(os.environ.get("PORT", 5000))
    socketio.run(app, host='0.0.0.0', port=port, debug=False, allow_unsafe_werkzeug=True)
