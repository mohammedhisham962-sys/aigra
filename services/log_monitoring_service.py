import time
import subprocess
import threading
import psutil
from datetime import datetime
from database.models import Log
from database.connection import SessionLocal

class LogSimulatorThread(threading.Thread):
    def __init__(self, callback):
        super().__init__()
        self.daemon = True
        self.callback = callback
        self.running = True
        self.last_event_time = None
        
        # Take a snapshot of currently running apps when the server starts
        self.existing_pids = set()
        for p in psutil.process_iter(['pid']):
            self.existing_pids.add(p.info['pid'])
            
    def _save_and_emit(self, log):
        session = SessionLocal()
        try:
            new_log = Log(
                timestamp=datetime.fromisoformat(log["timestamp"]),
                log_source=log["log_source"],
                log_level=log["log_level"],
                message=log["message"],
                client_ip=log["client_ip"],
                username=log["username"],
                process_name=log["process_name"]
            )
            session.add(new_log)
            session.commit()
            log["id"] = new_log.id
        except Exception as e:
            print(f"Error saving log: {e}")
        finally:
            session.close()
            
        if self.callback:
            self.callback(log)
            
    def run(self):
        while self.running:
            try:
                # 1. Detect Newly Opened Applications
                current_pids = set()
                for p in psutil.process_iter(['pid', 'name']):
                    pid = p.info['pid']
                    name = p.info['name']
                    current_pids.add(pid)
                    
                    if pid not in self.existing_pids:
                        # Only alert on common interesting user apps to avoid spam
                        if name and name.lower() in ['chrome.exe', 'msedge.exe', 'explorer.exe', 'notepad.exe', 'cmd.exe', 'powershell.exe', 'taskmgr.exe']:
                            log = {
                                "timestamp": datetime.utcnow().isoformat(),
                                "log_source": "ProcessMonitor",
                                "log_level": "WARNING" if name.lower() in ['cmd.exe', 'powershell.exe'] else "INFO",
                                "message": f"User opened application: {name}",
                                "client_ip": "127.0.0.1",
                                "username": "LocalUser",
                                "process_name": name
                            }
                            self._save_and_emit(log)
                            
                self.existing_pids = current_pids

                # 2. Check actual Windows Event Logs
                result = subprocess.run(
                    ['wevtutil', 'qe', 'Application', '/c:1', '/f:text', '/rd:true'],
                    capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW
                )
                
                output = result.stdout
                
                if output and "Event ID:" in output:
                    lines = output.split('\n')
                    event_id = "Unknown"
                    level = "INFO"
                    source = "Windows Application"
                    message = ""
                    
                    for line in lines:
                        if line.startswith("Event ID:"):
                            event_id = line.split(":", 1)[1].strip()
                        elif line.startswith("Level:"):
                            lvl = line.split(":", 1)[1].strip()
                            if "Warning" in lvl or "Error" in lvl:
                                level = "WARNING"
                        elif line.startswith("Source:"):
                            source = line.split(":", 1)[1].strip()
                        elif line.startswith("Description:"):
                            message = line.split(":", 1)[1].strip()
                    
                    if not message:
                        message = f"Windows Event {event_id} from {source}"
                    
                    current_event_id = f"{event_id}-{message[:50]}"
                    
                    if current_event_id != self.last_event_time:
                        self.last_event_time = current_event_id
                        
                        log = {
                            "timestamp": datetime.utcnow().isoformat(),
                            "log_source": f"Windows-{source}",
                            "log_level": level,
                            "message": message[:100],
                            "client_ip": "127.0.0.1",
                            "username": "SYSTEM",
                            "process_name": source
                        }
                        self._save_and_emit(log)
                            
            except Exception as e:
                print(f"Failed to read Windows logs or processes: {e}")
                
            # Check every 2 seconds
            time.sleep(2.0)

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import os

class FileActivityHandler(FileSystemEventHandler):
    def __init__(self, callback):
        self.callback = callback
        self.last_event = None
        
    def _emit(self, event_type, path):
        # Ignore temporary files
        if path.endswith('.tmp') or path.endswith('~'): return
        
        filename = os.path.basename(path)
        event_sig = f"{event_type}-{filename}"
        
        # Debounce rapid identical events
        if event_sig == self.last_event: return
        self.last_event = event_sig
        
        log = {
            "timestamp": datetime.utcnow().isoformat(),
            "log_source": "FileMonitor",
            "log_level": "INFO",
            "message": f"File {event_type}: {filename}",
            "client_ip": "127.0.0.1",
            "username": "LocalUser",
            "process_name": "explorer.exe",
            "file_path": path,
            "event_type": event_type
        }
        
        session = SessionLocal()
        try:
            new_log = Log(
                timestamp=datetime.fromisoformat(log["timestamp"]),
                log_source=log["log_source"],
                log_level=log["log_level"],
                message=log["message"],
                client_ip=log["client_ip"],
                username=log["username"],
                process_name=log["process_name"]
            )
            session.add(new_log)
            session.commit()
            log["id"] = new_log.id
        except Exception as e:
            pass
        finally:
            session.close()
            
        if self.callback:
            self.callback(log)

    def on_created(self, event):
        if not event.is_directory: self._emit("Created", event.src_path)
            
    def on_modified(self, event):
        if not event.is_directory: self._emit("Modified", event.src_path)

    def on_deleted(self, event):
        if not event.is_directory: self._emit("Deleted", event.src_path)

class FileMonitorThread(threading.Thread):
    def __init__(self, callback):
        super().__init__()
        self.daemon = True
        self.callback = callback
        self.observer = Observer()
        
    def run(self):
        try:
            # Monitor the user's Documents folder
            user_profile = os.environ.get('USERPROFILE', 'C:\\')
            path_to_watch = os.path.join(user_profile, 'Documents')
            
            if not os.path.exists(path_to_watch):
                path_to_watch = user_profile
                
            event_handler = FileActivityHandler(self.callback)
            self.observer.schedule(event_handler, path_to_watch, recursive=True)
            self.observer.start()
            
            while True:
                time.sleep(1)
        except Exception as e:
            print(f"File monitor failed: {e}")

class NetworkMonitorThread(threading.Thread):
    def __init__(self, callback):
        super().__init__()
        self.daemon = True
        self.callback = callback
        # Threat Intelligence Blacklist
        self.blacklist = ['malicious-test-domain.com', 'phishing.com', 'evil-hacker-site.net']
        self.seen_domains = set()
        
    def run(self):
        while True:
            try:
                # Check Windows DNS Cache
                result = subprocess.run(
                    ['ipconfig', '/displaydns'],
                    capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW
                )
                output = result.stdout.lower()
                
                for bad_domain in self.blacklist:
                    if bad_domain in output and bad_domain not in self.seen_domains:
                        self.seen_domains.add(bad_domain)
                        
                        log = {
                            "timestamp": datetime.utcnow().isoformat(),
                            "log_source": "NetworkMonitor",
                            "log_level": "WARNING", # Warning level triggers a dashboard alert
                            "message": f"Suspicious Network Activity: Device attempted to connect to blacklisted domain {bad_domain}",
                            "client_ip": "127.0.0.1",
                            "username": "LocalUser",
                            "process_name": "DNS Client"
                        }
                        
                        # Save to database
                        session = SessionLocal()
                        try:
                            new_log = Log(
                                timestamp=datetime.fromisoformat(log["timestamp"]),
                                log_source=log["log_source"],
                                log_level=log["log_level"],
                                message=log["message"],
                                client_ip=log["client_ip"],
                                username=log["username"],
                                process_name=log["process_name"]
                            )
                            session.add(new_log)
                            session.commit()
                            log["id"] = new_log.id
                        except Exception as e:
                            pass
                        finally:
                            session.close()
                            
                        if self.callback:
                            self.callback(log)
                            
            except Exception as e:
                pass
                
            time.sleep(5.0)
