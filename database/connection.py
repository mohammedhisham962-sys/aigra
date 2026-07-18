from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session
import sys
import os

# Adjust path so we can import config
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import config

from database.models import Base, MitreTechnique, Setting

# We will use the development config by default for local initialization
env = os.environ.get('FLASK_ENV', 'development')
db_uri = config[env].SQLALCHEMY_DATABASE_URI

engine = create_engine(db_uri, connect_args={"check_same_thread": False} if "sqlite" in db_uri else {})
SessionLocal = scoped_session(sessionmaker(autocommit=False, autoflush=False, bind=engine))

def init_db():
    """Initializes the database, creating tables and inserting default data if empty."""
    Base.metadata.create_all(bind=engine)
    
    session = SessionLocal()
    
    # Check if MITRE techniques are empty, if so seed them
    if session.query(MitreTechnique).count() == 0:
        seed_mitre_data(session)
    
    # Check if default settings are empty
    if session.query(Setting).count() == 0:
        seed_settings(session)
        
    session.commit()
    session.close()

def seed_mitre_data(session):
    techniques = [
        MitreTechnique(technique_id="T1110", technique_name="Brute Force", tactic="Credential Access", 
                       description="Adversaries may use brute force techniques to gain access to accounts.", 
                       detection_logic="Monitor for multiple failed login attempts across accounts.",
                       recommended_response="Lock account, reset password, investigate source IP."),
        MitreTechnique(technique_id="T1059", technique_name="Command and Scripting Interpreter", tactic="Execution", 
                       description="Adversaries may abuse command and script interpreters to execute commands.", 
                       detection_logic="Monitor for unusual PowerShell or Bash commands, especially with encoded payloads.",
                       recommended_response="Kill suspicious process, isolate host, decode and analyze payload."),
        MitreTechnique(technique_id="T1046", technique_name="Network Service Discovery", tactic="Discovery", 
                       description="Adversaries may attempt to get a listing of services running on remote hosts.", 
                       detection_logic="Monitor for port scanning activities (Nmap, masscan) from a single host.",
                       recommended_response="Block IP at firewall, investigate scanning host.")
    ]
    session.add_all(techniques)

def seed_settings(session):
    settings = [
        Setting(key="alert_threshold_cpu", value="90", description="CPU usage percentage threshold for alerts"),
        Setting(key="alert_threshold_failed_logins", value="5", description="Number of failed logins before triggering Brute Force alert"),
        Setting(key="auto_resolve_false_positives", value="true", description="Automatically resolve alerts marked as False Positive by AI")
    ]
    session.add_all(settings)
