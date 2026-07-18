from datetime import datetime
from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

Base = declarative_base()

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(50), unique=True, nullable=False)
    email = Column(String(120), unique=True, nullable=False)
    password_hash = Column(String(256), nullable=False)
    role = Column(String(20), default='Analyst')  # Admin or Analyst
    created_at = Column(DateTime, default=datetime.utcnow)
    
    audit_logs = relationship('AuditLog', back_populates='user')
    reports = relationship('Report', back_populates='user')

class Log(Base):
    __tablename__ = 'logs'
    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    log_source = Column(String(50), nullable=False)  # WindowsEvent, Syslog, Web, SSH
    log_level = Column(String(20), default='INFO')
    message = Column(Text, nullable=False)
    client_ip = Column(String(50))
    username = Column(String(50))
    process_name = Column(String(100))
    details = Column(Text)  # Store JSON as text
    
    alerts = relationship('Alert', back_populates='log')

class Alert(Base):
    __tablename__ = 'alerts'
    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    log_id = Column(Integer, ForeignKey('logs.id'))
    rule_name = Column(String(100), nullable=False)
    severity = Column(String(20), default='Low')  # Low, Medium, High, Critical
    status = Column(String(20), default='New')    # New, Investigating, Resolved, False_Positive
    description = Column(Text)
    mitre_id = Column(String(20), ForeignKey('mitre_techniques.technique_id'))
    assigned_to = Column(String(50))
    notes = Column(Text)
    
    log = relationship('Log', back_populates='alerts')
    mitre_technique = relationship('MitreTechnique', back_populates='alerts')
    ai_analysis = relationship('AIAnalysis', back_populates='alert', uselist=False)

class MitreTechnique(Base):
    __tablename__ = 'mitre_techniques'
    technique_id = Column(String(20), primary_key=True)
    technique_name = Column(String(100), nullable=False)
    tactic = Column(String(100), nullable=False)
    description = Column(Text)
    detection_logic = Column(Text)
    recommended_response = Column(Text)
    
    alerts = relationship('Alert', back_populates='mitre_technique')

class AIAnalysis(Base):
    __tablename__ = 'ai_analyses'
    id = Column(Integer, primary_key=True, autoincrement=True)
    alert_id = Column(Integer, ForeignKey('alerts.id'))
    incident_explanation = Column(Text)
    risk_score = Column(Integer, default=0)
    confidence_score = Column(Float, default=0.0)
    remediation_steps = Column(Text)  # JSON list
    investigation_checklist = Column(Text)  # JSON list
    executive_summary = Column(Text)
    
    alert = relationship('Alert', back_populates='ai_analysis')

class Report(Base):
    __tablename__ = 'reports'
    id = Column(Integer, primary_key=True, autoincrement=True)
    report_name = Column(String(100), nullable=False)
    report_type = Column(String(20))  # PDF, CSV, Excel
    date_range = Column(String(100))
    generated_by = Column(Integer, ForeignKey('users.id'))
    created_at = Column(DateTime, default=datetime.utcnow)
    filepath = Column(String(255))
    
    user = relationship('User', back_populates='reports')

class Setting(Base):
    __tablename__ = 'settings'
    key = Column(String(50), primary_key=True)
    value = Column(Text)
    description = Column(Text)

class AuditLog(Base):
    __tablename__ = 'audit_logs'
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    action = Column(String(255), nullable=False)
    ip_address = Column(String(50))
    timestamp = Column(DateTime, default=datetime.utcnow)
    
    user = relationship('User', back_populates='audit_logs')
