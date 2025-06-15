# backend/database/models.py
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import json

db = SQLAlchemy()

class ScanResult(db.Model):
    __tablename__ = 'scan_results'
    
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.String(36), unique=True, nullable=False, index=True)
    domain = db.Column(db.String(255), nullable=False, index=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    status = db.Column(db.String(20), default='completed', nullable=False)  # completed, failed, in_progress
    
    # Store JSON results for each check type
    dns_checks = db.Column(db.JSON)
    spf_checks = db.Column(db.JSON)
    dkim_checks = db.Column(db.JSON)
    dmarc_checks = db.Column(db.JSON)
    mta_sts_checks = db.Column(db.JSON)
    tls_rpt_checks = db.Column(db.JSON)
    ssl_tls_checks = db.Column(db.JSON)
    caa_records = db.Column(db.JSON)
    ct_logs = db.Column(db.JSON)
    cert_chain = db.Column(db.JSON)
    certificate = db.Column(db.JSON)
    
    # Error tracking
    error_message = db.Column(db.Text)
    
    # Metadata
    scan_duration = db.Column(db.Float)  # Duration in seconds
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def to_dict(self):
        return {
            "scan_metadata": {
                "scan_id": self.scan_id,
                "domain": self.domain,
                "timestamp": self.timestamp.isoformat(),
                "status": self.status,
                "scan_duration": self.scan_duration
            },
            "dns_checks": self.dns_checks,
            "spf_checks": self.spf_checks,
            "dkim_checks": self.dkim_checks,
            "dmarc_checks": self.dmarc_checks,
            "mta_sts_checks": self.mta_sts_checks,
            "tls_rpt_checks": self.tls_rpt_checks,
            "ssl_tls_checks": self.ssl_tls_checks,
            "caa_records": self.caa_records,
            "ct_logs": self.ct_logs,
            "cert_chain": self.cert_chain,
            "certificate": self.certificate,
            "error_message": self.error_message
        }

class DomainHistory(db.Model):
    __tablename__ = 'domain_history'
    
    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(255), nullable=False, index=True)
    first_scan = db.Column(db.DateTime, nullable=False)
    last_scan = db.Column(db.DateTime, nullable=False)
    total_scans = db.Column(db.Integer, default=1)
    
    def to_dict(self):
        return {
            "domain": self.domain,
            "first_scan": self.first_scan.isoformat(),
            "last_scan": self.last_scan.isoformat(),
            "total_scans": self.total_scans
        }
