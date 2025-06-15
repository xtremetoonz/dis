# backend/database/service.py
from backend.database.models import db, ScanResult, DomainHistory
from datetime import datetime
from sqlalchemy.exc import SQLAlchemyError
import logging

logger = logging.getLogger(__name__)

class DatabaseService:
    @staticmethod
    def save_scan_result(scan_data):
        """Save scan results to database"""
        try:
            # Create scan result record
            scan_result = ScanResult(
                scan_id=scan_data['scan_metadata']['scan_id'],
                domain=scan_data['scan_metadata']['domain'],
                timestamp=datetime.fromisoformat(scan_data['scan_metadata']['timestamp']),
                dns_checks=scan_data.get('dns_checks'),
                spf_checks=scan_data.get('spf_checks'),
                dkim_checks=scan_data.get('dkim_checks'),
                dmarc_checks=scan_data.get('dmarc_checks'),
                mta_sts_checks=scan_data.get('mta_sts_checks'),
                tls_rpt_checks=scan_data.get('tls_rpt_checks'),
                ssl_tls_checks=scan_data.get('ssl_tls_checks'),
                caa_records=scan_data.get('caa_records'),
                ct_logs=scan_data.get('ct_logs'),
                cert_chain=scan_data.get('cert_chain'),
                certificate=scan_data.get('certificate'),
                scan_duration=scan_data.get('scan_duration')
            )
            
            db.session.add(scan_result)
            
            # Update domain history
            DatabaseService._update_domain_history(scan_data['scan_metadata']['domain'])
            
            db.session.commit()
            logger.info(f"Saved scan result for domain: {scan_data['scan_metadata']['domain']}")
            return True
            
        except SQLAlchemyError as e:
            db.session.rollback()
            logger.error(f"Database error saving scan result: {str(e)}")
            return False
        except Exception as e:
            db.session.rollback()
            logger.error(f"Unexpected error saving scan result: {str(e)}")
            return False
    
    @staticmethod
    def save_failed_scan(scan_id, domain, error_message):
        """Save failed scan information"""
        try:
            scan_result = ScanResult(
                scan_id=scan_id,
                domain=domain,
                status='failed',
                error_message=error_message
            )
            
            db.session.add(scan_result)
            db.session.commit()
            logger.info(f"Saved failed scan for domain: {domain}")
            return True
            
        except SQLAlchemyError as e:
            db.session.rollback()
            logger.error(f"Database error saving failed scan: {str(e)}")
            return False
    
    @staticmethod
    def get_scan_by_id(scan_id):
        """Retrieve scan result by scan_id"""
        try:
            return ScanResult.query.filter_by(scan_id=scan_id).first()
        except SQLAlchemyError as e:
            logger.error(f"Database error retrieving scan: {str(e)}")
            return None
    
    @staticmethod
    def get_domain_scans(domain, limit=10):
        """Get recent scans for a domain"""
        try:
            return ScanResult.query.filter_by(domain=domain)\
                .order_by(ScanResult.timestamp.desc())\
                .limit(limit).all()
        except SQLAlchemyError as e:
            logger.error(f"Database error retrieving domain scans: {str(e)}")
            return []
    
    @staticmethod
    def get_domain_history(domain):
        """Get domain scan history"""
        try:
            return DomainHistory.query.filter_by(domain=domain).first()
        except SQLAlchemyError as e:
            logger.error(f"Database error retrieving domain history: {str(e)}")
            return None
    
    @staticmethod
    def _update_domain_history(domain):
        """Update or create domain history record"""
        history = DomainHistory.query.filter_by(domain=domain).first()
        
        if history:
            history.last_scan = datetime.utcnow()
            history.total_scans += 1
        else:
            history = DomainHistory(
                domain=domain,
                first_scan=datetime.utcnow(),
                last_scan=datetime.utcnow(),
                total_scans=1
            )
            db.session.add(history)
