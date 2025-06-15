# backend/database/init.py
from backend.database.models import db
import logging

logger = logging.getLogger(__name__)

def init_database(app):
    """Initialize database with Flask app"""
    db.init_app(app)
    
    with app.app_context():
        try:
            # Create all tables
            db.create_all()
            logger.info("Database tables created successfully")
        except Exception as e:
            logger.error(f"Error creating database tables: {str(e)}")
            raise

def drop_all_tables(app):
    """Drop all tables (use with caution!)"""
    with app.app_context():
        try:
            db.drop_all()
            logger.info("All database tables dropped")
        except Exception as e:
            logger.error(f"Error dropping database tables: {str(e)}")
            raise
