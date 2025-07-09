#!/usr/bin/env python3
"""
Database migration to add audit_logs table for security event tracking
"""

import sqlite3
import os
from datetime import datetime

def migrate_database():
    """Add audit_logs table"""
    
    db_path = 'instance/warp_gateway.db'
    
    if not os.path.exists(db_path):
        print(f"Database file {db_path} not found. Please run the application first to create the database.")
        return False
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    try:
        # Check if audit_logs table already exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='audit_logs';")
        if cursor.fetchone():
            print("Audit logs table already exists. Migration not needed.")
            return True
        
        print("Creating audit_logs table...")
        
        # Create audit_logs table
        cursor.execute('''
            CREATE TABLE audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                event_type VARCHAR(50) NOT NULL,
                resource_type VARCHAR(50),
                resource_id INTEGER,
                event_description TEXT NOT NULL,
                ip_address VARCHAR(45),
                user_agent TEXT,
                session_id VARCHAR(255),
                success BOOLEAN DEFAULT 1,
                error_message TEXT,
                additional_data TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        ''')
        
        # Create index on timestamp for faster queries
        cursor.execute('CREATE INDEX idx_audit_logs_timestamp ON audit_logs(timestamp);')
        
        # Create index on event_type for filtering
        cursor.execute('CREATE INDEX idx_audit_logs_event_type ON audit_logs(event_type);')
        
        # Create index on user_id for user-specific queries
        cursor.execute('CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id);')
        
        conn.commit()
        print("✓ Audit logs table created successfully!")
        
        # Add initial system event
        cursor.execute('''
            INSERT INTO audit_logs (user_id, event_type, event_description, success, timestamp)
            VALUES (NULL, 'system_init', 'Audit logging system initialized', 1, ?)
        ''', (datetime.utcnow(),))
        
        conn.commit()
        print("✓ Initial audit log entry created!")
        
        return True
        
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        conn.rollback()
        return False
    finally:
        conn.close()

def main():
    """Main migration function"""
    
    print("KahLuna WARP Gateway - Audit Logging Migration")
    print("=" * 50)
    
    # Check if we're in the right directory
    if not os.path.exists('app.py'):
        print("Error: Please run this script from the warp-gateway directory")
        return
    
    # Run migration
    if migrate_database():
        print("\n" + "="*50)
        print("MIGRATION COMPLETED SUCCESSFULLY!")
        print("="*50)
        print("Audit logging is now active. The system will track:")
        print("- User login/logout events")
        print("- Failed login attempts")
        print("- User management actions")
        print("- Session timeouts")
        print("- Security events")
        print("="*50)
    else:
        print("\n" + "="*50)
        print("MIGRATION FAILED!")
        print("="*50)
        print("Please check the error messages above and try again.")

if __name__ == "__main__":
    main()