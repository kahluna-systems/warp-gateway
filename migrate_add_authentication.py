#!/usr/bin/env python3
"""
Database migration to add authentication system
Adds users table and creates default admin user
"""

import sqlite3
import os
from datetime import datetime
from werkzeug.security import generate_password_hash
import getpass

def migrate_database():
    """Add users table and create default admin user"""
    
    db_path = 'instance/warp_gateway.db'
    
    if not os.path.exists(db_path):
        print(f"Database file {db_path} not found. Please run the application first to create the database.")
        return False
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    try:
        # Check if users table already exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users';")
        if cursor.fetchone():
            print("Users table already exists. Checking for admin user...")
            
            # Check if admin user exists
            cursor.execute("SELECT username FROM users WHERE username='admin';")
            if cursor.fetchone():
                print("Admin user already exists. Migration not needed.")
                return True
            else:
                print("Admin user not found. Creating...")
                create_admin_user(cursor)
                conn.commit()
                print("✓ Admin user created successfully!")
                return True
        
        print("Creating users table...")
        
        # Create users table
        cursor.execute('''
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username VARCHAR(80) UNIQUE NOT NULL,
                email VARCHAR(120) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                role VARCHAR(20) DEFAULT 'admin',
                is_active BOOLEAN DEFAULT 1,
                last_login DATETIME,
                failed_login_attempts INTEGER DEFAULT 0,
                locked_until DATETIME,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        print("✓ Users table created successfully!")
        
        # Create default admin user
        create_admin_user(cursor)
        
        conn.commit()
        print("✓ Database migration completed successfully!")
        return True
        
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        conn.rollback()
        return False
    finally:
        conn.close()

def create_admin_user(cursor):
    """Create the default admin user"""
    
    print("\n" + "="*50)
    print("CREATING DEFAULT ADMIN USER")
    print("="*50)
    
    # Get admin credentials
    username = input("Enter admin username [admin]: ").strip() or "admin"
    email = input("Enter admin email [admin@kahluna.com]: ").strip() or "admin@kahluna.com"
    
    # Get password with confirmation
    while True:
        password = getpass.getpass("Enter admin password: ")
        if len(password) < 8:
            print("Password must be at least 8 characters long.")
            continue
        
        confirm_password = getpass.getpass("Confirm admin password: ")
        if password != confirm_password:
            print("Passwords do not match. Please try again.")
            continue
        
        break
    
    # Hash password
    password_hash = generate_password_hash(password)
    
    # Create admin user
    cursor.execute('''
        INSERT INTO users (username, email, password_hash, role, is_active, created_at, updated_at)
        VALUES (?, ?, ?, 'admin', 1, ?, ?)
    ''', (username, email, password_hash, datetime.utcnow(), datetime.utcnow()))
    
    print(f"✓ Admin user '{username}' created successfully!")
    print("="*50)

def main():
    """Main migration function"""
    
    print("KahLuna WARP Gateway - Authentication Migration")
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
        print("You can now:")
        print("1. Start the application: python app.py")
        print("2. Login with your admin credentials")
        print("3. Create additional users if needed")
        print("="*50)
    else:
        print("\n" + "="*50)
        print("MIGRATION FAILED!")
        print("="*50)
        print("Please check the error messages above and try again.")

if __name__ == "__main__":
    main()