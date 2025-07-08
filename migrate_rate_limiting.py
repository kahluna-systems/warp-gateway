#!/usr/bin/env python3
"""
Database migration script for rate limiting fields
Adds rate limiting fields to VPNNetwork and Endpoint models.
"""

import sqlite3
import os
import sys
from datetime import datetime

def backup_database(db_path):
    """Create a backup of the database"""
    backup_path = f"{db_path}.backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    try:
        with open(db_path, 'rb') as src:
            with open(backup_path, 'wb') as dst:
                dst.write(src.read())
        print(f"✅ Database backed up to: {backup_path}")
        return backup_path
    except Exception as e:
        print(f"❌ Error creating backup: {e}")
        return None

def migrate_rate_limiting_fields(db_path):
    """Add rate limiting fields to VPNNetwork and Endpoint tables"""
    
    if not os.path.exists(db_path):
        print(f"❌ Database not found: {db_path}")
        return False
    
    # Create backup
    backup_path = backup_database(db_path)
    if not backup_path:
        print("❌ Failed to create backup, aborting migration")
        return False
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check if migration is needed for VPNNetwork
        cursor.execute("PRAGMA table_info(vpn_networks)")
        vpn_columns = [column[1] for column in cursor.fetchall()]
        
        if 'rate_limit_enabled' in vpn_columns:
            print("✅ Rate limiting fields already exist in VPNNetwork table")
        else:
            print("🔄 Adding rate limiting fields to vpn_networks table...")
            
            # Add rate limiting fields to VPNNetwork
            cursor.execute("ALTER TABLE vpn_networks ADD COLUMN rate_limit_enabled BOOLEAN DEFAULT 0")
            cursor.execute("ALTER TABLE vpn_networks ADD COLUMN rate_limit_download_mbps REAL")
            cursor.execute("ALTER TABLE vpn_networks ADD COLUMN rate_limit_upload_mbps REAL")
            cursor.execute("ALTER TABLE vpn_networks ADD COLUMN rate_limit_burst_factor REAL DEFAULT 1.5")
            
            print("  ✅ Added rate limiting fields to vpn_networks table")
        
        # Check if migration is needed for Endpoint
        cursor.execute("PRAGMA table_info(endpoints)")
        endpoint_columns = [column[1] for column in cursor.fetchall()]
        
        if 'rate_limit_enabled' in endpoint_columns:
            print("✅ Rate limiting fields already exist in Endpoint table")
        else:
            print("🔄 Adding rate limiting fields to endpoints table...")
            
            # Add rate limiting fields to Endpoint
            cursor.execute("ALTER TABLE endpoints ADD COLUMN rate_limit_enabled BOOLEAN DEFAULT 0")
            cursor.execute("ALTER TABLE endpoints ADD COLUMN rate_limit_download_mbps REAL")
            cursor.execute("ALTER TABLE endpoints ADD COLUMN rate_limit_upload_mbps REAL")
            cursor.execute("ALTER TABLE endpoints ADD COLUMN rate_limit_burst_factor REAL DEFAULT 1.5")
            
            print("  ✅ Added rate limiting fields to endpoints table")
        
        conn.commit()
        conn.close()
        
        print("✅ Rate limiting fields migration completed successfully")
        print(f"💾 Database backup available at: {backup_path}")
        
        return True
        
    except Exception as e:
        print(f"❌ Migration failed: {e}")
        
        # Attempt to restore backup
        try:
            with open(backup_path, 'rb') as src:
                with open(db_path, 'wb') as dst:
                    dst.write(src.read())
            print(f"🔄 Database restored from backup: {backup_path}")
        except Exception as restore_error:
            print(f"❌ Failed to restore backup: {restore_error}")
        
        return False

def main():
    """Main migration function"""
    db_path = "instance/warp_gateway.db"
    
    print("🚀 Starting rate limiting fields migration...")
    print("=" * 50)
    
    if migrate_rate_limiting_fields(db_path):
        print("=" * 50)
        print("✅ Migration completed successfully!")
        print("\nNew rate limiting fields added:")
        print("  VPNNetwork:")
        print("    - rate_limit_enabled: Boolean for enabling network-level rate limiting")
        print("    - rate_limit_download_mbps: Float for download speed limit")
        print("    - rate_limit_upload_mbps: Float for upload speed limit")
        print("    - rate_limit_burst_factor: Float for burst allowance (default 1.5)")
        print("  Endpoint:")
        print("    - rate_limit_enabled: Boolean for enabling endpoint-level rate limiting")
        print("    - rate_limit_download_mbps: Float for download speed limit")
        print("    - rate_limit_upload_mbps: Float for upload speed limit")
        print("    - rate_limit_burst_factor: Float for burst allowance (default 1.5)")
        print("\nNext steps:")
        print("  1. Update forms to include rate limiting controls")
        print("  2. Implement rate limiting in WireGuard configuration")
        print("  3. Add rate limiting management interface")
        print("  4. Test rate limiting functionality")
        sys.exit(0)
    else:
        print("=" * 50)
        print("❌ Migration failed!")
        print("Please check the error messages above and try again.")
        sys.exit(1)

if __name__ == "__main__":
    main()