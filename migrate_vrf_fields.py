#!/usr/bin/env python3
"""
Database migration script for VRF fields
Adds VCID, peer_communication_enabled, expected_users, vrf_name, and routing_table_id fields to VPNNetwork model.
"""

import sqlite3
import os
import sys
import random
from datetime import datetime

def generate_vcid():
    """Generate a unique 8-digit VCID"""
    return random.randint(10000000, 99999999)

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

def migrate_vrf_fields(db_path):
    """Add VRF fields to the VPNNetwork table"""
    
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
        
        # Check if migration is needed
        cursor.execute("PRAGMA table_info(vpn_networks)")
        columns = [column[1] for column in cursor.fetchall()]
        
        if 'vcid' in columns:
            print("✅ VRF fields already exist, migration not needed")
            conn.close()
            return True
        
        print("🔄 Adding VRF fields to vpn_networks table...")
        
        # Add new VRF fields
        cursor.execute("ALTER TABLE vpn_networks ADD COLUMN vcid INTEGER")
        cursor.execute("ALTER TABLE vpn_networks ADD COLUMN peer_communication_enabled BOOLEAN DEFAULT 0")
        cursor.execute("ALTER TABLE vpn_networks ADD COLUMN expected_users INTEGER DEFAULT 1")
        cursor.execute("ALTER TABLE vpn_networks ADD COLUMN vrf_name TEXT")
        cursor.execute("ALTER TABLE vpn_networks ADD COLUMN routing_table_id INTEGER")
        
        # Get all existing networks to assign VCIDs
        cursor.execute("SELECT id, name, network_type FROM vpn_networks")
        networks = cursor.fetchall()
        
        used_vcids = set()
        
        for network_id, name, network_type in networks:
            # Generate unique VCID
            vcid = generate_vcid()
            while vcid in used_vcids:
                vcid = generate_vcid()
            used_vcids.add(vcid)
            
            # Set default values based on network type
            peer_comm_enabled = 1 if network_type == 'secure_internet' else 0
            expected_users = 1
            vrf_name = f"vrf-{name}"
            routing_table_id = 1000 + network_id
            
            cursor.execute("""
                UPDATE vpn_networks 
                SET vcid = ?, peer_communication_enabled = ?, expected_users = ?, 
                    vrf_name = ?, routing_table_id = ?
                WHERE id = ?
            """, (vcid, peer_comm_enabled, expected_users, vrf_name, routing_table_id, network_id))
            
            print(f"  📋 Network '{name}' assigned VCID: {vcid}")
        
        # Create unique index on vcid
        cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_vpn_networks_vcid ON vpn_networks(vcid)")
        
        conn.commit()
        conn.close()
        
        print("✅ VRF fields migration completed successfully")
        print(f"📊 Migrated {len(networks)} networks with unique VCIDs")
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
    
    print("🚀 Starting VRF fields migration...")
    print("=" * 50)
    
    if migrate_vrf_fields(db_path):
        print("=" * 50)
        print("✅ Migration completed successfully!")
        print("\nNew VRF fields added:")
        print("  - vcid: 8-digit unique identifier")
        print("  - peer_communication_enabled: Boolean for Secure Internet toggle")
        print("  - expected_users: Integer for dynamic subnet sizing")
        print("  - vrf_name: VRF namespace name")
        print("  - routing_table_id: Dedicated routing table ID")
        print("\nNext steps:")
        print("  1. Update forms to include new fields")
        print("  2. Update templates to display VCID and peer communication toggle")
        print("  3. Implement dynamic subnet sizing logic")
        print("  4. Fix WireGuard configuration generation")
        sys.exit(0)
    else:
        print("=" * 50)
        print("❌ Migration failed!")
        print("Please check the error messages above and try again.")
        sys.exit(1)

if __name__ == "__main__":
    main()