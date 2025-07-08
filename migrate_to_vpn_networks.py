#!/usr/bin/env python3
"""
Database migration script: WireGuard terminology to VPN Networks
Transforms the database schema from WireGuard-centric to business-focused terminology
"""

import sqlite3
import os
import sys
import shutil
from datetime import datetime

def backup_database(db_path):
    """Create a backup of the database before migration"""
    backup_path = f"{db_path}.backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    shutil.copy2(db_path, backup_path)
    print(f"Database backup created: {backup_path}")
    return backup_path

def migrate_schema(db_path):
    """Migrate database schema from WireGuard terminology to VPN Networks"""
    
    # Create backup first
    backup_path = backup_database(db_path)
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    try:
        # Begin transaction
        cursor.execute("BEGIN TRANSACTION;")
        
        # Step 1: Create new vpn_networks table with VLAN fields
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS vpn_networks (
                id INTEGER PRIMARY KEY,
                name VARCHAR(50) NOT NULL UNIQUE,
                port INTEGER NOT NULL UNIQUE,
                subnet VARCHAR(18) NOT NULL,
                network_type VARCHAR(50) NOT NULL,
                private_key TEXT NOT NULL,
                public_key TEXT NOT NULL,
                is_active BOOLEAN DEFAULT 0,
                custom_allowed_ips TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                -- New VLAN-related fields
                vlan_id INTEGER,
                vlan_range VARCHAR(50),
                bridge_name VARCHAR(50),
                vni_pool VARCHAR(100),
                -- Check constraints for VLAN
                CHECK (vlan_id IS NULL OR (vlan_id >= 1 AND vlan_id <= 4094)),
                CHECK (network_type IN ('secure_internet', 'remote_resource_gw', 'l3vpn_gateway', 'l2_point_to_point', 'l2_mesh'))
            );
        """)
        
        # Step 2: Create new endpoints table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS endpoints (
                id INTEGER PRIMARY KEY,
                vpn_network_id INTEGER NOT NULL,
                name VARCHAR(100) NOT NULL,
                ip_address VARCHAR(45) NOT NULL,
                private_key TEXT NOT NULL,
                public_key TEXT NOT NULL,
                preshared_key TEXT,
                is_active BOOLEAN DEFAULT 0,
                last_handshake DATETIME,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                -- New endpoint type field
                endpoint_type VARCHAR(20) DEFAULT 'mobile',
                FOREIGN KEY (vpn_network_id) REFERENCES vpn_networks (id) ON DELETE CASCADE,
                UNIQUE(vpn_network_id, name),
                CHECK (endpoint_type IN ('mobile', 'cpe', 'gateway'))
            );
        """)
        
        # Step 3: Create new endpoint_configs table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS endpoint_configs (
                id INTEGER PRIMARY KEY,
                endpoint_id INTEGER NOT NULL,
                config_content TEXT NOT NULL,
                version INTEGER NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (endpoint_id) REFERENCES endpoints (id) ON DELETE CASCADE
            );
        """)
        
        # Step 4: Check if old tables exist and migrate data
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='wg_interfaces';")
        if cursor.fetchone():
            print("Migrating data from wg_interfaces to vpn_networks...")
            cursor.execute("""
                INSERT INTO vpn_networks (id, name, port, subnet, network_type, private_key, 
                                        public_key, is_active, custom_allowed_ips, created_at)
                SELECT id, name, port, subnet, network_type, private_key, 
                       public_key, is_active, custom_allowed_ips, created_at
                FROM wg_interfaces;
            """)
            
            print("Migrating data from peers to endpoints...")
            cursor.execute("""
                INSERT INTO endpoints (id, vpn_network_id, name, ip_address, private_key, 
                                     public_key, preshared_key, is_active, last_handshake, created_at)
                SELECT id, wg_interface_id, name, ip_address, private_key, 
                       public_key, preshared_key, is_active, last_handshake, created_at
                FROM peers;
            """)
            
            print("Migrating data from peer_configs to endpoint_configs...")
            cursor.execute("""
                INSERT INTO endpoint_configs (id, endpoint_id, config_content, version, created_at)
                SELECT id, peer_id, config_content, version, created_at
                FROM peer_configs;
            """)
            
            # Step 5: Drop old tables
            cursor.execute("DROP TABLE IF EXISTS peer_configs;")
            cursor.execute("DROP TABLE IF EXISTS peers;")
            cursor.execute("DROP TABLE IF EXISTS wg_interfaces;")
            
            print("Old tables dropped successfully")
        else:
            print("No old tables found, migration skipped")
        
        # Step 6: Create indexes for performance
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_vpn_networks_network_type ON vpn_networks(network_type);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_vpn_networks_vlan_id ON vpn_networks(vlan_id);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_endpoints_vpn_network_id ON endpoints(vpn_network_id);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_endpoints_endpoint_type ON endpoints(endpoint_type);")
        
        # Commit transaction
        cursor.execute("COMMIT;")
        
        print("Database migration completed successfully!")
        print(f"Backup available at: {backup_path}")
        
        # Verify migration
        cursor.execute("SELECT COUNT(*) FROM vpn_networks;")
        networks_count = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM endpoints;")
        endpoints_count = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM endpoint_configs;")
        configs_count = cursor.fetchone()[0]
        
        print(f"Migration results:")
        print(f"  VPN Networks: {networks_count}")
        print(f"  Endpoints: {endpoints_count}")
        print(f"  Endpoint Configs: {configs_count}")
        
    except Exception as e:
        cursor.execute("ROLLBACK;")
        print(f"Migration failed: {e}")
        print(f"Database restored from backup: {backup_path}")
        shutil.copy2(backup_path, db_path)
        sys.exit(1)
    finally:
        conn.close()

def main():
    import argparse
    parser = argparse.ArgumentParser(description='Migrate database schema to VPN Networks')
    parser.add_argument('--yes', action='store_true', help='Skip confirmation prompt')
    args = parser.parse_args()
    
    # Database path (Flask uses instance folder)
    db_path = "/home/groundcontrol/warp-gateway/instance/warp_gateway.db"
    
    # Check if database exists
    if not os.path.exists(db_path):
        print(f"Database not found at {db_path}")
        print("Please ensure the database exists before running migration")
        sys.exit(1)
    
    print("Starting database migration...")
    print("This will transform:")
    print("  - wg_interfaces -> vpn_networks")
    print("  - peers -> endpoints")
    print("  - peer_configs -> endpoint_configs")
    print("  - Add VLAN support fields")
    print()
    
    # Confirm migration
    if not args.yes:
        try:
            response = input("Continue with migration? (y/N): ")
            if response.lower() != 'y':
                print("Migration cancelled")
                sys.exit(0)
        except (EOFError, KeyboardInterrupt):
            print("\nMigration cancelled")
            sys.exit(0)
    
    migrate_schema(db_path)

if __name__ == "__main__":
    main()