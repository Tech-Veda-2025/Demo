#!/usr/bin/env python3
"""
MySQL Connection Test Script for Ayurvedic Healthcare Portal
Run this script to test your database connection before starting the app.
"""

import mysql.connector
from mysql.connector import Error

# Test different connection configurations
test_configs = [
    # Test 1: Root with password
    {
        'name': 'Root user with password',
        'config': {
            'host': 'localhost',
            'user': 'root',
            'password': '56964',  # CHANGE THIS
            'database': 'ayurvedic_portal'
        }
    },
    # Test 2: Dedicated user
    {
        'name': 'Dedicated ayurveda_user',
        'config': {
            'host': 'localhost',
            'user': 'ayurveda_user',
            'password': 'ayurveda_secure_2025',
            'database': 'ayurvedic_portal'
        }
    },
    # Test 3: Root without database (to create database)
    {
        'name': 'Root user (no database specified)',
        'config': {
            'host': 'localhost',
            'user': 'root',
            'password': '56964'  # CHANGE THIS
        }
    }
]

def test_connection(config_info):
    """Test a database connection configuration"""
    print(f"\n🔍 Testing: {config_info['name']}")
    print("-" * 50)

    try:
        connection = mysql.connector.connect(**config_info['config'])
        cursor = connection.cursor()

        # Test basic query
        cursor.execute("SELECT VERSION()")
        version = cursor.fetchone()
        print(f"✅ Connection successful!")
        print(f"📊 MySQL Version: {version[0]}")

        # Test database existence
        if 'database' in config_info['config']:
            cursor.execute("SELECT DATABASE()")
            db_name = cursor.fetchone()
            print(f"🗄️  Connected to database: {db_name[0]}")

            # Check if tables exist
            cursor.execute("SHOW TABLES")
            tables = cursor.fetchall()
            if tables:
                print(f"📋 Tables found: {len(tables)}")
                for table in tables:
                    print(f"   - {table[0]}")
            else:
                print("⚠️  No tables found. Run database.sql to create tables.")

        cursor.close()
        connection.close()
        return True

    except Error as err:
        print(f"❌ Connection failed!")
        print(f"   Error: {err}")

        # Provide specific help
        if err.errno == 1045:
            print("   💡 Solution: Check your username and password")
        elif err.errno == 1049:
            print("   💡 Solution: Create the database first")
        elif err.errno == 2003:
            print("   💡 Solution: Make sure MySQL server is running")

        return False

def main():
    print("=" * 60)
    print("🕉️  AYURVEDIC HEALTHCARE PORTAL - DATABASE TEST")
    print("=" * 60)

    success_count = 0

    for config in test_configs:
        if test_connection(config):
            success_count += 1

    print("\n" + "=" * 60)
    print(f"📈 RESULTS: {success_count}/{len(test_configs)} configurations successful")

    if success_count > 0:
        print("✅ At least one configuration works!")
        print("🚀 You can start the Flask application now.")
    else:
        print("❌ No configurations work.")
        print("🔧 Please check MySQL installation and credentials.")
        print("📖 See DATABASE_SETUP.md for detailed instructions.")

    print("\n💡 TIP: Update the working configuration in app.py")
    print("=" * 60)

if __name__ == "__main__":
    main()
