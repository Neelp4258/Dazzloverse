#!/usr/bin/env python
"""
Bulk Email Service Runner
Run this script to start the Flask application
"""

import os
import sys
from app import app

def create_directories():
    """Create necessary directories if they don't exist"""
    directories = ['uploads', 'logs', 'static']
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
        print(f"✓ Directory '{directory}' ready")

def check_environment():
    """Check if required environment variables are set"""
    required_vars = []
    missing_vars = []
    
    for var in required_vars:
        if not os.environ.get(var):
            missing_vars.append(var)
    
    if missing_vars:
        print("⚠️  Warning: The following environment variables are not set:")
        for var in missing_vars:
            print(f"   - {var}")
        print("   Consider creating a .env file based on .env.example")
    else:
        print("✓ Environment variables configured")

def main():
    """Main function to run the application"""
    print("🚀 Starting Bulk Email Service...")
    print("=" * 50)
    
    # Create necessary directories
    create_directories()
    
    # Check environment
    check_environment()
    
    # Get configuration
    host = os.environ.get('HOST', '0.0.0.0')
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV') == 'development'
    
    print(f"✓ Host: {host}")
    print(f"✓ Port: {port}")
    print(f"✓ Debug mode: {debug}")
    print(f"✓ Environment: {os.environ.get('FLASK_ENV', 'development')}")
    
    print("=" * 50)
    print("🌐 Application will be available at:")
    print(f"   http://localhost:{port}")
    if host != 'localhost':
        print(f"   http://{host}:{port}")
    print("=" * 50)
    
    try:
        # Run the Flask application
        app.run(
            host=host,
            port=port,
            debug=debug,
            threaded=True
        )
    except KeyboardInterrupt:
        print("\n🛑 Application stopped by user")
        sys.exit(0)
    except Exception as e:
        print(f"❌ Error starting application: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()