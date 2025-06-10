#!/usr/bin/env python3
"""
Clean up Git merge conflicts from all files
"""

import os
import glob

def clean_merge_conflicts():
    """Remove Git merge conflict markers from all Python files"""
    
    # Files that need cleaning
    files_to_clean = [
        'requirements.txt',
        'README.md',
        'docker-compose.yml',
        'Dockerfile.txt',
        'runtime.txt'
    ]
    
    # Also check for any remaining .py files
    python_files = glob.glob('*.py')
    files_to_clean.extend(python_files)
    
    for filename in files_to_clean:
        if not os.path.exists(filename):
            continue
            
        print(f"Checking {filename}...")
        
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Check if file has merge conflicts
            if '<<<<<<< HEAD' in content:
                print(f"  ❌ Found merge conflicts in {filename}")
                
                # Split by conflict markers and take the first part (before =======)
                lines = content.split('\n')
                cleaned_lines = []
                in_conflict = False
                
                for line in lines:
                    if line.startswith('<<<<<<< HEAD'):
                        in_conflict = True
                        continue
                    elif line.startswith('======='):
                        in_conflict = False
                        continue
                    elif line.startswith('>>>>>>> '):
                        continue
                    elif not in_conflict:
                        cleaned_lines.append(line)
                
                # Write cleaned content back
                cleaned_content = '\n'.join(cleaned_lines)
                
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(cleaned_content)
                
                print(f"  ✅ Cleaned merge conflicts in {filename}")
            else:
                print(f"  ✅ No conflicts in {filename}")
                
        except Exception as e:
            print(f"  ❌ Error processing {filename}: {e}")

def create_missing_files():
    """Create any missing required files"""
    
    # Create directories
    directories = ['static', 'uploads', 'logs', 'templates']
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
        print(f"✅ Directory '{directory}' ready")
    
    # Create empty favicon if it doesn't exist
    favicon_path = 'static/favicon.ico'
    if not os.path.exists(favicon_path):
        with open(favicon_path, 'w') as f:
            f.write('')
        print(f"✅ Created empty {favicon_path}")

if __name__ == "__main__":
    print("🧹 Cleaning up merge conflicts...")
    print("=" * 50)
    
    clean_merge_conflicts()
    create_missing_files()
    
    print("=" * 50)
    print("✅ Cleanup complete!")
    print("\nNext steps:")
    print("1. Run: python app.py")
    print("2. Check: http://localhost:5000")
    print("3. If issues persist, check the logs/")