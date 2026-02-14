
import os
import sys
import subprocess
from pathlib import Path

def check_file(path):
    if not Path(path).exists():
        print(f"[X] Missing: {path}")
        return False
    print(f"[+] Found: {path}")
    return True

def run_cmd(cmd):
    try:
        subprocess.check_call(cmd, shell=True)
        print(f"[+] Executed: {cmd}")
        return True
    except subprocess.CalledProcessError:
        print(f"[X] Failed: {cmd}")
        return False

def main():
    print("[*] Validating Chimera Release Structure...")
    
    required_files = [
        "README.md",
        "CONTRIBUTING.md",
        "SECURITY.md",
        "CHANGELOG.md",
        "requirements.txt",
        "docs/Chimera_Research_Brief.md",
        "chimera/__init__.py",
        "chimera/cli.py",
        "chimera/scoring.py",
        "chimera/threat_intel.py",
    ]
    
    success = True
    for f in required_files:
        if not check_file(f):
            success = False
            
    print("\n[*] Validating CLI...")
    if not run_cmd("chimera --help"):
        success = False
        
    print("\n[*] Validating Sample Data Generation...")
    if not run_cmd("python generate_sample_data.py --users 5 --seed 42 -o validation.csv"):
        success = False
        
    print("\n[*] Validating Quick Start Flow...")
    # Train
    if not run_cmd("chimera train validation.csv -o val_model.joblib --detector ensemble --contamination 0.1"):
        success = False
    
    # Detect
    if not run_cmd("chimera detect validation.csv val_model.joblib -o val_results.json"):
        success = False
        
    if success:
        print("\n[+] RELEASE VALIDATION PASSED!")
        sys.exit(0)
    else:
        print("\n[X] RELEASE VALIDATION FAILED!")
        sys.exit(1)

if __name__ == "__main__":
    main()
