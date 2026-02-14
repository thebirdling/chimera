"""
End-to-end verification script for Chimera v0.2.0.
Runs the full CLI workflow as described in the verification plan.
"""

import subprocess
import sys
import shutil
import io
from pathlib import Path

# Force UTF-8 output for Windows console
if sys.stdout.encoding.lower() != 'utf-8':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

def run_cmd(args: list[str], description: str) -> None:
    print(f"\n🚀 {description}...")
    cmd = [sys.executable, "-m", "chimera.cli"] + args
    print(f"   $ chimera {' '.join(args)}")
    
    try:
        result = subprocess.run(
            cmd, 
            capture_output=True, 
            text=True, 
            check=True
        )
        print("   ✅ Success")
        # Print first few lines of output
        for line in result.stdout.splitlines()[:5]:
            print(f"      {line}")
    except subprocess.CalledProcessError as e:
        print(f"   ❌ Failed with exit code {e.returncode}")
        print("   STDOUT:")
        print(e.stdout)
        print("   STDERR:")
        print(e.stderr)
        sys.exit(1)

def main() -> None:
    print("🔥 Chimera v0.2.0 End-to-End Verification")
    print("==========================================")
    
    # 0. Clean up previous run
    print("\n🧹 Cleaning up...")
    cleanup_paths = [
        "e2e_data.csv", "e2e_config.yaml", "e2e_model.joblib", 
        "e2e_results.json", "e2e_reports", "e2e_exports"
    ]
    for p in cleanup_paths:
        path = Path(p)
        if path.exists():
            if path.is_dir():
                shutil.rmtree(path)
            else:
                path.unlink()

    # 1. Generate data
    print("\n📦 Generating test data...")
    subprocess.run(
        [sys.executable, "generate_sample_data.py", 
         "-o", "e2e_data.csv", 
         "--scenario", "mixed", 
         "--users", "10", 
         "--events", "100"],
        check=True
    )
    print("   ✅ Generated e2e_data.csv")

    # 2. Init config
    run_cmd(["init", "-o", "e2e_config.yaml"], "Initializing configuration")

    # 3. Train model
    run_cmd([
        "--config", "e2e_config.yaml",
        "train", "e2e_data.csv", 
        "-o", "e2e_model.joblib", 
        "--detector", "ensemble"
    ], "Training model (Ensemble)")

    # 4. Info
    run_cmd(["info", "e2e_model.joblib"], "Checking model info")
    
    # 5. Detect
    run_cmd([
        "detect", "e2e_data.csv", "e2e_model.joblib",
        "-o", "e2e_results.json",
        "--rules"
    ], "Detecting anomalies")

    # 6. Rules list
    run_cmd(["rules", "--list"], "Listing detection rules")

    # 7. Correlate
    run_cmd([
        "correlate", "e2e_data.csv",
        "-o", "e2e_correlations.json"
    ], "Correlating events")

    # 8. Report
    run_cmd([
        "report", "e2e_results.json",
        "-o", "e2e_reports",
        "--format", "all"
    ], "Generating reports")

    # 9. Export
    run_cmd([
        "export", "e2e_results.json",
        "-o", "e2e_exports",
        "--format", "all"
    ], "Exporting to SIEM formats")

    # 10. Watch (dry run - just check help)
    run_cmd(["watch", "--help"], "Checking watch command help")

    print("\n✨ Verification Complete! All systems operational.")

if __name__ == "__main__":
    main()
