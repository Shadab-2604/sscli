"""Developer utility script to run formatting, linting, and testing."""

import subprocess
import sys


def main() -> int:
    py = sys.executable
    commands = [
        [py, "-m", "ruff", "check", "src", "tests"],
        [py, "-m", "ruff", "format", "--check", "src", "tests"],
        [py, "-m", "mypy", "src"],
        [py, "-m", "pytest", "--cov=src/systemscan", "tests"],
    ]

    for cmd in commands:
        print(f"\n--- Running: {' '.join(cmd)} ---")
        res = subprocess.run(cmd)
        if res.returncode != 0:
            print(f"FAILED: {' '.join(cmd)} (exit code: {res.returncode})")
            return res.returncode

    print("\nAll development quality checks passed successfully!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
