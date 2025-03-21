import sys

# Path to Sagemath executable for the guess and determine tool
PATH_SAGE = '/usr/local/bin/sage'
# PATH_SAGE = '/usr/bin/sage'
TEMP_DIR = 'temp'

REQUIRED_PACKAGES = ["pandas", "sympy"]

def check_dependencies():
    """Check if all required packages are installed. If not, prompt the user to install them."""
    missing_packages = []

    for package in REQUIRED_PACKAGES:
        try:
            __import__(package)
        except ImportError:
            missing_packages.append(package)

    if missing_packages:
        print("\n❌ Missing dependencies detected!\n")
        print("➡️  Please install them by running:\n")
        print(f"   pip install {' '.join(missing_packages)}\n")
        print("OR install all dependencies from requirements.txt:")
        print("   pip install -r requirements.txt\n")
        sys.exit(1)  # Exit the script if any required package is missing



