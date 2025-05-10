import sys
import pkg_resources
import os
from pathlib import Path

class MLSetupVerifier:
    """
    Verifies the ML environment setup for PQC Kyber integration
    """

    REQUIRED_PACKAGES = {
        'scikit-learn': '1.0.0',
        'pandas': '1.3.0',
        'numpy': '1.21.0',
        'joblib': '1.0.0'
    }

    def __init__(self):
        self.python_version = sys.version
        self.base_path = Path(__file__).parent
        self.models_dir = self.base_path / "models"
        self.data_dir = self.base_path / "data"

    def check_python_version(self) -> bool:
        """Verify Python version is 3.7 or higher"""
        major, minor, _ = sys.version_info[:3]
        return major == 3 and minor >= 7

    def check_dependencies(self) -> dict:
        """Check if required packages are installed with correct versions"""
        results = {}
        for package, min_version in self.REQUIRED_PACKAGES.items():
            try:
                installed_version = pkg_resources.get_distribution(package).version
                meets_requirement = pkg_resources.parse_version(installed_version) >= \
                                  pkg_resources.parse_version(min_version)
                results[package] = {
                    'installed': True,
                    'version': installed_version,
                    'meets_requirement': meets_requirement
                }
            except pkg_resources.DistributionNotFound:
                results[package] = {
                    'installed': False,
                    'version': None,
                    'meets_requirement': False
                }
        return results

    def check_directories(self) -> dict:
        """Check if required directories exist"""
        return {
            'models_dir': {
                'exists': self.models_dir.exists(),
                'path': str(self.models_dir)
            },
            'data_dir': {
                'exists': self.data_dir.exists(),
                'path': str(self.data_dir)
            }
        }

    def verify_all(self) -> dict:
        """Run all verification checks and return results"""
        python_ok = self.check_python_version()
        deps_ok = self.check_dependencies()
        dirs_ok = self.check_directories()

        # Create missing directories if needed
        if not self.models_dir.exists():
            self.models_dir.mkdir(parents=True, exist_ok=True)
        if not self.data_dir.exists():
            self.data_dir.mkdir(parents=True, exist_ok=True)

        return {
            'status': 'ok' if python_ok and all(d['meets_requirement']
                    for d in deps_ok.values()) else 'error',
            'python_version': self.python_version,
            'python_executable': sys.executable,
            'dependencies': deps_ok,
            'directories': dirs_ok
        }

def main():
    verifier = MLSetupVerifier()
    results = verifier.verify_all()

    print("\n=== ML Setup Verification Results ===")
    print(f"\nPython Version: {results['python_version']}")
    print(f"Python Executable: {results['python_executable']}")

    print("\nDependencies:")
    for pkg, info in results['dependencies'].items():
        status = "✓" if info['meets_requirement'] else "✗"
        version = info['version'] or "Not installed"
        print(f"{status} {pkg}: {version}")

    print("\nDirectories:")
    for dir_name, info in results['directories'].items():
        status = "✓" if info['exists'] else "Created"
        print(f"{status} {dir_name}: {info['path']}")

    print(f"\nOverall Status: {results['status'].upper()}")

if __name__ == "__main__":
    main()