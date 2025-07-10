"""
Test runner configuration and utilities.
"""

import os
import sys

import pytest

# Add the parent directory to the Python path so tests can import the main package
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def run_all_tests():
    """Run all tests in the test suite."""
    # Run pytest with verbose output and coverage if available
    args = [
        "-v",  # Verbose output
        "--tb=short",  # Short traceback format
        "-x",  # Stop on first failure
        "tests/",  # Test directory
    ]

    # Try to add coverage if pytest-cov is installed
    try:
        import importlib.util

        if importlib.util.find_spec("pytest_cov") is not None:
            args.extend(["--cov=audit_agent", "--cov-report=term-missing"])
    except ImportError:
        print("pytest-cov not installed, running without coverage")

    return pytest.main(args)


def run_specific_test(test_file):
    """Run a specific test file."""
    return pytest.main(["-v", f"tests/{test_file}"])


def run_test_class(test_file, test_class):
    """Run a specific test class."""
    return pytest.main(["-v", f"tests/{test_file}::{test_class}"])


def run_test_method(test_file, test_class, test_method):
    """Run a specific test method."""
    return pytest.main(["-v", f"tests/{test_file}::{test_class}::{test_method}"])


if __name__ == "__main__":
    # Default behavior: run all tests
    exit_code = run_all_tests()
    sys.exit(exit_code)
