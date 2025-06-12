"""
MuleSoft Package Validator - Main Entry Point

This script serves as the primary entry point to execute the MuleSoft Package Validator.
It directly calls the `main()` function from the `mule_validator.main` module,
which handles command-line argument parsing and orchestrates all validation tasks.
"""
from mule_validator.main import main

if __name__ == '__main__':
    main()