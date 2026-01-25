# Contributing to MuleSoft Package Validator

Thank you for your interest in contributing! This document provides guidelines for contributing to this project.

## Development Setup

1. Fork the repository
2. Clone your fork:
```bash
   git clone https://github.com/YOUR_USERNAME/mulesoft_package_validator.git
```
3. Create a virtual environment:
```bash
   python -m venv venv
   source venv/bin/activate  # Windows: venv\Scripts\activate
```
4. Install dependencies:
```bash
   pip install -r requirements.txt
   pip install -e .
```

## Running Tests
```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=mule_validator

# Run specific test file
pytest tests/test_flow_validator.py -v
```

## Code Style

- Follow PEP 8
- Use type hints
- Write docstrings for public functions
- Keep functions focused and small

## Pull Request Process

1. Update tests for your changes
2. Ensure all tests pass
3. Update documentation
4. Create PR with clear description
5. Link any related issues

## Reporting Issues

- Use GitHub Issues
- Provide minimal reproducible example
- Include Python version and OS
- Attach relevant error messages

## Questions?

Open a GitHub Discussion for questions and general discussion.