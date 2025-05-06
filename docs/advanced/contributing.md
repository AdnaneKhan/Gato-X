# Contributing to Gato-X

This guide explains how to contribute to the Gato-X project.

## Getting Started

### Prerequisites

- Python 3.10 or higher
- Git
- A GitHub account

### Setting Up the Development Environment

1. Fork the Gato-X repository on GitHub
2. Clone your fork:
   ```bash
   git clone https://github.com/YOUR_USERNAME/gato-x.git
   cd gato-x
   ```
3. Set up a virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```
4. Install in development mode:
   ```bash
   pip install -e .
   ```

## Project Structure

The Gato-X codebase is organized into several modules:

- `gatox/cli/`: Command-line interface components
- `gatox/enumerate/`: Repository and organization enumeration
- `gatox/search/`: GitHub code search functionality
- `gatox/attack/`: Attack capabilities
- `gatox/workflow_graph/`: Workflow analysis engine
- `gatox/models/`: Data models
- `gatox/github/`: GitHub API interaction
- `gatox/util/`: Utility functions

## Development Guidelines

### Code Style

Gato-X follows the Black code style. Before submitting a pull request, format your code:

```bash
pip install black
black .
```

### Adding New Features

When adding new features:

1. Create a new branch:
   ```bash
   git checkout -b feature/my-new-feature
   ```
2. Implement your feature
3. Add tests for your feature
4. Update documentation
5. Submit a pull request

### Design Methodology

Before working on significant changes, please review the project's design methodology:

1. **Operator-Focused**: Gato-X is designed for security practitioners, prioritizing usability and effectiveness over perfect precision
2. **Avoid False Negatives**: The tool is tuned to catch all potential vulnerabilities, even if it means some false positives
3. **Provide Context**: For each finding, provide enough context for operators to quickly determine if it's a true positive
4. **Performance Matters**: The tool should be able to scan thousands of repositories efficiently

## Testing

### Running Tests

To run the test suite:

```bash
pytest
```

### Adding Tests

When adding new features, please add appropriate tests:

1. Unit tests for individual functions
2. Integration tests for complex workflows
3. Mock tests for GitHub API interactions

## Submitting Changes

### Pull Request Process

1. Ensure your code follows the project's style guidelines
2. Update documentation to reflect your changes
3. Add or update tests as necessary
4. Submit a pull request with a clear description of the changes

### Proposing Significant Changes

If you're proposing significant changes to the tool, please open an issue first to discuss the motivation for the changes.

## Documentation

### Updating Documentation

When adding or modifying features, please update the relevant documentation:

1. Update the README.md if necessary
2. Update or add documentation in the docs/ directory
3. Update command help text in the CLI code

## Reporting Issues

If you find a bug or have a feature request:

1. Check if the issue already exists in the GitHub issues
2. If not, create a new issue with:
   - A clear description of the problem
   - Steps to reproduce
   - Expected behavior
   - Actual behavior
   - Any relevant logs or screenshots

## License

By contributing to Gato-X, you agree that your contributions will be licensed under the project's Apache License, Version 2.0.
