# Contributing to AuditAgent

Thank you for your interest in contributing to AuditAgent! This guide will help you get started.

## Development Setup

### Prerequisites

- Python 3.8 or higher
- [mise](https://mise.jdx.dev) (recommended) or Make

### Quick Start with mise (Recommended)

1. **Install mise** (if not already installed):

   ```bash
   curl https://mise.run | sh
   ```

   Or follow the [official installation guide](https://mise.jdx.dev/getting-started.html).

2. **Clone the repository**:

   ```bash
   git clone https://github.com/xoity/AuditAgent.git
   cd AuditAgent
   ```

3. **Install dependencies**:

   ```bash
   mise install  # Install Python and create venv
   mise run install_dev  # Install AuditAgent with dev dependencies
   ```

4. **Verify setup**:

   ```bash
   mise run test  # Run tests
   mise run check  # Run linters
   ```

### Alternative: Using Make

If you prefer Make over mise:

```bash
make install_dev
make test
make check
```

**Note**: The Makefile is a wrapper around mise, so you still need mise installed.

### Alternative: Manual Setup

If you prefer not to use mise:

```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -e '.[dev]'
pytest tests/
ruff check .
ruff format --check .
```

## Development Workflow

### Available Tasks

View all available tasks:

```bash
mise tasks
# or
make help
```

### Common Tasks

| Task | Command | Description |
|------|---------|-------------|
| **Installation** | | |
| Install for development | `mise run install_dev` | Install with dev dependencies |
| Install dependencies only | `mise run install_deps` | Install requirements.txt |
| Clean build artifacts | `mise run clean` | Remove venv, caches, build files |
| **Code Quality** | | |
| Format code | `mise run format` | Auto-format with ruff |
| Check formatting | `mise run format_check` | Check if code is formatted |
| Lint code | `mise run lint` | Check code quality |
| Auto-fix linting issues | `mise run lint_fix` | Fix auto-fixable issues |
| Type check | `mise run typecheck` | Run mypy type checking |
| Run all checks | `mise run check` | Format check + lint |
| **Testing** | | |
| Run all tests | `mise run test` | Verbose test output |
| Quick test run | `mise run test_quick` | Minimal output |
| Test with coverage | `mise run test_coverage` | HTML coverage report |
| Unit tests only | `mise run test_unit` | Skip integration tests |
| Integration tests only | `mise run test_integration` | Skip unit tests |
| Test specific file | `mise run test_file file=tests/test_*.py` | Run one test file |
| **Development** | | |
| Run example | `mise run example` | Run Linux iptables example |
| Build package | `mise run build` | Create distribution packages |
| Show version | `mise run version` | Display AuditAgent version |

### Pre-commit Checks

Before committing code, run:

```bash
mise run check  # Format check + lint
mise run test   # All tests
```

Or run everything at once:

```bash
mise run all  # install + lint + test
```

## Code Style

AuditAgent uses **ruff** for linting and formatting:

- **Line length**: 88 characters (Black-compatible)
- **Target Python**: 3.8+
- **Import sorting**: Managed by ruff
- **Type hints**: Encouraged but not enforced

### Formatting

Auto-format your code before committing:

```bash
mise run format
```

### Linting

Check for issues:

```bash
mise run lint
```

Auto-fix what can be fixed:

```bash
mise run lint_fix
```

### Configuration

- Ruff configuration: `ruff.toml` and `[tool.ruff]` in `pyproject.toml`
- Pytest configuration: `[tool.pytest.ini_options]` in `pyproject.toml`
- MyPy configuration: `[tool.mypy]` in `pyproject.toml`

## Testing

### Writing Tests

Tests are located in the `tests/` directory:

- `test_*.py` - Test files
- Use pytest fixtures for setup/teardown
- Mark tests appropriately:
  - `@pytest.mark.unit` - Unit tests
  - `@pytest.mark.integration` - Integration tests (may require SSH access)
  - `@pytest.mark.slow` - Slow tests

### Running Tests

```bash
# All tests
mise run test

# Specific test file
mise run test_file file=tests/test_rules.py

# With coverage
mise run test_coverage

# Skip integration tests
pytest tests/ -m "not integration"
```

### Test Coverage

Coverage reports are generated in `htmlcov/` when running:

```bash
mise run test_coverage
```

Open `htmlcov/index.html` in your browser to view detailed coverage.

## Pull Request Process

1. **Fork and clone** the repository
2. **Create a branch**: `git checkout -b feature/your-feature-name`
3. **Make changes** following code style guidelines
4. **Add tests** for new functionality
5. **Run checks**:

   ```bash
   mise run format  # Format code
   mise run check   # Lint and format check
   mise run test    # Run tests
   ```

6. **Commit**: Use clear, descriptive commit messages
7. **Push** to your fork
8. **Open a Pull Request** with a clear description

### CI Pipeline

When you open a PR, GitHub Actions will automatically:

- **Lint Check**: Verify code formatting and linting (ruff)
- **Test Suite**: Run tests on Python 3.8, 3.9, 3.10, 3.11, 3.12, 3.13
- **Coverage**: Generate coverage report (Python 3.13 only)

All checks must pass before merging.

## Project Structure

``` bash
AuditAgent/
├── audit_agent/           # Main package
│   ├── cli.py            # CLI interface (typer)
│   ├── core/             # Core functionality
│   │   ├── credentials.py  # SSH credential management
│   │   ├── logging_config.py
│   │   ├── objects.py    # Data models (Pydantic)
│   │   ├── policy.py     # Policy engine
│   │   └── rules.py      # Firewall rule logic
│   ├── devices/          # Device connectors
│   │   ├── base.py       # Base device class
│   │   └── linux_iptables.py  # Linux iptables implementation
│   ├── audit/            # Audit engine
│   │   └── engine.py
│   └── enforcement/      # Enforcement engine
│       └── engine.py
├── tests/                # Test suite
├── examples/             # Usage examples
├── .github/workflows/    # CI/CD workflows
├── .mise.toml           # Task definitions
├── Makefile             # Make wrapper for mise
├── ruff.toml            # Ruff configuration
└── pyproject.toml       # Project metadata and tool configs
```

## Reporting Issues

When reporting issues, please include:

- Python version
- Operating system
- Steps to reproduce
- Expected vs actual behavior
- Error messages and stack traces
- Relevant configuration files (sanitize sensitive data)

## Code of Conduct

- Be respectful and inclusive
- Provide constructive feedback
- Focus on the code, not the person
- Help others learn and grow

## Questions?

- Open an issue for bug reports or feature requests
- Check existing issues before creating new ones
- For security issues, please email privately to the maintainers

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

Thank you for contributing to AuditAgent! 🎉
