# Contributing to Chimera

Thank you for your interest in contributing to Chimera! We welcome contributions from security researchers, data scientists, and engineers.

## Philosophy

Chimera is a **Research Framework** first, and a tool second. We prioritize:
1.  **Correctness**: Algorithms must be implemented correctly and verified.
2.  **Reproducibility**: Use fixed random seeds and deterministic logic where possible.
3.  **Modularity**: New detectors should follow the `BaseDetector` interface.
4.  **Offline Capability**: No external API dependencies by default.

## Getting Started

1.  Fork the repository.
2.  Clone your fork: `git clone https://github.com/your-username/chimera.git`
3.  Install development dependencies:
    ```bash
    pip install -e ".[dev]"
    ```
4.  Run tests to ensure everything is working:
    ```bash
    pytest tests/ -v
    ```

## Code Style

- **Type Hints**: All public functions and classes must be fully type-hinted.
- **Docstrings**: Use Google-style docstrings.
- **Formatting**: We use `black` and `ruff`.
    ```bash
    black chimera/ tests/
    ruff check chimera/ tests/
    ```

## Adding a New Detector

1.  Create a new file in `chimera/detectors/`.
2.  Inherit from `BaseDetector`.
3.  Implement `fit`, `score`, `predict`, and `explain`.
4.  Register it with `@DetectorRegistry.register`.
5.  Add unit tests in `tests/test_detectors.py`.

## Pull Request Process

1.  Ensure all tests pass.
2.  Update documentation if you change behavior.
3.  Describe your changes clearly in the PR description.
4.  Wait for review.

## License

By contributing, you agree that your contributions will be licensed under the project's [MIT License](LICENSE).
