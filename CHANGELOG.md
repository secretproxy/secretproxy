# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog and this project follows Semantic Versioning.

## [Unreleased]

### Added

- Initial open source release scaffolding
- GitHub release workflow and Homebrew packaging
- Developer docs for contributing and security reporting

## [0.1.0] - 2026-03-31

### Added

- Local HTTP proxy for masking secrets before they reach upstream LLM APIs
- Support for Anthropic, OpenAI-compatible routes, and Codex WebSocket traffic
- Streaming unmasking for SSE and WebSocket responses
- Built-in gitleaks-based secret patterns plus optional regex-based PII detection
- User service commands for launchd and systemd
