# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Development and releases moved to GitHub (`https://github.com/haproxy-haptic/haproxy-spoa-hub-plugin-api-gateway`); GitLab is a read-only mirror.

## [0.1.0] - 2026-07-16

### Added

- Add low-latency JSON request-body validation as a `haproxy-spoa-hub` plugin.
- Compile configured JSON Schemas at plugin initialization so request handling
  only parses bounded JSON and runs an in-memory validator.
- Return request validation verdicts through `txn.hub.api_gateway.*` variables.
- Enforce per-request body-size limits and configured request content types.
- Add multi-arch release packaging with SHA256 manifests, keyless cosign bundles,
  and GitLab Generic Package Registry publication.
