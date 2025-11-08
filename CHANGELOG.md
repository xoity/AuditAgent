# Changelog

All notable changes to AuditAgent.

## [1.0.0] - 2025-11-08

### Summary

- Major release: stable `1.0.0` containing AI remediation reliability fixes, CLI fixes, and improved enforcement handling.

### Highlights

- Fix: Use safe JSON-style YAML serialization for AI prompts to avoid Python-specific YAML tags (fixed `!!python/...` output).
- Fix: Added detection for all-`missing_rule` audit results and return original policy when policy is already correct (prevents unnecessary AI-generated policy changes).
- Fix: Corrected async handling and CLI enforcement invocation (use `asyncio.run(...)`).
- Fix: Corrected `NetworkPolicy.from_yaml()` usage and other minor method-name fixes.
- Improvement: Google AI provider integration updated—uses `X-goog-api-key` header, retry/backoff logic for rate-limits, and robust prompt/response handling.
- Feature: Added programmatic fallback policy generator for deterministic remediation when AI is unavailable.
- Testing: Added debug/test scripts to exercise AI remediation flows and prompts; added Vagrant test policy and device configs (`vagrant-policy.yaml` and `vagrant-devices.yaml`).

### Files/Artifacts

- `audit_agent/ai/remediation.py` — safe YAML serialization and missing-rule detection
- `audit_agent/ai/providers.py` — GoogleAIProvider improvements and retries
- `audit_agent/cli.py` — CLI guidance for enforcement-only scenarios and async fixes
- `vagrant-policy.yaml`, `vagrant-devices.yaml` — new test files for Vagrant server

## [0.1.0]

- Initial packaging and baseline functionality (earlier development release).

---

For more details see the repository commits and the `AI` branch history.
