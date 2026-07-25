# Changelog

All notable changes are documented here. Versions follow Semantic Versioning.

## 2.1.0 - 2026-07-24

### Added

- Added `checkSecurityStatus()` with `SAFE` (0), `COMPROMISED` (1), and
  `UNKNOWN` (2) results.
- Added `checkSecurityDetailed()` with evidence and unavailable-check metadata.
- Added bounded Frida D-Bus protocol probes instead of treating any open default
  port as conclusive.
- Added bounded Android thread-name inspection and discovery of non-default
  listening ports through process-visible TCP tables.
- Added automated API, packaging, version-consistency, and regression tests.
- Added CI builds against Cordova Android 15.1 and Cordova iOS 8.1.
- Added TypeScript declarations, an enterprise/trading integration profile, and
  a controlled npm release checklist.

### Changed

- Android detection no longer starts shell processes. File, process-local memory,
  file-descriptor, build-provenance, and bounded protocol checks are combined by
  evidence strength.
- Android 13 and newer return `UNKNOWN` from the new APIs when no strong local
  evidence exists. Use server-verified Play Integrity for an authoritative
  production policy.
- iOS checks run off the UI thread and combine jailbreak artifacts, sandbox
  escape, loaded images, symbols, thread names, descriptors, debugger state, and
  a bounded protocol probe.
- Errors, unavailable capabilities, and timeouts now produce `UNKNOWN`, never
  `COMPROMISED`.
- The legacy `checkSecurity()` API remains binary and maps `UNKNOWN` to 0 to
  prevent upgrade-induced user lockouts.

### Fixed

- Removed generic `/private/preboot` detection, which can exist on stock iOS.
- Removed unbounded and false-positive-prone Android shell checks.
- Fixed the case mismatch between `plugin.xml` and `www/rootguard.js`.
- Synchronized versions in `plugin.xml` and `package.json`.
- Removed the iOS `libproc` link and URL-scheme allowlist requirements.

### Security

- Documented why client-side checks cannot guarantee detection against Magisk
  DenyList, renamed Frida Gadget, runtime hooks, repackaging, or iOS Shadow.
- Added guidance for layered, server-side Play Integrity and App Attest policies.

## 2.0.3 - 2025-10-02

- Replaced the unavailable `/system/xbin/which` path.

## 2.0.2 - 2025-10-02

- Added process timeouts and background Android execution.

## 2.0.0 - 2025-04-17

- Added iOS jailbreak and Frida checks.

## 1.0.0

- Initial Android release.
