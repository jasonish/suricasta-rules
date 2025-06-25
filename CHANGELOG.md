# Changelog

## [0.3.0] - 2025-06-25

### Added
- Validation to prevent enabling obsolete rulesets with clear error messages
- Filtering of obsolete and deprecated rulesets from interactive selection menu

### Changed
- Interactive ruleset selection now only displays active, maintained rulesets
- Users attempting to enable obsolete rulesets receive informative error messages

## [0.2.0] - 2025-06-25

### Added
- Native Windows CI testing job for better Windows support validation
- Automatic `--user` mode for Windows platforms

### Changed
- Windows now always runs in `--user` mode by default for proper path handling
- Moved main binary from `src/bin/suricasta-rules.rs` to `src/main.rs` for simpler project structure
- Enhanced CI pipeline with native Windows builds and testing

### Fixed
- Windows path resolution issues by enforcing user-mode operation

## [0.1.0] - 2025-06-25

Initial release.
