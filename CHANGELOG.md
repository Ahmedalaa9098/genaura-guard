# Changelog

## [1.0.0] - 2026-01-29

### Added

- Security scanning with 20+ OWASP rules across 4 severity levels (critical, high, medium, low)
- **`genaura-guard scan`** — Default scan with severity filtering, exclusion patterns, and JSON output
- **`genaura-guard quick`** — Quick scan for critical and high severity issues only
- **`genaura-guard full`** — Explicit full scan across all severity levels
- **`genaura-guard fix`** — Detailed per-file fix report with line numbers, problematic code, and fix suggestions
- **Fix Guide** — Every scan ends with a deduplicated summary grouped by rule, with instance counts, affected files, fix instructions, and reference links
- **`genaura-guard init`** — Install git pre-push hook and auto-discover + inject security rules into project-level AI config files (CLAUDE.md, .cursorrules, AGENTS.md, and any other AI tool configs found in the project root)
- **`genaura-guard sync`** — Sync security rules to global AI tool configs (~/.claude, ~/.cursor, etc.)
- **`genaura-guard status`** — Show current hooks and sync status
- **`genaura-guard rules`** — List all security rules
- **`genaura-guard uninstall`** — Remove git hooks
- Git pre-push hook with top 5 findings, fix suggestions, and severity-based exit codes (0 = clean, 1 = warn, 2 = block)
- Optional pre-commit hook for staged files
- JSON output for CI/CD integration
- AI config auto-discovery: markdown configs, dotfile rules, tool directories, UPPERCASE.md, .toolrules patterns
- Idempotent injection using HTML comment markers
