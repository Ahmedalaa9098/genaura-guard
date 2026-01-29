<p align="center">
  <img src="assets/banner.svg" alt="Genaura Guard" width="100%">
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/genaura-guard"><img src="https://img.shields.io/npm/v/genaura-guard.svg?style=flat-square&color=1e3a5f" alt="npm version"></a>
  <a href="https://www.npmjs.com/package/genaura-guard"><img src="https://img.shields.io/npm/dm/genaura-guard.svg?style=flat-square&color=1e3a5f" alt="npm downloads"></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-1e3a5f.svg?style=flat-square" alt="License: MIT"></a>
</p>

<p align="center">
  <strong>Security scanner for vibe coders. Find vulnerabilities before you push.</strong>
</p>

<p align="center">
  <a href="#the-problem">Problem</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#what-it-catches">What It Catches</a> •
  <a href="#commands">Commands</a> •
  <a href="#fix-guide">Fix Guide</a> •
  <a href="#git-hooks">Git Hooks</a>
</p>

---

## The Problem

You're vibe coding with Claude, Cursor, Copilot. AI generates code fast. You ship fast.

But AI doesn't think about security:

```javascript
// AI happily generates this:
db.query(`SELECT * FROM users WHERE id = ${userId}`);  // SQL injection 💀

const apiKey = "sk_live_abc123...";  // Hardcoded secret 💀

element.innerHTML = userInput;  // XSS vulnerability 💀

exec(`convert ${filename}.png`);  // Command injection 💀
```

You push to prod. Hackers find it. Data breach. Career ruined.

## The Solution

Genaura Guard scans your code **before you push**. Catches security issues instantly.

```bash
npx genaura-guard
```

```
🛡️  GENAURA GUARD

Found 4 security issues
──────────────────────────────────────────────
💀 1 critical  ✗ 2 high  ⚠ 1 medium

Findings
──────────────────────────────────────────────

💀 CRITICAL Hardcoded API Key
   src/config.ts:12
   const apiKey = "sk_live_...
   → Move secrets to environment variables

✗ HIGH SQL Injection (String Concatenation)
   src/db/users.ts:42
   db.query(`SELECT * FROM users WHERE id = ${userId}`)
   → Use parameterized queries: db.query("SELECT * FROM users WHERE id = ?", [userId])

✗ HIGH XSS via innerHTML
   src/components/Comment.tsx:28
   element.innerHTML = userContent
   → Use textContent for text, or sanitize HTML with DOMPurify

⚠ MEDIUM Weak Cryptography (MD5)
   src/utils/hash.ts:8
   crypto.createHash("md5")
   → Use SHA-256 or better. For passwords, use bcrypt or argon2

⚠️  Fix Guide
──────────────────────────────────────────────
💀 Hardcoded API Key (1 instance in 1 file)
   Fix: Move secrets to environment variables
✗ SQL Injection (1 instance in 1 file)
   Fix: Use parameterized queries
✗ XSS via innerHTML (1 instance in 1 file)
   Fix: Use textContent or sanitize with DOMPurify
⚠ Weak Cryptography (1 instance in 1 file)
   Fix: Use SHA-256 or better
```

## Quick Start

```bash
# Install globally
npm install -g genaura-guard

# Scan your project
genaura-guard

# Get detailed fix instructions per file
genaura-guard fix

# Install git hook + auto-inject rules into your AI configs
genaura-guard init
```

Or use without installing:

```bash
npx genaura-guard
```

That's it. `init` installs the pre-push hook **and** auto-discovers your AI config files (CLAUDE.md, .cursorrules, AGENTS.md, etc.) to inject security rules.

## What It Catches

### 💀 Critical (Stop Everything)

| Issue | Example |
|-------|---------|
| **Hardcoded API Keys** | `const key = "sk_live_..."` |
| **Hardcoded Passwords** | `password = "admin123"` |
| **Private Keys in Code** | `-----BEGIN RSA PRIVATE KEY-----` |

### ✗ High (Fix Before Deploy)

| Issue | Example |
|-------|---------|
| **SQL Injection** | `` db.query(`SELECT * FROM users WHERE id = ${id}`) `` |
| **XSS (innerHTML)** | `element.innerHTML = userInput` |
| **Command Injection** | `` exec(`rm -rf ${userInput}`) `` |
| **Path Traversal** | `fs.readFile(req.params.filename)` |
| **NoSQL Injection** | `db.find({ user: req.body.user })` |
| **SSRF** | `fetch(req.query.url)` |
| **Eval Usage** | `eval(userCode)` |
| **JWT None Algorithm** | `algorithms: ["none"]` |

### ⚠ Medium (Should Fix)

| Issue | Example |
|-------|---------|
| **Weak Crypto (MD5/SHA1)** | `crypto.createHash("md5")` |
| **Insecure Cookies** | Missing httpOnly, secure, sameSite |
| **CORS Wildcard** | `cors({ origin: "*" })` |
| **Missing Rate Limit** | Login endpoint without rate limiting |
| **Timing Attacks** | `if (token === secret)` |
| **Unvalidated Redirects** | `res.redirect(req.query.url)` |

### ○ Low (Best Practice)

| Issue | Example |
|-------|---------|
| **Debug Mode On** | `DEBUG=true` in production |
| **Security TODOs** | `// TODO: fix auth` |
| **HTTP URLs** | `fetch("http://api.example.com")` |
| **Weak Randomness** | `Math.random()` for tokens |
| **Error Disclosure** | `res.send(err.stack)` |

## Commands

```bash
# Default scan (all severities)
genaura-guard                     # Scan current directory
genaura-guard scan ./src          # Scan specific path
genaura-guard scan --json         # Output as JSON

# Quick scan (critical + high only)
genaura-guard quick               # Fast pre-push check

# Full scan (explicit all severities)
genaura-guard full                # Same as default, explicit alias

# Fix report (detailed per-file fix instructions)
genaura-guard fix                 # Show what to fix and how
genaura-guard fix ./src           # Fix report for specific path
genaura-guard fix --severity critical,high

# Filter by severity
genaura-guard scan --severity critical,high
genaura-guard scan --severity medium,low

# Exclude patterns
genaura-guard scan --exclude "test/**,*.spec.ts"

# Setup
genaura-guard init                # Install pre-push hook + inject AI configs
genaura-guard init --pre-commit   # Also install pre-commit hook
genaura-guard uninstall           # Remove hooks

# Sync to AI tools (global configs)
genaura-guard sync                # Add rules to ~/.claude, ~/.cursor, etc.
genaura-guard sync claude cursor  # Sync to specific tools

# Info
genaura-guard status              # Show hooks and sync status
genaura-guard rules               # List all security rules
```

## Fix Guide

Every scan ends with a **Fix Guide** — a deduplicated summary of all issues grouped by rule, with fix instructions and reference links.

For detailed per-file instructions, run:

```bash
genaura-guard fix
```

```
🛡️  GENAURA GUARD

Found 3 security issues
──────────────────────────────────────────────

Fix Report
──────────────────────────────────────────────

📄 src/config.ts (1 issue)
   L12 💀 Hardcoded API Key
      - const apiKey = "sk_live_abc123..."
      + Move secrets to environment variables

📄 src/db/users.ts (2 issues)
   L42 ✗ SQL Injection (String Concatenation)
      - db.query(`SELECT * FROM users WHERE id = ${userId}`)
      + Use parameterized queries
   L78 ⚠ Weak Cryptography (MD5)
      - crypto.createHash("md5")
      + Use SHA-256 or better

⚠️  Fix Guide
──────────────────────────────────────────────
💀 Hardcoded API Key (1 instance in 1 file)
   Fix: Move secrets to environment variables
✗ SQL Injection (1 instance in 1 file)
   Fix: Use parameterized queries
⚠ Weak Cryptography (1 instance in 1 file)
   Fix: Use SHA-256 or better
```

## Git Hooks

### Pre-Push Hook (Recommended)

Scans before every push. Blocks if critical issues found.

```bash
genaura-guard init
```

When you `git push`:

```
─────────────────────────────────────────────────────
🛡️  Genaura Guard found security issues:

   💀 1 critical issue
   ✗ 2 high severity issues

   💀 config.ts:12 Hardcoded API Key
      → Move secrets to environment variables
   ✗ users.ts:42 SQL Injection
      → Use parameterized queries

 Run genaura-guard scan for full details.
 Run genaura-guard fix for fix guidance.
─────────────────────────────────────────────────────
```

- **Critical issues** → Push blocked (exit code 2)
- **High issues** → Warning, ask to continue (exit code 1)
- **Medium/Low** → Passes (exit code 0)

### Pre-Commit Hook (Optional)

Quick scan of staged files only.

```bash
genaura-guard init --pre-commit
```

### Manual Pre-Push Check

Don't want hooks? Run manually before pushing:

```bash
genaura-guard quick && git push
```

## AI Tool Integration

### Auto-Injection via `init`

When you run `genaura-guard init`, it automatically discovers and injects security rules into your project-level AI config files:

```bash
genaura-guard init
```

```
🛡️  GENAURA GUARD

Installing Git Hooks
─────────────────────────────────────────────
✓ Installed pre-push hook

AI Config Rules
─────────────────────────────────────────────
✓ Updated CLAUDE.md
✓ Updated .cursorrules
✓ Updated AGENTS.md
○ .github/copilot-instructions.md already configured
```

It discovers any AI config files in your project root:

| Auto-Detected | Examples |
|---------------|----------|
| **Markdown configs** | `CLAUDE.md`, `AGENTS.md`, `COPILOT.md`, `CLINE.md` |
| **Dotfile rules** | `.cursorrules`, `.clinerules`, `.boltrules`, `.replitrules` |
| **Tool directories** | `.cursor/rules/`, `.github/copilot-instructions.md`, `.v0/instructions.md` |
| **Any UPPERCASE.md** | Scans root for all uppercase markdown files |
| **Any .toolrules** | Scans root for all dotfile rule patterns |

Injection is **idempotent** — running `init` again won't duplicate the section.

### Global Sync

For global AI tool configs (not project-level), use `sync`:

```bash
genaura-guard sync
```

Writes `SECURITY.md` to:

| Tool | Path |
|------|------|
| Claude | `~/.claude/SECURITY.md` |
| Cursor | `~/.cursor/rules/security.md` |
| Codex | `~/.codex/SECURITY.md` |
| Copilot | `~/.copilot/security.md` |
| Gemini | `~/.gemini/SECURITY.md` |
| Windsurf | `~/.windsurf/security.md` |
| OpenCode | `~/.opencode/security.md` |

Now when you ask AI to write code, it follows security best practices.

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run Genaura Guard
        run: npx genaura-guard --json > security-report.json
      - name: Check for critical issues
        run: |
          CRITICAL=$(cat security-report.json | jq '.summary.critical')
          if [ "$CRITICAL" -gt 0 ]; then
            echo "Critical security issues found!"
            exit 1
          fi
```

### GitLab CI

```yaml
security_scan:
  script:
    - npx genaura-guard
  allow_failure: false
```

## Configuration

Create `.guardrc.json` in your project root:

```json
{
  "exclude": [
    "test/**",
    "**/*.test.ts",
    "scripts/**"
  ],
  "severityThreshold": "high",
  "hooks": {
    "blockOnCritical": true,
    "blockOnHigh": false
  }
}
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No issues found (or only low) |
| 1 | High/medium issues found |
| 2 | Critical issues found |

## Why This Exists

I was vibe coding. Shipped fast. Felt good.

Then I found SQL injection in my production code. Hardcoded API keys. innerHTML with user input everywhere.

AI generates code fast. But it doesn't think about security.

**Genaura Guard catches what AI misses.** Run it before you push.

## Links

- [npm](https://www.npmjs.com/package/genaura-guard)
- [GitHub](https://github.com/Harkanovac/genaura-guard)
- [Genaura Sync](https://github.com/Harkanovac/genaura-sync) - Rate and sync AI skills
- [Genaura](https://genaura.app) - AWS SaaS Control Panel

## License

MIT © [Genaura](https://genaura.app)
