import { describe, it, expect } from 'vitest';
import { SECURITY_RULES, getRulesBySeverity, getRulesByCategory, getCategories } from '../src/rules.js';

describe('Security Rules', () => {
  it('has at least 25 rules', () => {
    expect(SECURITY_RULES.length).toBeGreaterThanOrEqual(25);
  });

  it('has rules for all severity levels', () => {
    const severities = new Set(SECURITY_RULES.map(r => r.severity));
    expect(severities).toContain('critical');
    expect(severities).toContain('high');
    expect(severities).toContain('medium');
    expect(severities).toContain('low');
  });

  it('every rule has required fields', () => {
    for (const rule of SECURITY_RULES) {
      expect(rule.id).toBeTruthy();
      expect(rule.name).toBeTruthy();
      expect(rule.description).toBeTruthy();
      expect(rule.severity).toBeTruthy();
      expect(rule.category).toBeTruthy();
      expect(rule.patterns.length).toBeGreaterThan(0);
      expect(rule.fileTypes.length).toBeGreaterThan(0);
    }
  });

  it('every rule has a unique id', () => {
    const ids = SECURITY_RULES.map(r => r.id);
    const uniqueIds = new Set(ids);
    expect(uniqueIds.size).toBe(ids.length);
  });

  it('every rule has valid regex patterns', () => {
    for (const rule of SECURITY_RULES) {
      for (const pattern of rule.patterns) {
        expect(pattern).toBeInstanceOf(RegExp);
      }
    }
  });

  describe('getRulesBySeverity', () => {
    it('returns only critical rules', () => {
      const critical = getRulesBySeverity('critical');
      expect(critical.length).toBeGreaterThan(0);
      expect(critical.every(r => r.severity === 'critical')).toBe(true);
    });

    it('returns only high rules', () => {
      const high = getRulesBySeverity('high');
      expect(high.length).toBeGreaterThan(0);
      expect(high.every(r => r.severity === 'high')).toBe(true);
    });
  });

  describe('getRulesByCategory', () => {
    it('returns rules for Injection category', () => {
      const injection = getRulesByCategory('Injection');
      expect(injection.length).toBeGreaterThan(0);
      expect(injection.every(r => r.category === 'Injection')).toBe(true);
    });

    it('returns rules for Secrets category', () => {
      const secrets = getRulesByCategory('Secrets');
      expect(secrets.length).toBeGreaterThan(0);
    });
  });

  describe('getCategories', () => {
    it('returns all unique categories', () => {
      const categories = getCategories();
      expect(categories.length).toBeGreaterThan(0);
      expect(categories).toContain('Injection');
      expect(categories).toContain('Secrets');
      expect(categories).toContain('XSS');
    });
  });

  // Pattern matching tests for each severity
  describe('Critical patterns', () => {
    it('detects hardcoded API keys', () => {
      const rule = SECURITY_RULES.find(r => r.id === 'hardcoded-secret-api-key')!;
      const testCode = 'const apiKey = "secret_test_abcdef1234567890abcdef1234567890";';
      const matches = rule.patterns.some(p => {
        p.lastIndex = 0;
        return p.test(testCode);
      });
      expect(matches).toBe(true);
    });

    it('detects AWS access keys', () => {
      const rule = SECURITY_RULES.find(r => r.id === 'hardcoded-secret-api-key')!;
      const testCode = 'const key = "AKIAIOSFODNN7EXAMPLE";';
      const matches = rule.patterns.some(p => {
        p.lastIndex = 0;
        return p.test(testCode);
      });
      expect(matches).toBe(true);
    });

    it('detects hardcoded passwords', () => {
      const rule = SECURITY_RULES.find(r => r.id === 'hardcoded-password')!;
      const testCode = 'const password = "SuperSecret123!";';
      const matches = rule.patterns.some(p => {
        p.lastIndex = 0;
        return p.test(testCode);
      });
      expect(matches).toBe(true);
    });

    it('detects private keys', () => {
      const rule = SECURITY_RULES.find(r => r.id === 'private-key-exposed')!;
      const testCode = '-----BEGIN RSA PRIVATE KEY-----';
      const matches = rule.patterns.some(p => {
        p.lastIndex = 0;
        return p.test(testCode);
      });
      expect(matches).toBe(true);
    });

    it('does not flag environment variable usage as hardcoded', () => {
      const rule = SECURITY_RULES.find(r => r.id === 'hardcoded-password')!;
      const testCode = 'const password = process.env.DB_PASSWORD;';
      const matches = rule.patterns.some(p => {
        p.lastIndex = 0;
        return p.test(testCode);
      });
      expect(matches).toBe(false);
    });

    it('does not flag console.error with secret in message string', () => {
      const rule = SECURITY_RULES.find(r => r.id === 'hardcoded-password')!;
      const testCode = "console.error('Failed to get secret:', error)";
      const matches = rule.patterns.some(p => {
        p.lastIndex = 0;
        return p.test(testCode);
      });
      expect(matches).toBe(false);
    });

    it('does not match secret keyword across multiple lines', () => {
      const rule = SECURITY_RULES.find(r => r.id === 'hardcoded-password')!;
      const testCode = "console.error('Failed to get secret:', error)\n    return NextResponse.json({ error: 'Failed to get secret' })";
      const matches = rule.patterns.some(p => {
        p.lastIndex = 0;
        return p.test(testCode);
      });
      expect(matches).toBe(false);
    });

    it('detects password in object literal', () => {
      const rule = SECURITY_RULES.find(r => r.id === 'hardcoded-password')!;
      const testCode = '{ password: "SuperSecret123!" }';
      const matches = rule.patterns.some(p => {
        p.lastIndex = 0;
        return p.test(testCode);
      });
      expect(matches).toBe(true);
    });
  });

  describe('High patterns', () => {
    it('detects SQL injection via template literals', () => {
      const rule = SECURITY_RULES.find(r => r.id === 'sql-injection-concat')!;
      const testCode = 'db.query(`SELECT * FROM users WHERE id = ${userId}`)';
      const matches = rule.patterns.some(p => {
        p.lastIndex = 0;
        return p.test(testCode);
      });
      expect(matches).toBe(true);
    });

    it('does not flag parameterized queries', () => {
      const rule = SECURITY_RULES.find(r => r.id === 'sql-injection-concat')!;
      const testCode = 'db.query("SELECT * FROM users WHERE id = ?", [userId])';
      const matches = rule.patterns.some(p => {
        p.lastIndex = 0;
        return p.test(testCode);
      });
      expect(matches).toBe(false);
    });

    it('detects innerHTML XSS', () => {
      const rule = SECURITY_RULES.find(r => r.id === 'xss-innerhtml')!;
      const testCode = 'element.innerHTML = userInput;';
      const matches = rule.patterns.some(p => {
        p.lastIndex = 0;
        return p.test(testCode);
      });
      expect(matches).toBe(true);
    });

    it('detects command injection', () => {
      const rule = SECURITY_RULES.find(r => r.id === 'command-injection')!;
      const testCode = 'exec(`convert ${filename}.png`)';
      const matches = rule.patterns.some(p => {
        p.lastIndex = 0;
        return p.test(testCode);
      });
      expect(matches).toBe(true);
    });

    it('detects eval usage', () => {
      const rule = SECURITY_RULES.find(r => r.id === 'eval-usage')!;
      const testCode = 'eval(userCode)';
      const matches = rule.patterns.some(p => {
        p.lastIndex = 0;
        return p.test(testCode);
      });
      expect(matches).toBe(true);
    });

    it('detects path traversal', () => {
      const rule = SECURITY_RULES.find(r => r.id === 'path-traversal')!;
      const testCode = 'fs.readFile(req.params.filename)';
      const matches = rule.patterns.some(p => {
        p.lastIndex = 0;
        return p.test(testCode);
      });
      expect(matches).toBe(true);
    });

    it('detects NoSQL injection', () => {
      const rule = SECURITY_RULES.find(r => r.id === 'nosql-injection')!;
      const testCode = 'db.find({ user: req.body.user })';
      const matches = rule.patterns.some(p => {
        p.lastIndex = 0;
        return p.test(testCode);
      });
      expect(matches).toBe(true);
    });

    it('detects SSRF', () => {
      const rule = SECURITY_RULES.find(r => r.id === 'ssrf-fetch')!;
      const testCode = 'fetch(`https://api.com/${req.query.url}`)';
      const matches = rule.patterns.some(p => {
        p.lastIndex = 0;
        return p.test(testCode);
      });
      expect(matches).toBe(true);
    });

    it('detects Python SQL injection', () => {
      const rule = SECURITY_RULES.find(r => r.id === 'sql-injection-python')!;
      const testCode = 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")';
      const matches = rule.patterns.some(p => {
        p.lastIndex = 0;
        return p.test(testCode);
      });
      expect(matches).toBe(true);
    });
  });

  describe('Medium patterns', () => {
    it('detects MD5 usage', () => {
      const rule = SECURITY_RULES.find(r => r.id === 'weak-crypto-md5')!;
      const testCode = 'crypto.createHash("md5")';
      const matches = rule.patterns.some(p => {
        p.lastIndex = 0;
        return p.test(testCode);
      });
      expect(matches).toBe(true);
    });

    it('detects SHA1 usage', () => {
      const rule = SECURITY_RULES.find(r => r.id === 'weak-crypto-sha1')!;
      const testCode = 'crypto.createHash("sha1")';
      const matches = rule.patterns.some(p => {
        p.lastIndex = 0;
        return p.test(testCode);
      });
      expect(matches).toBe(true);
    });

    it('does not flag SHA256', () => {
      const md5Rule = SECURITY_RULES.find(r => r.id === 'weak-crypto-md5')!;
      const sha1Rule = SECURITY_RULES.find(r => r.id === 'weak-crypto-sha1')!;
      const testCode = 'crypto.createHash("sha256")';

      const md5Match = md5Rule.patterns.some(p => {
        p.lastIndex = 0;
        return p.test(testCode);
      });
      const sha1Match = sha1Rule.patterns.some(p => {
        p.lastIndex = 0;
        return p.test(testCode);
      });
      expect(md5Match).toBe(false);
      expect(sha1Match).toBe(false);
    });

    it('detects CORS wildcard', () => {
      const rule = SECURITY_RULES.find(r => r.id === 'cors-wildcard')!;
      const testCode = 'app.use(cors())';
      const matches = rule.patterns.some(p => {
        p.lastIndex = 0;
        return p.test(testCode);
      });
      expect(matches).toBe(true);
    });

    it('detects sensitive console.log with variable', () => {
      const rule = SECURITY_RULES.find(r => r.id === 'console-log-sensitive')!;
      const testCode = 'console.log("Debug:", token);';
      const matches = rule.patterns.some(p => {
        p.lastIndex = 0;
        return p.test(testCode);
      });
      expect(matches).toBe(true);
    });

    it('does not flag isSecret or hasToken variable names in timing attack', () => {
      const rule = SECURITY_RULES.find(r => r.id === 'timing-attack')!;
      const testCode = 'if (isSecret !== undefined)';
      const matches = rule.patterns.some(p => {
        p.lastIndex = 0;
        return p.test(testCode);
      });
      expect(matches).toBe(false);
    });

    it('does not flag typeof type guards in timing attack', () => {
      const rule = SECURITY_RULES.find(r => r.id === 'timing-attack')!;
      const testCode = "if (typeof secret !== 'string')";
      const matches = rule.patterns.some(p => {
        p.lastIndex = 0;
        return p.test(testCode);
      });
      expect(matches).toBe(false);
    });

    it('detects missing rate limiting on login', () => {
      const rule = SECURITY_RULES.find(r => r.id === 'missing-rate-limit')!;
      const testCode = 'app.post("/login", handler)';
      const matches = rule.patterns.some(p => {
        p.lastIndex = 0;
        return p.test(testCode);
      });
      expect(matches).toBe(true);
    });
  });

  describe('Low patterns', () => {
    it('detects debug mode', () => {
      const rule = SECURITY_RULES.find(r => r.id === 'debug-mode')!;
      const testCode = 'DEBUG = true';
      const matches = rule.patterns.some(p => {
        p.lastIndex = 0;
        return p.test(testCode);
      });
      expect(matches).toBe(true);
    });

    it('detects HTTP URLs (non-localhost)', () => {
      const rule = SECURITY_RULES.find(r => r.id === 'http-without-tls')!;
      const testCode = 'fetch("http://api.example.com/data")';
      const matches = rule.patterns.some(p => {
        p.lastIndex = 0;
        return p.test(testCode);
      });
      expect(matches).toBe(true);
    });

    it('does not flag localhost HTTP', () => {
      const rule = SECURITY_RULES.find(r => r.id === 'http-without-tls')!;
      const testCode = 'fetch("http://localhost:3000/api")';
      const matches = rule.patterns.some(p => {
        p.lastIndex = 0;
        return p.test(testCode);
      });
      expect(matches).toBe(false);
    });

    it('does not flag SVG/XML namespace URIs', () => {
      const rule = SECURITY_RULES.find(r => r.id === 'http-without-tls')!;
      const testCode = 'xmlns="http://www.w3.org/2000/svg"';
      const matches = rule.patterns.some(p => {
        p.lastIndex = 0;
        return p.test(testCode);
      });
      expect(matches).toBe(false);
    });

    it('does not flag schema.org URIs', () => {
      const rule = SECURITY_RULES.find(r => r.id === 'http-without-tls')!;
      const testCode = "'http://schema.org/extensions'";
      const matches = rule.patterns.some(p => {
        p.lastIndex = 0;
        return p.test(testCode);
      });
      expect(matches).toBe(false);
    });

    it('does not flag NODE_ENV checks as debug mode', () => {
      const rule = SECURITY_RULES.find(r => r.id === 'debug-mode')!;
      const testCode = "if (process.env.NODE_ENV === 'development')";
      const matches = rule.patterns.some(p => {
        p.lastIndex = 0;
        return p.test(testCode);
      });
      expect(matches).toBe(false);
    });

    it('detects security TODOs', () => {
      const rule = SECURITY_RULES.find(r => r.id === 'todo-security')!;
      const testCode = '// TODO: fix authentication bypass vulnerability';
      const matches = rule.patterns.some(p => {
        p.lastIndex = 0;
        return p.test(testCode);
      });
      expect(matches).toBe(true);
    });

    it('detects error message disclosure', () => {
      const rule = SECURITY_RULES.find(r => r.id === 'error-disclosure')!;
      const testCode = 'res.send(err.stack)';
      const matches = rule.patterns.some(p => {
        p.lastIndex = 0;
        return p.test(testCode);
      });
      expect(matches).toBe(true);
    });
  });
});
