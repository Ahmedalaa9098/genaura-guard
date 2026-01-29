import { SecurityRule } from './types.js';

// All file types we scan
export const ALL_CODE_FILES = [
  '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs',
  '.py', '.rb', '.php', '.go', '.java', '.cs',
  '.vue', '.svelte', '.astro'
];

export const JS_TS_FILES = ['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.vue', '.svelte', '.astro'];
export const PYTHON_FILES = ['.py'];
export const PHP_FILES = ['.php'];
export const CONFIG_FILES = ['.json', '.yaml', '.yml', '.env', '.toml', '.ini'];

export const SECURITY_RULES: SecurityRule[] = [
  // ==========================================
  // CRITICAL - Stop everything, fix now
  // ==========================================
  {
    id: 'hardcoded-secret-api-key',
    name: 'Hardcoded API Key',
    description: 'API key or secret token found in source code',
    severity: 'critical',
    category: 'Secrets',
    patterns: [
      // Generic API keys
      /['"`](?:sk|pk|api|key|token|secret|password|auth)[_-]?(?:live|prod|test|dev)?[_-]?[a-zA-Z0-9]{20,}['"`]/gi,
      // AWS
      /['"`]AKIA[0-9A-Z]{16}['"`]/g,
      // Stripe
      /['"`]sk_live_[a-zA-Z0-9]{24,}['"`]/g,
      /['"`]pk_live_[a-zA-Z0-9]{24,}['"`]/g,
      // OpenAI
      /['"`]sk-[a-zA-Z0-9]{40,}['"`]/g,
      // GitHub
      /['"`]ghp_[a-zA-Z0-9]{36,}['"`]/g,
      /['"`]github_pat_[a-zA-Z0-9_]{20,}['"`]/g,
      // Slack
      /['"`]xox[baprs]-[a-zA-Z0-9-]{10,}['"`]/g,
      // Twilio
      /['"`]SK[a-f0-9]{32}['"`]/g,
      // SendGrid
      /['"`]SG\.[a-zA-Z0-9_-]{20,}['"`]/g,
      // Firebase
      /['"`]AIza[0-9A-Za-z_-]{35}['"`]/g,
    ],
    fileTypes: ALL_CODE_FILES,
    fix: 'Move secrets to environment variables. Use: process.env.API_KEY',
    references: ['https://owasp.org/Top10/A02_2021-Cryptographic_Failures/'],
  },
  {
    id: 'hardcoded-password',
    name: 'Hardcoded Password',
    description: 'Password or credential hardcoded in source code',
    severity: 'critical',
    category: 'Secrets',
    patterns: [
      // Assignment with = (e.g. password = "value", const secret = "abc")
      /\b(?:password|passwd|pwd|secret|credential)\s*=\s*['"`][^'"`\n]{4,}['"`]/gi,
      // Object/config key with : (e.g. password: "value", { secret: "abc" })
      // Require keyword to be in object key position (after { or ,) and NOT be a ternary like ? 'password' : 'text'
      /(?:^|[{,]\s*)\b(?:password|passwd|pwd|secret|credential)\b\s*:\s*(?!['"`](?:text|hidden|number|email|tel)\b)['"`][^'"`\n]{4,}['"`]/gim,
      // Quoted keys in JSON/objects (e.g. "password": "value")
      // Require object context (after { or ,) to avoid matching ternaries like ? 'password' : 'text'
      /(?:[{,])\s*['"`](?:password|passwd|pwd|secret|credential)['"`]\s*:\s*['"`][^'"`\n]{4,}['"`]/gi,
      // DB-specific password variables
      /\b(?:db_pass|database_password|mysql_pwd|postgres_password)\s*[=:]\s*['"`][^'"`\n]+['"`]/gi,
    ],
    fileTypes: ALL_CODE_FILES,
    fix: 'Use environment variables: process.env.DB_PASSWORD',
    references: ['https://cwe.mitre.org/data/definitions/798.html'],
  },
  {
    id: 'private-key-exposed',
    name: 'Private Key Exposed',
    description: 'Private key found in source code',
    severity: 'critical',
    category: 'Secrets',
    patterns: [
      /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g,
      /-----BEGIN PGP PRIVATE KEY BLOCK-----/g,
    ],
    fileTypes: [...ALL_CODE_FILES, ...CONFIG_FILES],
    fix: 'Never commit private keys. Use secrets management or environment variables.',
    references: ['https://owasp.org/Top10/A02_2021-Cryptographic_Failures/'],
  },

  // ==========================================
  // HIGH - Serious vulnerability, fix before deploy
  // ==========================================
  {
    id: 'sql-injection-concat',
    name: 'SQL Injection (String Concatenation)',
    description: 'SQL query built with string concatenation - vulnerable to injection',
    severity: 'high',
    category: 'Injection',
    patterns: [
      // db.query/execute/sql("SELECT...${var}") — excludes Prisma tagged templates ($executeRaw`...`)
      /(?:query|execute|sql)\s*\(\s*['"](?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER).*\$\{/gi,
      // String concat: query("SELECT..." + var)
      /(?:query|execute|raw|sql)\s*\(\s*['"`](?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER).*['"`]\s*\+/gi,
      // .query(`...${var}`) without parameterized ? placeholder
      /\.query\s*\(\s*`[^`]*\$\{(?!.*\?)/gi,
      // Template literal SQL WHERE clause with direct variable interpolation (not .join, not Prisma tagged templates)
      /(?<!Raw\s*`)(?:SELECT|INSERT|UPDATE|DELETE)\s+\w+.*(?:WHERE|VALUES\s*\()\s*[^'"`]*\$\{(?![^}]*\.join)[^}]+\}/gi,
    ],
    fileTypes: JS_TS_FILES,
    fix: 'Use parameterized queries: db.query("SELECT * FROM users WHERE id = ?", [userId])',
    references: ['https://owasp.org/Top10/A03_2021-Injection/'],
  },
  {
    id: 'sql-injection-python',
    name: 'SQL Injection (Python)',
    description: 'SQL query built with string formatting - vulnerable to injection',
    severity: 'high',
    category: 'Injection',
    patterns: [
      /execute\s*\(\s*f['"`](?:SELECT|INSERT|UPDATE|DELETE)/gi,
      /execute\s*\(\s*['"`](?:SELECT|INSERT|UPDATE|DELETE).*%s/gi,
      /cursor\.execute\s*\(\s*['"`].*['"`]\s*%/gi,
      /\.format\s*\([^)]*\).*(?:SELECT|INSERT|UPDATE|DELETE)/gi,
    ],
    fileTypes: PYTHON_FILES,
    fix: 'Use parameterized queries: cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
    references: ['https://owasp.org/Top10/A03_2021-Injection/'],
  },
  {
    id: 'xss-innerhtml',
    name: 'XSS via innerHTML',
    description: 'Using innerHTML with potentially untrusted content',
    severity: 'high',
    category: 'XSS',
    patterns: [
      /\.innerHTML\s*=\s*(?!['"`]<)/g,
      /\.innerHTML\s*=\s*`[^`]*\$\{/g,
      /\.innerHTML\s*\+=\s*/g,
      /\[['"`]innerHTML['"`]\]\s*=/g,
    ],
    fileTypes: JS_TS_FILES,
    fix: 'Use textContent for text, or sanitize HTML with DOMPurify',
    references: ['https://owasp.org/Top10/A03_2021-Injection/'],
  },
  {
    id: 'xss-dangerously-set',
    name: 'XSS via dangerouslySetInnerHTML',
    description: 'Using dangerouslySetInnerHTML without sanitization',
    severity: 'high',
    category: 'XSS',
    patterns: [
      // Only flag when __html receives unsanitized user input (variable/prop)
      // Exclude: sanitize/purify, JSON.stringify, Object.entries, template literals (inline CSS/JS)
      /dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*(?!.*(?:sanitize|purify|escape|DOMPurify|JSON\.stringify|Object\.entries))(?!`)[^}`]+\}\s*\}/gi,
    ],
    fileTypes: JS_TS_FILES,
    fix: 'Sanitize HTML with DOMPurify: dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }}',
    references: ['https://owasp.org/Top10/A03_2021-Injection/'],
  },
  {
    id: 'command-injection',
    name: 'Command Injection',
    description: 'Executing shell commands with user-controlled input',
    severity: 'high',
    category: 'Injection',
    patterns: [
      // Node.js
      /(?:exec|execSync|spawn|spawnSync)\s*\(\s*`[^`]*\$\{/g,
      /(?:exec|execSync|spawn|spawnSync)\s*\(\s*['"`].*['"`]\s*\+/g,
      /child_process.*(?:exec|spawn)\s*\([^)]*\+/g,
      // Python
      /(?:os\.system|subprocess\.call|subprocess\.run|subprocess\.Popen)\s*\(\s*f['"`]/g,
      /(?:os\.system|subprocess\.call)\s*\([^)]*\+/g,
    ],
    fileTypes: [...JS_TS_FILES, ...PYTHON_FILES],
    fix: 'Use spawn with array arguments, never concatenate user input into commands',
    references: ['https://owasp.org/Top10/A03_2021-Injection/'],
  },
  {
    id: 'eval-usage',
    name: 'Dangerous eval() Usage',
    description: 'Using eval() which can execute arbitrary code',
    severity: 'high',
    category: 'Injection',
    patterns: [
      /\beval\s*\(\s*(?!['"`])/g,
      /new\s+Function\s*\(\s*(?!['"`])/g,
      /setTimeout\s*\(\s*['"`][^'"`]*['"`]\s*[,)]/g,
      /setInterval\s*\(\s*['"`][^'"`]*['"`]\s*[,)]/g,
    ],
    fileTypes: JS_TS_FILES,
    fix: 'Avoid eval(). Use JSON.parse() for JSON, or safer alternatives',
    references: ['https://cwe.mitre.org/data/definitions/95.html'],
  },
  {
    id: 'path-traversal',
    name: 'Path Traversal',
    description: 'File path constructed with user input - may allow directory traversal',
    severity: 'high',
    category: 'Path Traversal',
    patterns: [
      /(?:readFile|writeFile|createReadStream|createWriteStream|unlink|rmdir|mkdir)\s*\(\s*(?:`[^`]*\$\{|['"`].*['"`]\s*\+)/g,
      /path\.(?:join|resolve)\s*\([^)]*(?:req\.|params\.|query\.|body\.)/g,
      /fs\..*\(\s*.*(?:req\.|params\.|query\.|body\.)/g,
    ],
    fileTypes: JS_TS_FILES,
    fix: 'Validate and sanitize file paths. Use path.basename() and whitelist allowed directories',
    references: ['https://owasp.org/Top10/A01_2021-Broken_Access_Control/'],
  },
  {
    id: 'nosql-injection',
    name: 'NoSQL Injection',
    description: 'MongoDB/NoSQL query with user input may be vulnerable to injection',
    severity: 'high',
    category: 'Injection',
    patterns: [
      /\.\s*find\s*\(\s*\{[^}]*:\s*(?:req\.|params\.|query\.|body\.)/g,
      /\.\s*findOne\s*\(\s*\{[^}]*:\s*(?:req\.|params\.|query\.|body\.)/g,
      /\$where\s*:/g,
      /\.\s*aggregate\s*\(\s*\[[^\]]*\$(?:match|lookup)[^\]]*(?:req\.|params\.)/g,
    ],
    fileTypes: JS_TS_FILES,
    fix: 'Sanitize input, use mongoose schema validation, avoid $where operator',
    references: ['https://owasp.org/Top10/A03_2021-Injection/'],
  },
  {
    id: 'jwt-none-algorithm',
    name: 'JWT None Algorithm Attack',
    description: 'JWT verification may accept "none" algorithm',
    severity: 'high',
    category: 'Authentication',
    patterns: [
      /algorithms\s*:\s*\[[^\]]*['"`]none['"`]/gi,
      /jwt\.verify\s*\([^)]*\{\s*algorithms\s*:\s*\[/g,
    ],
    fileTypes: JS_TS_FILES,
    fix: 'Always specify allowed algorithms explicitly: { algorithms: ["HS256"] }',
    references: ['https://cwe.mitre.org/data/definitions/327.html'],
  },
  {
    id: 'ssrf-fetch',
    name: 'Server-Side Request Forgery (SSRF)',
    description: 'HTTP request URL constructed from user input',
    severity: 'high',
    category: 'SSRF',
    patterns: [
      // fetch() with user-controlled URL from request objects
      /fetch\s*\(\s*['"`].*['"`]\s*\+\s*(?:req\.|request\.)/g,
      /fetch\s*\(\s*`[^`]*\$\{(?:[^}]*(?:req\.|request\.|body\.|userInput|user_input))[^}]*\}/g,
      // fetch() with a variable URL (not template literal, not string)
      /fetch\s*\(\s*(?:req\.|request\.)(?:body|query|params)\./g,
      /axios\.(?:get|post|put|delete)\s*\(\s*(?:`[^`]*\$\{|.*\+\s*)(?:req\.|request\.)/g,
      /http\.(?:get|request)\s*\(\s*(?:req\.|request\.)(?:body|query|params)\./g,
    ],
    fileTypes: JS_TS_FILES,
    fix: 'Validate and whitelist allowed URLs/domains. Never pass user input directly to HTTP clients',
    references: ['https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/'],
  },

  // ==========================================
  // MEDIUM - Should fix, but not critical
  // ==========================================
  {
    id: 'weak-crypto-md5',
    name: 'Weak Cryptography (MD5)',
    description: 'MD5 is cryptographically broken, do not use for security',
    severity: 'medium',
    category: 'Cryptography',
    patterns: [
      /createHash\s*\(\s*['"`]md5['"`]\s*\)/gi,
      /hashlib\.md5\s*\(/gi,
      /MD5\s*\(/g,
      /\.md5\s*\(/gi,
    ],
    fileTypes: [...JS_TS_FILES, ...PYTHON_FILES],
    fix: 'Use SHA-256 or better. For passwords, use bcrypt or argon2',
    references: ['https://cwe.mitre.org/data/definitions/328.html'],
  },
  {
    id: 'weak-crypto-sha1',
    name: 'Weak Cryptography (SHA1)',
    description: 'SHA1 is deprecated for security purposes',
    severity: 'medium',
    category: 'Cryptography',
    patterns: [
      /createHash\s*\(\s*['"`]sha1['"`]\s*\)/gi,
      /hashlib\.sha1\s*\(/gi,
    ],
    fileTypes: [...JS_TS_FILES, ...PYTHON_FILES],
    fix: 'Use SHA-256 or SHA-3. For passwords, use bcrypt or argon2',
    references: ['https://cwe.mitre.org/data/definitions/328.html'],
  },
  {
    id: 'insecure-cookie',
    name: 'Insecure Cookie',
    description: 'Cookie missing security flags (httpOnly, secure, sameSite)',
    severity: 'medium',
    category: 'Session',
    patterns: [
      /res\.cookie\s*\([^)]*\)\s*(?!.*httpOnly)/g,
      /document\.cookie\s*=\s*[`'"](?:session|auth|token|jwt|sid|csrf)/gi,
      /setCookie\s*\([^)]*(?!.*(?:httpOnly|secure|sameSite))/gi,
    ],
    fileTypes: JS_TS_FILES,
    fix: 'Set cookies with: { httpOnly: true, secure: true, sameSite: "strict" }',
    references: ['https://owasp.org/Top10/A05_2021-Security_Misconfiguration/'],
  },
  {
    id: 'cors-wildcard',
    name: 'CORS Wildcard Origin',
    description: 'CORS configured to allow any origin',
    severity: 'medium',
    category: 'Misconfiguration',
    patterns: [
      /Access-Control-Allow-Origin['"`:]\s*['"`]\*['"`]/gi,
      /cors\s*\(\s*\{\s*origin\s*:\s*(?:true|['"`]\*['"`])/gi,
      /\.use\s*\(\s*cors\s*\(\s*\)\s*\)/g,
    ],
    fileTypes: JS_TS_FILES,
    fix: 'Specify allowed origins explicitly: cors({ origin: "https://yourdomain.com" })',
    references: ['https://owasp.org/Top10/A05_2021-Security_Misconfiguration/'],
  },
  {
    id: 'missing-rate-limit',
    name: 'Missing Rate Limiting',
    description: 'Authentication endpoint without rate limiting',
    severity: 'medium',
    category: 'Brute Force',
    patterns: [
      /(?:app|router)\.post\s*\(\s*['"`]\/(?:login|signin|auth|register|signup|password|reset)['"`]/gi,
    ],
    fileTypes: JS_TS_FILES,
    fix: 'Add rate limiting with express-rate-limit or similar middleware',
    references: ['https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/'],
  },
  {
    id: 'console-log-sensitive',
    name: 'Sensitive Data in Console.log',
    description: 'Logging potentially sensitive information',
    severity: 'medium',
    category: 'Information Disclosure',
    patterns: [
      // Only flag when sensitive variable is passed as argument (after comma or as sole arg)
      // Avoids matching keywords inside descriptive strings
      /console\.log\s*\([^)]*,\s*\b(?:password|secret|token|credential|ssn|creditCard)\b/gi,
      /console\.log\s*\(\s*\b(?:password|secret|token|credential|ssn|creditCard)\b/gi,
      /console\.(?:log|info|debug)\s*\([^)]*(?:req\.body|req\.headers)/gi,
    ],
    fileTypes: JS_TS_FILES,
    fix: 'Remove sensitive data from logs. Use structured logging with redaction',
    references: ['https://cwe.mitre.org/data/definitions/532.html'],
  },
  {
    id: 'unvalidated-redirect',
    name: 'Unvalidated Redirect',
    description: 'Redirect URL from user input without validation',
    severity: 'medium',
    category: 'Redirect',
    patterns: [
      /res\.redirect\s*\(\s*(?:req\.|params\.|query\.|body\.)/g,
      /window\.location\s*=\s*(?!\s*['"`])/g,
      /location\.href\s*=\s*(?!\s*['"`])/g,
    ],
    fileTypes: JS_TS_FILES,
    fix: 'Validate redirect URLs against a whitelist of allowed destinations',
    references: ['https://cwe.mitre.org/data/definitions/601.html'],
  },
  {
    id: 'missing-csrf',
    name: 'Missing CSRF Protection',
    description: 'Form submission without CSRF token',
    severity: 'medium',
    category: 'CSRF',
    patterns: [
      /<form[^>]*method\s*=\s*['"`]post['"`][^>]*>(?:(?!csrf|_token|authenticity_token).)*<\/form>/gis,
    ],
    fileTypes: ['.html', '.jsx', '.tsx', '.vue', '.svelte'],
    fix: 'Add CSRF token to forms. Use csurf middleware or framework CSRF protection',
    references: ['https://owasp.org/Top10/A05_2021-Security_Misconfiguration/'],
  },
  {
    id: 'timing-attack',
    name: 'Timing Attack Vulnerable Comparison',
    description: 'String comparison that may leak timing information',
    severity: 'medium',
    category: 'Cryptography',
    patterns: [
      // Direct comparison of secret/token/hash variable with another variable (not string literal or UI pattern)
      // Matches: storedToken === providedToken, hash === userHash
      // Excludes: password === confirmPassword, secret.name, typeof, string literals, config checks
      /(?<!confirm|cached|\.|new\s)\b(?:token|hash|digest)\b\s*(?:===|!==|==|!=)\s*(?!undefined|null|true|false|['"`])\b(?!confirm|\.name|\.length)/gi,
      /(?:===|!==|==|!=)\s*(?!confirm|cached)\b(?:token|hash|digest)\b(?!\w|\.name|\.length)/gi,
    ],
    // Only server-side files - exclude .tsx/.jsx (React components)
    fileTypes: ['.js', '.ts', '.mjs', '.cjs'],
    fix: 'Use crypto.timingSafeEqual() for comparing secrets',
    references: ['https://cwe.mitre.org/data/definitions/208.html'],
  },

  // ==========================================
  // LOW - Best practice, fix when possible
  // ==========================================
  {
    id: 'debug-mode',
    name: 'Debug Mode Enabled',
    description: 'Debug mode may expose sensitive information in production',
    severity: 'low',
    category: 'Misconfiguration',
    patterns: [
      // Explicit debug flags set to true (not NODE_ENV checks which are standard practice)
      /\bDEBUG\s*[=:]\s*(?:true|1|['"`]true['"`])/gi,
      /app\.debug\s*=\s*True/gi,
    ],
    fileTypes: [...ALL_CODE_FILES, ...CONFIG_FILES],
    fix: 'Ensure debug mode is disabled in production',
    references: ['https://owasp.org/Top10/A05_2021-Security_Misconfiguration/'],
  },
  {
    id: 'todo-security',
    name: 'Security TODO/FIXME',
    description: 'Unresolved security-related TODO or FIXME',
    severity: 'low',
    category: 'Code Quality',
    patterns: [
      /(?:TODO|FIXME|HACK|XXX).*(?:security|auth|password|token|secret|vulnerable|inject|xss|csrf|sql)/gi,
    ],
    fileTypes: ALL_CODE_FILES,
    fix: 'Address security-related TODOs before deployment',
    references: [],
  },
  {
    id: 'http-without-tls',
    name: 'HTTP URL (No TLS)',
    description: 'Using HTTP instead of HTTPS for API or resource URL',
    severity: 'low',
    category: 'Transport Security',
    patterns: [
      // Exclude localhost, loopback, XML/SVG namespaces, schema.org
      /['"`]http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0|www\.w3\.org|schema\.org|schemas\.)[^'"`]+['"`]/g,
    ],
    fileTypes: ALL_CODE_FILES,
    fix: 'Use HTTPS for all external URLs',
    references: ['https://owasp.org/Top10/A02_2021-Cryptographic_Failures/'],
  },
  {
    id: 'weak-random',
    name: 'Weak Randomness',
    description: 'Math.random() is not cryptographically secure',
    severity: 'low',
    category: 'Cryptography',
    patterns: [
      /Math\.random\s*\(\s*\).*(?:token|secret|password|key|session|id|uuid)/gi,
      /(?:token|secret|password|key|session).*Math\.random\s*\(\s*\)/gi,
    ],
    fileTypes: JS_TS_FILES,
    fix: 'Use crypto.randomBytes() or crypto.randomUUID() for security-sensitive randomness',
    references: ['https://cwe.mitre.org/data/definitions/338.html'],
  },
  {
    id: 'commented-credentials',
    name: 'Commented Credentials',
    description: 'Credentials in comments may be exposed',
    severity: 'low',
    category: 'Secrets',
    patterns: [
      /(?:\/\/|#|\/\*)\s*(?:password|secret|token|api_key|apikey)\s*[=:]/gi,
    ],
    fileTypes: ALL_CODE_FILES,
    fix: 'Remove credentials from comments',
    references: ['https://cwe.mitre.org/data/definitions/615.html'],
  },
  {
    id: 'error-disclosure',
    name: 'Error Message Disclosure',
    description: 'Exposing detailed error messages to users',
    severity: 'low',
    category: 'Information Disclosure',
    patterns: [
      /res\.(?:send|json)\s*\(\s*(?:err|error)(?:\.message|\.stack)?/gi,
      /catch\s*\([^)]*\)\s*\{[^}]*res\.send\s*\([^)]*(?:err|error)/gi,
    ],
    fileTypes: JS_TS_FILES,
    fix: 'Return generic error messages to users. Log detailed errors server-side',
    references: ['https://cwe.mitre.org/data/definitions/209.html'],
  },
];

// Get rules by severity
export function getRulesBySeverity(severity: string): SecurityRule[] {
  return SECURITY_RULES.filter(r => r.severity === severity);
}

// Get rules by category
export function getRulesByCategory(category: string): SecurityRule[] {
  return SECURITY_RULES.filter(r => r.category === category);
}

// Get all categories
export function getCategories(): string[] {
  return [...new Set(SECURITY_RULES.map(r => r.category))];
}
