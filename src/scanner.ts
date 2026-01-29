import * as fs from 'fs';
import * as path from 'path';
import { glob } from 'glob';
import { Finding, ScanOptions, ScanResult, SecurityRule } from './types.js';
import { SECURITY_RULES } from './rules.js';

const DEFAULT_EXCLUDE = [
  '**/node_modules/**',
  '**/dist/**',
  '**/build/**',
  '**/.git/**',
  '**/vendor/**',
  '**/__pycache__/**',
  '**/venv/**',
  '**/.next/**',
  '**/.nuxt/**',
  '**/coverage/**',
  '**/*.min.js',
  '**/*.bundle.js',
  '**/package-lock.json',
  '**/yarn.lock',
  '**/pnpm-lock.yaml',
  // Test files - contain intentional mock secrets/patterns
  '**/__tests__/**',
  '**/__mocks__/**',
  '**/*.test.ts',
  '**/*.test.tsx',
  '**/*.test.js',
  '**/*.test.jsx',
  '**/*.spec.ts',
  '**/*.spec.tsx',
  '**/*.spec.js',
  '**/*.spec.jsx',
  '**/test/**',
  '**/tests/**',
];

const CODE_EXTENSIONS = [
  '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs',
  '.py', '.rb', '.php', '.go', '.java', '.cs',
  '.vue', '.svelte', '.astro',
  '.html', '.htm',
  '.json', '.yaml', '.yml', '.env', '.toml', '.ini',
];

export async function scan(options: ScanOptions): Promise<ScanResult> {
  const startTime = Date.now();
  const findings: Finding[] = [];
  
  const targetPath = path.resolve(options.path);
  
  // Check if path exists
  if (!fs.existsSync(targetPath)) {
    throw new Error(`Path does not exist: ${targetPath}`);
  }
  
  // Get all files to scan
  const files = await getFilesToScan(targetPath, options.exclude);
  
  // Scan each file
  for (const file of files) {
    const fileFindings = await scanFile(file, options);
    findings.push(...fileFindings);
  }
  
  // Sort by severity (critical first)
  findings.sort((a, b) => {
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
    return severityOrder[a.rule.severity] - severityOrder[b.rule.severity];
  });
  
  return {
    findings,
    filesScanned: files.length,
    duration: Date.now() - startTime,
  };
}

async function getFilesToScan(targetPath: string, customExclude?: string[]): Promise<string[]> {
  const stat = fs.statSync(targetPath);
  
  if (stat.isFile()) {
    return [targetPath];
  }
  
  const exclude = [...DEFAULT_EXCLUDE, ...(customExclude || [])];
  
  // Build glob pattern for code files
  const extensions = CODE_EXTENSIONS.map(ext => ext.slice(1)).join(',');
  const pattern = `**/*.{${extensions}}`;
  
  const files = await glob(pattern, {
    cwd: targetPath,
    absolute: true,
    ignore: exclude,
    nodir: true,
  });
  
  return files;
}

async function scanFile(filePath: string, options: ScanOptions): Promise<Finding[]> {
  const findings: Finding[] = [];
  
  try {
    const content = fs.readFileSync(filePath, 'utf-8');
    const lines = content.split('\n');
    const ext = path.extname(filePath).toLowerCase();
    
    // Get applicable rules for this file type
    const applicableRules = SECURITY_RULES.filter(rule => 
      rule.fileTypes.some(ft => ft === ext || ft === '.*')
    );
    
    // Filter by severity if specified
    const rulesToApply = options.severity 
      ? applicableRules.filter(r => options.severity!.includes(r.severity))
      : applicableRules;
    
    // Check each rule
    for (const rule of rulesToApply) {
      const ruleFindings = checkRule(rule, content, lines, filePath);
      findings.push(...ruleFindings);
    }
  } catch (err) {
    // Skip files we can't read (binary, permission issues, etc.)
    if (options.verbose) {
      console.error(`Warning: Could not scan ${filePath}: ${err}`);
    }
  }
  
  return findings;
}

function checkRule(
  rule: SecurityRule,
  content: string,
  lines: string[],
  filePath: string
): Finding[] {
  const findings: Finding[] = [];
  
  for (const pattern of rule.patterns) {
    // Reset regex lastIndex for global patterns
    pattern.lastIndex = 0;
    
    let match: RegExpExecArray | null;
    
    while ((match = pattern.exec(content)) !== null) {
      const position = getLineAndColumn(content, match.index);
      const contextLine = lines[position.line - 1] || '';
      
      // Avoid duplicate findings on same line for same rule
      const isDuplicate = findings.some(
        f => f.rule.id === rule.id && f.line === position.line && f.file === filePath
      );
      
      if (!isDuplicate) {
        findings.push({
          rule,
          file: filePath,
          line: position.line,
          column: position.column,
          match: match[0].substring(0, 100), // Truncate long matches
          context: contextLine.trim(),
        });
      }
      
      // Prevent infinite loop for patterns that match empty strings
      if (match[0].length === 0) {
        pattern.lastIndex++;
      }
    }
  }
  
  return findings;
}

function getLineAndColumn(content: string, index: number): { line: number; column: number } {
  const lines = content.substring(0, index).split('\n');
  return {
    line: lines.length,
    column: lines[lines.length - 1].length + 1,
  };
}

// Quick scan for pre-push hook - only critical and high
export async function quickScan(targetPath: string): Promise<ScanResult> {
  return scan({
    path: targetPath,
    severity: ['critical', 'high'],
  });
}

// Full scan with all severities
export async function fullScan(targetPath: string): Promise<ScanResult> {
  return scan({
    path: targetPath,
  });
}
