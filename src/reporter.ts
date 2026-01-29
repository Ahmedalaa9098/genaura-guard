import chalk from 'chalk';
import * as path from 'path';
import { Finding, ScanResult, Severity, SEVERITY_COLORS, SEVERITY_ICONS, SEVERITY_ORDER } from './types.js';

export function printBanner(): void {
  console.log();
  console.log(chalk.hex('#1e3a5f')('╔═══════════════════════════════════════╗'));
  console.log(chalk.hex('#1e3a5f')('║') + chalk.white.bold('  🛡️  GENAURA GUARD                    ') + chalk.hex('#1e3a5f')('║'));
  console.log(chalk.hex('#1e3a5f')('║') + chalk.gray('  Security scanner for vibe coders     ') + chalk.hex('#1e3a5f')('║'));
  console.log(chalk.hex('#1e3a5f')('╚═══════════════════════════════════════╝'));
  console.log();
}

export function printResults(result: ScanResult, cwd: string): void {
  const { findings, filesScanned, duration } = result;
  
  if (findings.length === 0) {
    console.log(chalk.green('✓ No security issues found!'));
    console.log(chalk.gray(`  Scanned ${filesScanned} files in ${duration}ms`));
    console.log();
    return;
  }
  
  // Group by severity
  const bySeverity = groupBySeverity(findings);
  
  // Print summary
  printSummary(bySeverity, filesScanned, duration);
  
  console.log();
  console.log(chalk.white.bold('  Findings'));
  console.log(chalk.gray('  ' + '─'.repeat(50)));
  
  // Print findings by severity
  for (const severity of ['critical', 'high', 'medium', 'low'] as Severity[]) {
    const severityFindings = bySeverity[severity] || [];
    if (severityFindings.length > 0) {
      printSeverityFindings(severity, severityFindings, cwd);
    }
  }
  
  // Print fix guide for all findings
  printFixGuide(findings);
}

function groupBySeverity(findings: Finding[]): Record<Severity, Finding[]> {
  return findings.reduce((acc, finding) => {
    const severity = finding.rule.severity;
    if (!acc[severity]) acc[severity] = [];
    acc[severity].push(finding);
    return acc;
  }, {} as Record<Severity, Finding[]>);
}

function printSummary(
  bySeverity: Record<Severity, Finding[]>,
  filesScanned: number,
  duration: number
): void {
  const critical = bySeverity.critical?.length || 0;
  const high = bySeverity.high?.length || 0;
  const medium = bySeverity.medium?.length || 0;
  const low = bySeverity.low?.length || 0;
  const total = critical + high + medium + low;
  
  console.log(chalk.white.bold(`  Found ${total} security issue${total === 1 ? '' : 's'}`));
  console.log(chalk.gray('  ' + '─'.repeat(50)));
  
  const parts: string[] = [];
  if (critical > 0) parts.push(chalk.magenta(`💀 ${critical} critical`));
  if (high > 0) parts.push(chalk.red(`✗ ${high} high`));
  if (medium > 0) parts.push(chalk.yellow(`⚠ ${medium} medium`));
  if (low > 0) parts.push(chalk.blue(`○ ${low} low`));
  
  console.log('  ' + parts.join('  '));
  console.log(chalk.gray(`  Scanned ${filesScanned} files in ${duration}ms`));
}

function printSeverityFindings(severity: Severity, findings: Finding[], cwd: string): void {
  const icon = SEVERITY_ICONS[severity];
  const colorFn = getSeverityColor(severity);
  
  console.log();
  
  for (const finding of findings) {
    const relativePath = path.relative(cwd, finding.file);
    const location = `${relativePath}:${finding.line}`;
    
    // Severity and rule name
    console.log(
      colorFn(`  ${icon} ${severity.toUpperCase()}`) +
      chalk.white(` ${finding.rule.name}`)
    );
    
    // Location
    console.log(chalk.gray(`    ${location}`));
    
    // Context (the code line)
    if (finding.context) {
      const truncatedContext = finding.context.length > 80 
        ? finding.context.substring(0, 77) + '...'
        : finding.context;
      console.log(chalk.dim(`    ${truncatedContext}`));
    }
    
    // Fix suggestion
    if (finding.rule.fix) {
      console.log(chalk.cyan(`    → ${finding.rule.fix}`));
    }
    
    console.log();
  }
}

function getSeverityColor(severity: Severity): (text: string) => string {
  switch (severity) {
    case 'critical': return chalk.magenta;
    case 'high': return chalk.red;
    case 'medium': return chalk.yellow;
    case 'low': return chalk.blue;
    default: return chalk.white;
  }
}

export function printJsonResults(result: ScanResult): void {
  const output = {
    summary: {
      total: result.findings.length,
      critical: result.findings.filter(f => f.rule.severity === 'critical').length,
      high: result.findings.filter(f => f.rule.severity === 'high').length,
      medium: result.findings.filter(f => f.rule.severity === 'medium').length,
      low: result.findings.filter(f => f.rule.severity === 'low').length,
      filesScanned: result.filesScanned,
      duration: result.duration,
    },
    findings: result.findings.map(f => ({
      severity: f.rule.severity,
      rule: f.rule.id,
      name: f.rule.name,
      category: f.rule.category,
      file: f.file,
      line: f.line,
      column: f.column,
      match: f.match,
      context: f.context,
      fix: f.rule.fix,
      references: f.rule.references,
    })),
  };
  
  console.log(JSON.stringify(output, null, 2));
}

export function printHookWarning(result: ScanResult): void {
  const critical = result.findings.filter(f => f.rule.severity === 'critical').length;
  const high = result.findings.filter(f => f.rule.severity === 'high').length;

  console.log();
  console.log(chalk.hex('#1e3a5f')('─'.repeat(55)));
  console.log(chalk.white.bold(' 🛡️  Genaura Guard found security issues:'));
  console.log();

  if (critical > 0) {
    console.log(chalk.magenta(`    💀 ${critical} critical issue${critical > 1 ? 's' : ''}`));
  }
  if (high > 0) {
    console.log(chalk.red(`    ✗ ${high} high severity issue${high > 1 ? 's' : ''}`));
  }

  // Show top 5 findings with file:line and fix
  const top5 = result.findings.slice(0, 5);
  if (top5.length > 0) {
    console.log();
    for (const finding of top5) {
      const icon = SEVERITY_ICONS[finding.rule.severity];
      const colorFn = getSeverityColor(finding.rule.severity);
      const basename = path.basename(finding.file);
      console.log(
        colorFn(`    ${icon} `) +
        chalk.white(`${basename}:${finding.line}`) +
        chalk.gray(` ${finding.rule.name}`)
      );
      if (finding.rule.fix) {
        console.log(chalk.cyan(`      → ${finding.rule.fix}`));
      }
    }
    if (result.findings.length > 5) {
      console.log(chalk.gray(`    ... and ${result.findings.length - 5} more`));
    }
  }

  console.log();
  console.log(chalk.white(' Run ') + chalk.cyan('genaura-guard scan') + chalk.white(' for full details.'));
  console.log(chalk.white(' Run ') + chalk.cyan('genaura-guard fix') + chalk.white(' for fix guidance.'));
  console.log(chalk.hex('#1e3a5f')('─'.repeat(55)));
  console.log();
}

export function printFixGuide(findings: Finding[]): void {
  if (findings.length === 0) return;

  // Group findings by rule ID to deduplicate fix suggestions
  const byRule = new Map<string, { rule: Finding['rule']; files: Set<string>; count: number }>();

  for (const finding of findings) {
    const existing = byRule.get(finding.rule.id);
    if (existing) {
      existing.files.add(finding.file);
      existing.count++;
    } else {
      byRule.set(finding.rule.id, {
        rule: finding.rule,
        files: new Set([finding.file]),
        count: 1,
      });
    }
  }

  // Sort by severity then count
  const sorted = [...byRule.values()].sort((a, b) => {
    const sevDiff = SEVERITY_ORDER[a.rule.severity] - SEVERITY_ORDER[b.rule.severity];
    if (sevDiff !== 0) return sevDiff;
    return b.count - a.count;
  });

  console.log();
  console.log(chalk.yellow.bold('  ⚠️  Fix Guide'));
  console.log(chalk.gray('  ' + '─'.repeat(50)));

  for (const entry of sorted) {
    const icon = SEVERITY_ICONS[entry.rule.severity];
    const colorFn = getSeverityColor(entry.rule.severity);
    const fileCount = entry.files.size;

    console.log(
      colorFn(`  ${icon} ${entry.rule.name}`) +
      chalk.gray(` (${entry.count} instance${entry.count > 1 ? 's' : ''} in ${fileCount} file${fileCount > 1 ? 's' : ''})`)
    );

    if (entry.rule.fix) {
      console.log(chalk.cyan(`    Fix: ${entry.rule.fix}`));
    }

    if (entry.rule.references?.length) {
      console.log(chalk.gray(`    Ref: ${entry.rule.references[0]}`));
    }
  }

  console.log();
}

export function printFixReport(result: ScanResult, cwd: string): void {
  const { findings, filesScanned, duration } = result;

  if (findings.length === 0) {
    console.log(chalk.green('✓ No security issues found!'));
    console.log(chalk.gray(`  Scanned ${filesScanned} files in ${duration}ms`));
    console.log();
    return;
  }

  // Print summary header
  const bySeverity = groupBySeverity(findings);
  printSummary(bySeverity, filesScanned, duration);

  // Group findings by file
  const byFile = new Map<string, Finding[]>();
  for (const finding of findings) {
    const existing = byFile.get(finding.file);
    if (existing) {
      existing.push(finding);
    } else {
      byFile.set(finding.file, [finding]);
    }
  }

  console.log();
  console.log(chalk.white.bold('  Fix Report'));
  console.log(chalk.gray('  ' + '─'.repeat(50)));

  for (const [file, fileFindings] of byFile) {
    const relativePath = path.relative(cwd, file) || path.basename(file);

    // Sort by line number
    fileFindings.sort((a, b) => a.line - b.line);

    console.log();
    console.log(chalk.white.bold(`  📄 ${relativePath}`) + chalk.gray(` (${fileFindings.length} issue${fileFindings.length > 1 ? 's' : ''})`));

    for (const finding of fileFindings) {
      const icon = SEVERITY_ICONS[finding.rule.severity];
      const colorFn = getSeverityColor(finding.rule.severity);

      console.log(
        chalk.gray(`    L${finding.line} `) +
        colorFn(`${icon} ${finding.rule.name}`)
      );

      // Show problematic code in red
      if (finding.context) {
        const truncated = finding.context.length > 80
          ? finding.context.substring(0, 77) + '...'
          : finding.context;
        console.log(chalk.red(`      - ${truncated}`));
      }

      // Show fix suggestion in green
      if (finding.rule.fix) {
        console.log(chalk.green(`      + ${finding.rule.fix}`));
      }
    }
  }

  // Append the fix guide summary
  printFixGuide(findings);
}

export function printRules(): void {
  // Import dynamically to avoid circular dependency
  import('./rules.js').then(({ SECURITY_RULES }) => {
    console.log();
    console.log(chalk.white.bold('  Security Rules'));
    console.log(chalk.gray('  ' + '─'.repeat(50)));
    console.log();
    
    const categories = [...new Set(SECURITY_RULES.map(r => r.category))];
    
    for (const category of categories) {
      console.log(chalk.white.bold(`  ${category}`));
      
      const categoryRules = SECURITY_RULES.filter(r => r.category === category);
      for (const rule of categoryRules) {
        const colorFn = getSeverityColor(rule.severity);
        const icon = SEVERITY_ICONS[rule.severity as Severity];
        console.log(
          colorFn(`    ${icon} ${rule.severity.toUpperCase().padEnd(8)}`) +
          chalk.white(` ${rule.name}`)
        );
      }
      console.log();
    }
  });
}
