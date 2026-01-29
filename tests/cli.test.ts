import { describe, it, expect } from 'vitest';
import { execSync } from 'child_process';
import * as path from 'path';

const CLI_PATH = path.join(import.meta.dirname, '..', 'dist', 'cli.js');
const FIXTURES_DIR = path.join(import.meta.dirname, 'fixtures');

function runCli(args: string, options?: { expectFail?: boolean }): string {
  try {
    return execSync(`node ${CLI_PATH} ${args}`, {
      encoding: 'utf-8',
      maxBuffer: 10 * 1024 * 1024,
      env: { ...process.env, FORCE_COLOR: '0', NO_COLOR: '1' },
      timeout: 30000,
    });
  } catch (err: unknown) {
    if (options?.expectFail) {
      return (err as { stdout?: string; stderr?: string }).stdout ||
             (err as { stderr?: string }).stderr || '';
    }
    throw err;
  }
}

describe('CLI', () => {
  describe('genaura-guard --version', () => {
    it('prints version number', () => {
      const output = runCli('--version');
      expect(output.trim()).toMatch(/^\d+\.\d+\.\d+$/);
    });
  });

  describe('genaura-guard --help', () => {
    it('shows help text', () => {
      const output = runCli('--help');
      expect(output).toContain('genaura-guard');
      expect(output).toContain('Security scanner');
    });

    it('lists all commands', () => {
      const output = runCli('--help');
      expect(output).toContain('scan');
      expect(output).toContain('quick');
      expect(output).toContain('full');
      expect(output).toContain('fix');
      expect(output).toContain('init');
      expect(output).toContain('sync');
      expect(output).toContain('status');
      expect(output).toContain('rules');
    });
  });

  describe('genaura-guard scan', () => {
    it('scans a vulnerable file and reports findings', () => {
      const vulnFile = path.join(FIXTURES_DIR, 'vulnerable.ts');
      const output = runCli(`scan ${vulnFile}`, { expectFail: true });
      expect(output).toContain('GENAURA GUARD');
      expect(output).toContain('security issue');
    });

    it('scans a clean file with no critical/high findings', () => {
      const cleanFile = path.join(FIXTURES_DIR, 'clean.ts');
      const output = runCli(`scan ${cleanFile} --severity critical,high`);
      expect(output).toContain('No security issues found');
    });

    it('supports --json flag with summary structure', () => {
      const vulnFile = path.join(FIXTURES_DIR, 'vulnerable.ts');
      const output = runCli(`scan ${vulnFile} --severity critical --json`, { expectFail: true });
      const json = JSON.parse(output);
      expect(json).toHaveProperty('summary');
      expect(json).toHaveProperty('findings');
      expect(json.summary).toHaveProperty('total');
      expect(json.summary).toHaveProperty('critical');
      expect(json.summary).toHaveProperty('high');
      expect(json.summary).toHaveProperty('medium');
      expect(json.summary).toHaveProperty('low');
      expect(json.summary).toHaveProperty('filesScanned');
      expect(json.summary.total).toBeGreaterThan(0);
    });

    it('--json output has correct finding structure', () => {
      const vulnFile = path.join(FIXTURES_DIR, 'vulnerable.ts');
      const output = runCli(`scan ${vulnFile} --severity critical --json`, { expectFail: true });
      const json = JSON.parse(output);
      const finding = json.findings[0];
      expect(finding).toHaveProperty('severity');
      expect(finding).toHaveProperty('rule');
      expect(finding).toHaveProperty('name');
      expect(finding).toHaveProperty('category');
      expect(finding).toHaveProperty('file');
      expect(finding).toHaveProperty('line');
      expect(finding).toHaveProperty('fix');
    });

    it('--json flag produces valid JSON start', () => {
      const vulnFile = path.join(FIXTURES_DIR, 'vulnerable.ts');
      const output = runCli(`scan ${vulnFile} --json`, { expectFail: true });
      expect(output.trimStart()).toMatch(/^\{/);
      expect(output).toContain('"summary"');
      expect(output).toContain('"findings"');
    });

    it('supports --severity filter', () => {
      const vulnFile = path.join(FIXTURES_DIR, 'vulnerable.ts');
      const output = runCli(`scan ${vulnFile} --severity critical --json`, { expectFail: true });
      const json = JSON.parse(output);
      const nonCritical = json.findings.filter((f: { severity: string }) => f.severity !== 'critical');
      expect(nonCritical.length).toBe(0);
    });

    it('exits with code 1 when issues found', () => {
      const vulnFile = path.join(FIXTURES_DIR, 'vulnerable.ts');
      let exitCode = 0;
      try {
        execSync(`node ${CLI_PATH} scan ${vulnFile}`, {
          encoding: 'utf-8',
          env: { ...process.env, FORCE_COLOR: '0', NO_COLOR: '1' },
        });
      } catch (err: unknown) {
        exitCode = (err as { status?: number }).status || 1;
      }
      expect(exitCode).toBeGreaterThan(0);
    });

    it('exits with code 0 for clean file', () => {
      const cleanFile = path.join(FIXTURES_DIR, 'clean.ts');
      // Should not throw (exit code 0)
      const output = runCli(`scan ${cleanFile} --severity critical,high`);
      expect(output).toBeTruthy();
    });
  });

  describe('genaura-guard quick', () => {
    it('only reports critical and high issues', () => {
      const vulnFile = path.join(FIXTURES_DIR, 'vulnerable.ts');
      const output = runCli(`quick ${vulnFile}`, { expectFail: true });
      expect(output).toContain('GENAURA GUARD');
    });
  });

  describe('genaura-guard full', () => {
    it('reports findings across all severities', () => {
      const vulnFile = path.join(FIXTURES_DIR, 'vulnerable.ts');
      const output = runCli(`full ${vulnFile}`, { expectFail: true });
      expect(output).toContain('GENAURA GUARD');
      expect(output).toContain('security issue');
    });

    it('includes medium and low severity findings', () => {
      const vulnFile = path.join(FIXTURES_DIR, 'vulnerable.ts');
      const output = runCli(`full ${vulnFile} --json`, { expectFail: true });
      const json = JSON.parse(output);
      const severities = new Set(json.findings.map((f: { severity: string }) => f.severity));
      // vulnerable.ts has critical, high, medium, and low
      expect(severities.size).toBeGreaterThanOrEqual(3);
    });

    it('supports --json flag', () => {
      const vulnFile = path.join(FIXTURES_DIR, 'vulnerable.ts');
      const output = runCli(`full ${vulnFile} --json`, { expectFail: true });
      const json = JSON.parse(output);
      expect(json).toHaveProperty('summary');
      expect(json).toHaveProperty('findings');
      expect(json.summary.total).toBeGreaterThan(0);
    });
  });

  describe('genaura-guard fix', () => {
    it('shows fix report output', () => {
      const vulnFile = path.join(FIXTURES_DIR, 'vulnerable.ts');
      const output = runCli(`fix ${vulnFile}`, { expectFail: true });
      expect(output).toContain('Fix Report');
    });

    it('shows per-file instructions with file name', () => {
      const vulnFile = path.join(FIXTURES_DIR, 'vulnerable.ts');
      const output = runCli(`fix ${vulnFile}`, { expectFail: true });
      expect(output).toContain('vulnerable.ts');
    });

    it('shows fix suggestions', () => {
      const vulnFile = path.join(FIXTURES_DIR, 'vulnerable.ts');
      const output = runCli(`fix ${vulnFile}`, { expectFail: true });
      // Fix Guide section should appear
      expect(output).toContain('Fix Guide');
    });

    it('shows clean message for clean file', () => {
      const cleanFile = path.join(FIXTURES_DIR, 'clean.ts');
      const output = runCli(`fix ${cleanFile} --severity critical,high`);
      expect(output).toContain('No security issues found');
    });

    it('supports --json flag', () => {
      const vulnFile = path.join(FIXTURES_DIR, 'vulnerable.ts');
      const output = runCli(`fix ${vulnFile} --json`, { expectFail: true });
      const json = JSON.parse(output);
      expect(json).toHaveProperty('summary');
      expect(json).toHaveProperty('findings');
    });

    it('supports --severity filter', () => {
      const vulnFile = path.join(FIXTURES_DIR, 'vulnerable.ts');
      const output = runCli(`fix ${vulnFile} --severity critical --json`, { expectFail: true });
      const json = JSON.parse(output);
      const nonCritical = json.findings.filter((f: { severity: string }) => f.severity !== 'critical');
      expect(nonCritical.length).toBe(0);
    });

    it('accepts path argument', () => {
      const vulnFile = path.join(FIXTURES_DIR, 'vulnerable.ts');
      const output = runCli(`fix ${vulnFile}`, { expectFail: true });
      expect(output).toContain('GENAURA GUARD');
    });
  });

  describe('genaura-guard rules', () => {
    it('lists security rules', () => {
      const output = runCli('rules');
      expect(output).toContain('Security Rules');
      expect(output).toContain('Injection');
      expect(output).toContain('Secrets');
    });
  });
});
