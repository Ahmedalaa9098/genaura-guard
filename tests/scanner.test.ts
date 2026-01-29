import { describe, it, expect } from 'vitest';
import * as path from 'path';
import { scan, quickScan, fullScan } from '../src/scanner.js';

const FIXTURES_DIR = path.join(import.meta.dirname, 'fixtures');

describe('Scanner', () => {
  describe('scan()', () => {
    it('finds vulnerabilities in a vulnerable file', async () => {
      const result = await scan({
        path: path.join(FIXTURES_DIR, 'vulnerable.ts'),
      });
      expect(result.findings.length).toBeGreaterThan(0);
      expect(result.filesScanned).toBe(1);
      expect(result.duration).toBeGreaterThanOrEqual(0);
    });

    it('finds critical issues in vulnerable file', async () => {
      const result = await scan({
        path: path.join(FIXTURES_DIR, 'vulnerable.ts'),
        severity: ['critical'],
      });
      const criticalFindings = result.findings.filter(f => f.rule.severity === 'critical');
      expect(criticalFindings.length).toBeGreaterThan(0);
      // Should find hardcoded API key and password
      const ruleIds = criticalFindings.map(f => f.rule.id);
      expect(ruleIds).toContain('hardcoded-secret-api-key');
      expect(ruleIds).toContain('hardcoded-password');
    });

    it('finds high severity issues', async () => {
      const result = await scan({
        path: path.join(FIXTURES_DIR, 'vulnerable.ts'),
        severity: ['high'],
      });
      const highFindings = result.findings.filter(f => f.rule.severity === 'high');
      expect(highFindings.length).toBeGreaterThan(0);
      const ruleIds = highFindings.map(f => f.rule.id);
      expect(ruleIds).toContain('xss-innerhtml');
      expect(ruleIds).toContain('command-injection');
      expect(ruleIds).toContain('eval-usage');
    });

    it('finds medium severity issues', async () => {
      const result = await scan({
        path: path.join(FIXTURES_DIR, 'vulnerable.ts'),
        severity: ['medium'],
      });
      const mediumFindings = result.findings.filter(f => f.rule.severity === 'medium');
      expect(mediumFindings.length).toBeGreaterThan(0);
      const ruleIds = mediumFindings.map(f => f.rule.id);
      expect(ruleIds).toContain('weak-crypto-md5');
    });

    it('finds low severity issues', async () => {
      const result = await scan({
        path: path.join(FIXTURES_DIR, 'vulnerable.ts'),
        severity: ['low'],
      });
      const lowFindings = result.findings.filter(f => f.rule.severity === 'low');
      expect(lowFindings.length).toBeGreaterThan(0);
    });

    it('reports no issues for clean file', async () => {
      const result = await scan({
        path: path.join(FIXTURES_DIR, 'clean.ts'),
      });
      // Clean file should have very few or no findings
      const criticalOrHigh = result.findings.filter(
        f => f.rule.severity === 'critical' || f.rule.severity === 'high'
      );
      expect(criticalOrHigh.length).toBe(0);
    });

    it('scans a directory recursively', async () => {
      const result = await scan({ path: FIXTURES_DIR });
      expect(result.filesScanned).toBeGreaterThanOrEqual(3);
      expect(result.findings.length).toBeGreaterThan(0);
    });

    it('detects Python vulnerabilities', async () => {
      const result = await scan({
        path: path.join(FIXTURES_DIR, 'vulnerable.py'),
      });
      expect(result.findings.length).toBeGreaterThan(0);
      const ruleIds = result.findings.map(f => f.rule.id);
      expect(ruleIds).toContain('hardcoded-password');
    });

    it('detects private keys in .env files', async () => {
      const result = await scan({
        path: path.join(FIXTURES_DIR, 'secrets.env'),
      });
      const privateKeyFindings = result.findings.filter(
        f => f.rule.id === 'private-key-exposed'
      );
      expect(privateKeyFindings.length).toBeGreaterThan(0);
    });

    it('throws on non-existent path', async () => {
      await expect(
        scan({ path: '/nonexistent/path/file.ts' })
      ).rejects.toThrow('Path does not exist');
    });

    it('respects severity filter', async () => {
      const result = await scan({
        path: path.join(FIXTURES_DIR, 'vulnerable.ts'),
        severity: ['critical'],
      });
      const nonCritical = result.findings.filter(f => f.rule.severity !== 'critical');
      expect(nonCritical.length).toBe(0);
    });

    it('findings are sorted by severity (critical first)', async () => {
      const result = await scan({ path: FIXTURES_DIR });
      const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
      for (let i = 1; i < result.findings.length; i++) {
        const prev = severityOrder[result.findings[i - 1].rule.severity];
        const curr = severityOrder[result.findings[i].rule.severity];
        expect(curr).toBeGreaterThanOrEqual(prev);
      }
    });

    it('findings include file path and line number', async () => {
      const result = await scan({
        path: path.join(FIXTURES_DIR, 'vulnerable.ts'),
      });
      for (const finding of result.findings) {
        expect(finding.file).toBeTruthy();
        expect(finding.line).toBeGreaterThan(0);
        expect(finding.column).toBeGreaterThan(0);
      }
    });

    it('findings include context (code line)', async () => {
      const result = await scan({
        path: path.join(FIXTURES_DIR, 'vulnerable.ts'),
      });
      const findingsWithContext = result.findings.filter(f => f.context.length > 0);
      expect(findingsWithContext.length).toBeGreaterThan(0);
    });
  });

  describe('quickScan()', () => {
    it('only returns critical and high findings', async () => {
      const result = await quickScan(path.join(FIXTURES_DIR, 'vulnerable.ts'));
      const invalidFindings = result.findings.filter(
        f => f.rule.severity !== 'critical' && f.rule.severity !== 'high'
      );
      expect(invalidFindings.length).toBe(0);
    });

    it('still finds critical issues', async () => {
      const result = await quickScan(path.join(FIXTURES_DIR, 'vulnerable.ts'));
      expect(result.findings.length).toBeGreaterThan(0);
    });
  });

  describe('fullScan()', () => {
    it('includes all severity levels', async () => {
      const result = await fullScan(FIXTURES_DIR);
      const severities = new Set(result.findings.map(f => f.rule.severity));
      expect(severities.size).toBeGreaterThanOrEqual(2);
    });
  });
});
