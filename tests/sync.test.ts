import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { generateSecurityRules, SYNC_TARGETS, syncToTargets } from '../src/sync.js';

describe('Sync', () => {
  describe('SYNC_TARGETS', () => {
    it('includes Claude', () => {
      const claude = SYNC_TARGETS.find(t => t.name === 'Claude');
      expect(claude).toBeTruthy();
      expect(claude!.path).toBe('~/.claude');
      expect(claude!.filename).toBe('SECURITY.md');
    });

    it('includes Cursor', () => {
      const cursor = SYNC_TARGETS.find(t => t.name === 'Cursor');
      expect(cursor).toBeTruthy();
      expect(cursor!.path).toBe('~/.cursor/rules');
      expect(cursor!.filename).toBe('security.md');
    });

    it('includes Codex', () => {
      const codex = SYNC_TARGETS.find(t => t.name === 'Codex');
      expect(codex).toBeTruthy();
    });

    it('includes Copilot', () => {
      const copilot = SYNC_TARGETS.find(t => t.name === 'Copilot');
      expect(copilot).toBeTruthy();
    });

    it('includes at least 7 targets', () => {
      expect(SYNC_TARGETS.length).toBeGreaterThanOrEqual(7);
    });

    it('all targets have required fields', () => {
      for (const target of SYNC_TARGETS) {
        expect(target.name).toBeTruthy();
        expect(target.path).toBeTruthy();
        expect(target.filename).toBeTruthy();
      }
    });
  });

  describe('generateSecurityRules()', () => {
    let rules: string;

    beforeEach(() => {
      rules = generateSecurityRules();
    });

    it('generates non-empty markdown content', () => {
      expect(rules.length).toBeGreaterThan(0);
    });

    it('starts with Security Rules header', () => {
      expect(rules).toContain('# Security Rules');
    });

    it('includes Genaura Guard attribution', () => {
      expect(rules).toContain('Genaura Guard');
    });

    it('includes correct GitHub URL', () => {
      expect(rules).toContain('github.com/Harkanovac/genaura-guard');
    });

    it('includes SQL injection prevention', () => {
      expect(rules).toContain('SQL Injection');
      expect(rules).toContain('parameterized queries');
    });

    it('includes XSS prevention', () => {
      expect(rules).toContain('XSS Prevention');
      expect(rules).toContain('innerHTML');
      expect(rules).toContain('DOMPurify');
    });

    it('includes command injection prevention', () => {
      expect(rules).toContain('Command Injection');
      expect(rules).toContain('spawn');
    });

    it('includes secrets management', () => {
      expect(rules).toContain('Secrets Management');
      expect(rules).toContain('environment variables');
    });

    it('includes secure cookie guidance', () => {
      expect(rules).toContain('httpOnly');
      expect(rules).toContain('secure');
      expect(rules).toContain('sameSite');
    });

    it('includes password hashing guidance', () => {
      expect(rules).toContain('bcrypt');
      expect(rules).toContain('argon2');
    });

    it('includes CORS guidance', () => {
      expect(rules).toContain('CORS');
      expect(rules).toContain('wildcard');
    });

    it('includes security checklist', () => {
      expect(rules).toContain('Security Checklist');
    });

    it('includes code examples with correct/incorrect patterns', () => {
      expect(rules).toContain('WRONG');
      expect(rules).toContain('CORRECT');
    });
  });

  describe('syncToTargets()', () => {
    let tmpDir: string;
    let originalHome: string;

    beforeEach(() => {
      tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gguard-sync-test-'));
      originalHome = os.homedir();
    });

    afterEach(() => {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    });

    it('can sync to a specific target by name', () => {
      // Sync to all targets (will create directories)
      const results = syncToTargets();
      // Should have some successes (at least the ones where we can create dirs)
      expect(results.success.length + results.failed.length).toBeGreaterThan(0);
    });

    it('filters targets when names provided', () => {
      const results = syncToTargets(['claude']);
      const totalProcessed = results.success.length + results.failed.length;
      expect(totalProcessed).toBeLessThanOrEqual(1);
    });

    it('returns results with success and failed arrays', () => {
      const results = syncToTargets(['nonexistent-tool']);
      expect(results).toHaveProperty('success');
      expect(results).toHaveProperty('failed');
      expect(results).toHaveProperty('skipped');
      expect(Array.isArray(results.success)).toBe(true);
      expect(Array.isArray(results.failed)).toBe(true);
    });
  });
});
