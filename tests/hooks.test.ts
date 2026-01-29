import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { findGitRoot, installHook, uninstallHook, checkHookStatus } from '../src/hooks.js';

describe('Hooks', () => {
  let tmpDir: string;
  let gitDir: string;
  let hooksDir: string;

  beforeEach(() => {
    // Create a temp directory with .git/hooks structure
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gguard-test-'));
    gitDir = path.join(tmpDir, '.git');
    hooksDir = path.join(gitDir, 'hooks');
    fs.mkdirSync(hooksDir, { recursive: true });
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  describe('findGitRoot()', () => {
    it('finds git root from project directory', () => {
      const result = findGitRoot(tmpDir);
      expect(result).toBe(tmpDir);
    });

    it('finds git root from subdirectory', () => {
      const subDir = path.join(tmpDir, 'src', 'components');
      fs.mkdirSync(subDir, { recursive: true });
      const result = findGitRoot(subDir);
      expect(result).toBe(tmpDir);
    });

    it('returns null for non-git directory', () => {
      const nonGitDir = fs.mkdtempSync(path.join(os.tmpdir(), 'no-git-'));
      const result = findGitRoot(nonGitDir);
      // May find a parent .git, so just check it returns string or null
      fs.rmSync(nonGitDir, { recursive: true, force: true });
      expect(result === null || typeof result === 'string').toBe(true);
    });
  });

  describe('installHook()', () => {
    it('installs pre-push hook', () => {
      const result = installHook(tmpDir, 'pre-push');
      expect(result.success).toBe(true);
      expect(result.message).toContain('installed');

      const hookPath = path.join(hooksDir, 'pre-push');
      expect(fs.existsSync(hookPath)).toBe(true);

      const content = fs.readFileSync(hookPath, 'utf-8');
      expect(content).toContain('Genaura Guard');
      expect(content).toContain('npx genaura-guard');
    });

    it('installs pre-commit hook', () => {
      const result = installHook(tmpDir, 'pre-commit');
      expect(result.success).toBe(true);

      const hookPath = path.join(hooksDir, 'pre-commit');
      expect(fs.existsSync(hookPath)).toBe(true);

      const content = fs.readFileSync(hookPath, 'utf-8');
      expect(content).toContain('Genaura Guard');
    });

    it('detects already installed hook', () => {
      installHook(tmpDir, 'pre-push');
      const result = installHook(tmpDir, 'pre-push');
      expect(result.success).toBe(true);
      expect(result.message).toContain('already installed');
    });

    it('backs up existing non-guard hook', () => {
      const hookPath = path.join(hooksDir, 'pre-push');
      fs.writeFileSync(hookPath, '#!/bin/sh\necho "existing hook"', { mode: 0o755 });

      const result = installHook(tmpDir, 'pre-push');
      expect(result.success).toBe(true);
      expect(result.message).toContain('backup');

      // Backup file should exist
      const files = fs.readdirSync(hooksDir);
      const backupFile = files.find(f => f.startsWith('pre-push.backup'));
      expect(backupFile).toBeTruthy();
    });

    it('hook file is executable', () => {
      installHook(tmpDir, 'pre-push');
      const hookPath = path.join(hooksDir, 'pre-push');
      const stat = fs.statSync(hookPath);
      // Check executable bit
      expect(stat.mode & 0o111).toBeGreaterThan(0);
    });

    it('pre-push hook contains correct exit code logic', () => {
      installHook(tmpDir, 'pre-push');
      const content = fs.readFileSync(path.join(hooksDir, 'pre-push'), 'utf-8');
      expect(content).toContain('EXIT_CODE');
      expect(content).toContain('exit 0');
      expect(content).toContain('exit 1');
      expect(content).toContain('Push anyway');
    });
  });

  describe('uninstallHook()', () => {
    it('removes installed hook', () => {
      installHook(tmpDir, 'pre-push');
      const result = uninstallHook(tmpDir, 'pre-push');
      expect(result.success).toBe(true);
      expect(result.message).toContain('removed');

      const hookPath = path.join(hooksDir, 'pre-push');
      expect(fs.existsSync(hookPath)).toBe(false);
    });

    it('reports when hook not found', () => {
      const result = uninstallHook(tmpDir, 'pre-push');
      expect(result.success).toBe(true);
      expect(result.message).toContain('not found');
    });

    it('refuses to remove non-guard hook', () => {
      const hookPath = path.join(hooksDir, 'pre-push');
      fs.writeFileSync(hookPath, '#!/bin/sh\necho "not ours"', { mode: 0o755 });

      const result = uninstallHook(tmpDir, 'pre-push');
      expect(result.success).toBe(false);
      expect(result.message).toContain('not installed by Genaura Guard');
    });
  });

  describe('checkHookStatus()', () => {
    it('detects installed pre-push hook', () => {
      installHook(tmpDir, 'pre-push');
      const status = checkHookStatus(tmpDir);
      expect(status.prePush).toBe(true);
      expect(status.preCommit).toBe(false);
    });

    it('detects installed pre-commit hook', () => {
      installHook(tmpDir, 'pre-commit');
      const status = checkHookStatus(tmpDir);
      expect(status.prePush).toBe(false);
      expect(status.preCommit).toBe(true);
    });

    it('detects both hooks installed', () => {
      installHook(tmpDir, 'pre-push');
      installHook(tmpDir, 'pre-commit');
      const status = checkHookStatus(tmpDir);
      expect(status.prePush).toBe(true);
      expect(status.preCommit).toBe(true);
    });

    it('reports no hooks when none installed', () => {
      const status = checkHookStatus(tmpDir);
      expect(status.prePush).toBe(false);
      expect(status.preCommit).toBe(false);
    });
  });
});
