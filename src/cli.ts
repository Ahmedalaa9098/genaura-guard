#!/usr/bin/env node

import { Command } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import * as path from 'path';
import { scan, quickScan, fullScan } from './scanner.js';
import { printBanner, printResults, printJsonResults, printHookWarning, printRules, printFixReport } from './reporter.js';
import { findGitRoot, installHook, uninstallHook, printHookStatus } from './hooks.js';
import { syncToTargets, printSyncStatus, printSyncResults, injectGuardToProjectConfigs } from './sync.js';
import { Severity } from './types.js';

// Set exit code and let Node drain stdout naturally (no process.exit)
function exit(code: number): void {
  process.exitCode = code;
}

const program = new Command();

program
  .name('genaura-guard')
  .description('🛡️  Security scanner for vibe coders. Find vulnerabilities before you push.')
  .version('1.0.0');

// Main scan command (default)
program
  .command('scan [path]', { isDefault: true })
  .description('Scan code for security vulnerabilities')
  .option('-s, --severity <levels>', 'Filter by severity (critical,high,medium,low)', 'critical,high,medium,low')
  .option('-e, --exclude <patterns>', 'Exclude patterns (comma-separated)')
  .option('--json', 'Output results as JSON')
  .option('--hook', 'Running from git hook (minimal output)')
  .option('-q, --quiet', 'Only output if issues found')
  .option('-v, --verbose', 'Show verbose output')
  .action(async (targetPath: string | undefined, options) => {
    const scanPath = targetPath || process.cwd();
    
    if (!options.json && !options.hook && !options.quiet) {
      printBanner();
    }
    
    const spinner = options.json || options.quiet ? null : ora('Scanning for security issues...').start();
    
    try {
      const severities = options.severity.split(',').map((s: string) => s.trim()) as Severity[];
      const exclude = options.exclude ? options.exclude.split(',').map((s: string) => s.trim()) : undefined;
      
      const result = await scan({
        path: scanPath,
        severity: severities,
        exclude,
        verbose: options.verbose,
      });
      
      spinner?.stop();
      
      if (options.json) {
        printJsonResults(result);
        exit(result.findings.length > 0 ? 1 : 0);
        return;
      }

      if (options.hook) {
        // Git hook mode - minimal output
        const critical = result.findings.filter(f => f.rule.severity === 'critical').length;
        const high = result.findings.filter(f => f.rule.severity === 'high').length;

        if (critical > 0 || high > 0) {
          printHookWarning(result);
          // Exit 2 for critical (block), 1 for high (warn)
          exit(critical > 0 ? 2 : 1);
          return;
        }
        exit(0);
        return;
      }

      if (options.quiet && result.findings.length === 0) {
        exit(0);
        return;
      }
      
      printResults(result, scanPath);

      // Exit code: 0 = clean, 1 = issues found
      exit(result.findings.length > 0 ? 1 : 0);
      return;

    } catch (err) {
      spinner?.fail('Scan failed');
      console.error(chalk.red(`Error: ${err instanceof Error ? err.message : String(err)}`));
      exit(1);
      return;
    }
  });

// Quick scan (critical + high only)
program
  .command('quick [path]')
  .description('Quick scan for critical and high severity issues only')
  .option('--json', 'Output results as JSON')
  .action(async (targetPath: string | undefined, options) => {
    const scanPath = targetPath || process.cwd();

    if (!options.json) {
      printBanner();
    }

    const spinner = options.json ? null : ora('Quick scan...').start();

    try {
      const result = await quickScan(scanPath);
      spinner?.stop();

      if (options.json) {
        printJsonResults(result);
      } else {
        printResults(result, scanPath);
      }

      exit(result.findings.length > 0 ? 1 : 0);
      return;
    } catch (err) {
      spinner?.fail('Scan failed');
      console.error(chalk.red(`Error: ${err instanceof Error ? err.message : String(err)}`));
      exit(1);
      return;
    }
  });

// Full scan (all severities)
program
  .command('full [path]')
  .description('Full scan for all severity levels')
  .option('--json', 'Output results as JSON')
  .action(async (targetPath: string | undefined, options) => {
    const scanPath = targetPath || process.cwd();

    if (!options.json) {
      printBanner();
    }

    const spinner = options.json ? null : ora('Full scan (all severities)...').start();

    try {
      const result = await fullScan(scanPath);
      spinner?.stop();

      if (options.json) {
        printJsonResults(result);
      } else {
        printResults(result, scanPath);
      }

      exit(result.findings.length > 0 ? 1 : 0);
      return;
    } catch (err) {
      spinner?.fail('Scan failed');
      console.error(chalk.red(`Error: ${err instanceof Error ? err.message : String(err)}`));
      exit(1);
      return;
    }
  });

// Fix command - scan with detailed fix report
program
  .command('fix [path]')
  .description('Scan and show detailed fix instructions per file')
  .option('-s, --severity <levels>', 'Filter by severity (critical,high,medium,low)', 'critical,high,medium,low')
  .option('-e, --exclude <patterns>', 'Exclude patterns (comma-separated)')
  .option('--json', 'Output results as JSON')
  .action(async (targetPath: string | undefined, options) => {
    const scanPath = targetPath || process.cwd();

    if (!options.json) {
      printBanner();
    }

    const spinner = options.json ? null : ora('Scanning for fix suggestions...').start();

    try {
      const severities = options.severity.split(',').map((s: string) => s.trim()) as Severity[];
      const exclude = options.exclude ? options.exclude.split(',').map((s: string) => s.trim()) : undefined;

      const result = await scan({
        path: scanPath,
        severity: severities,
        exclude,
      });

      spinner?.stop();

      if (options.json) {
        printJsonResults(result);
      } else {
        printFixReport(result, scanPath);
      }

      exit(result.findings.length > 0 ? 1 : 0);
      return;
    } catch (err) {
      spinner?.fail('Scan failed');
      console.error(chalk.red(`Error: ${err instanceof Error ? err.message : String(err)}`));
      exit(1);
      return;
    }
  });

// Init command - install git hooks
program
  .command('init')
  .description('Install git hooks for automatic scanning')
  .option('--pre-commit', 'Also install pre-commit hook')
  .action((options) => {
    printBanner();
    
    const gitRoot = findGitRoot(process.cwd());
    
    if (!gitRoot) {
      console.error(chalk.red('  ✗ Not a git repository'));
      console.log(chalk.gray('    Run this command inside a git repository.'));
      exit(1);
      return;
    }

    console.log(chalk.white.bold('  Installing Git Hooks'));
    console.log(chalk.gray('  ' + '─'.repeat(45)));
    
    // Install pre-push hook
    const prePushResult = installHook(gitRoot, 'pre-push');
    console.log(
      prePushResult.success
        ? chalk.green(`  ✓ ${prePushResult.message}`)
        : chalk.red(`  ✗ ${prePushResult.message}`)
    );
    
    // Install pre-commit hook if requested
    if (options.preCommit) {
      const preCommitResult = installHook(gitRoot, 'pre-commit');
      console.log(
        preCommitResult.success
          ? chalk.green(`  ✓ ${preCommitResult.message}`)
          : chalk.red(`  ✗ ${preCommitResult.message}`)
      );
    }
    
    // Inject guard section into project-level AI config files
    const projectRoot = gitRoot;
    const injectResults = injectGuardToProjectConfigs(projectRoot);
    const injected = injectResults.filter(r => r.action === 'created' || r.action === 'updated');
    const alreadyPresent = injectResults.filter(r => r.action === 'already_present');

    if (injected.length > 0 || alreadyPresent.length > 0) {
      console.log();
      console.log(chalk.white.bold('  AI Config Rules'));
      console.log(chalk.gray('  ' + '─'.repeat(45)));
      for (const r of injected) {
        console.log(chalk.green(`  ✓ ${r.action === 'created' ? 'Created' : 'Updated'} ${r.file}`));
      }
      for (const r of alreadyPresent) {
        console.log(chalk.gray(`  ○ ${r.file} already configured`));
      }
    }

    console.log();
    console.log(chalk.white('  Now when you push, Genaura Guard will scan for security issues.'));
    console.log();
  });

// Uninstall hooks
program
  .command('uninstall')
  .description('Remove git hooks')
  .action(() => {
    printBanner();
    
    const gitRoot = findGitRoot(process.cwd());
    
    if (!gitRoot) {
      console.error(chalk.red('  ✗ Not a git repository'));
      exit(1);
      return;
    }

    console.log(chalk.white.bold('  Removing Git Hooks'));
    console.log(chalk.gray('  ' + '─'.repeat(45)));
    
    const prePushResult = uninstallHook(gitRoot, 'pre-push');
    console.log(
      prePushResult.success
        ? chalk.green(`  ✓ ${prePushResult.message}`)
        : chalk.yellow(`  ○ ${prePushResult.message}`)
    );
    
    const preCommitResult = uninstallHook(gitRoot, 'pre-commit');
    console.log(
      preCommitResult.success
        ? chalk.green(`  ✓ ${preCommitResult.message}`)
        : chalk.yellow(`  ○ ${preCommitResult.message}`)
    );
    
    console.log();
  });

// Sync security rules to AI tools
program
  .command('sync [targets...]')
  .description('Sync security rules to AI coding assistants (Claude, Cursor, etc.)')
  .action((targets?: string[]) => {
    printBanner();
    
    const spinner = ora('Syncing security rules to AI tools...').start();
    
    const results = syncToTargets(targets);
    
    spinner.stop();
    
    printSyncResults(results);
  });

// Show sync status
program
  .command('status')
  .description('Show current status of hooks and synced rules')
  .action(() => {
    printBanner();
    
    const gitRoot = findGitRoot(process.cwd());
    
    if (gitRoot) {
      printHookStatus(gitRoot);
    } else {
      console.log(chalk.gray('  Not in a git repository - hooks not available'));
      console.log();
    }
    
    printSyncStatus();
  });

// Show rules
program
  .command('rules')
  .description('List all security rules that are checked')
  .action(() => {
    printBanner();
    printRules();
  });

// Parse and run
program.parse();
