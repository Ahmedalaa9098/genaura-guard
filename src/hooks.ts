import * as fs from 'fs';
import * as path from 'path';
import chalk from 'chalk';

const PRE_PUSH_HOOK = `#!/bin/sh
# Genaura Guard - Security scanner pre-push hook
# https://github.com/Harkanovac/genaura-guard

echo ""
echo "🛡️  Genaura Guard - Scanning for security issues..."
echo ""

# Run the security scan
npx genaura-guard scan --hook

# Capture exit code
EXIT_CODE=$?

if [ $EXIT_CODE -eq 0 ]; then
  echo "✓ No critical security issues found. Proceeding with push."
  exit 0
elif [ $EXIT_CODE -eq 1 ]; then
  echo ""
  echo "⚠️  Security issues found. Review the output above."
  echo ""
  read -p "Push anyway? (y/N): " REPLY
  if [ "$REPLY" = "y" ] || [ "$REPLY" = "Y" ]; then
    echo "Proceeding with push..."
    exit 0
  else
    echo "Push cancelled."
    exit 1
  fi
else
  # Exit code 2 = critical issues, block push
  echo ""
  echo "❌ Critical security issues found. Push blocked."
  echo "   Run 'genaura-guard scan' for full details."
  echo "   Run 'genaura-guard fix' for fix guidance."
  exit 1
fi
`;

const PRE_COMMIT_HOOK = `#!/bin/sh
# Genaura Guard - Security scanner pre-commit hook
# https://github.com/Harkanovac/genaura-guard

# Only scan staged files
STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM | grep -E '\\.(js|jsx|ts|tsx|py|php|rb|go|java|vue|svelte)$')

if [ -z "$STAGED_FILES" ]; then
  exit 0
fi

echo ""
echo "🛡️  Genaura Guard - Quick scan of staged files..."

# Create temp file with staged files list
echo "$STAGED_FILES" | while read FILE; do
  npx genaura-guard scan "$FILE" --severity critical,high --quiet
  if [ $? -ne 0 ]; then
    echo "❌ Security issue in $FILE"
    exit 1
  fi
done

exit 0
`;

export function findGitRoot(startPath: string): string | null {
  let currentPath = path.resolve(startPath);
  
  while (currentPath !== path.dirname(currentPath)) {
    const gitPath = path.join(currentPath, '.git');
    if (fs.existsSync(gitPath)) {
      return currentPath;
    }
    currentPath = path.dirname(currentPath);
  }
  
  return null;
}

export function installHook(
  gitRoot: string,
  hookType: 'pre-push' | 'pre-commit' = 'pre-push'
): { success: boolean; message: string } {
  const hooksDir = path.join(gitRoot, '.git', 'hooks');
  const hookPath = path.join(hooksDir, hookType);
  
  // Create hooks directory if it doesn't exist
  if (!fs.existsSync(hooksDir)) {
    fs.mkdirSync(hooksDir, { recursive: true });
  }
  
  // Check if hook already exists
  if (fs.existsSync(hookPath)) {
    const existingHook = fs.readFileSync(hookPath, 'utf-8');
    
    // Check if it's our hook
    if (existingHook.includes('Genaura Guard')) {
      return {
        success: true,
        message: `${hookType} hook already installed`,
      };
    }
    
    // Backup existing hook
    const backupPath = `${hookPath}.backup.${Date.now()}`;
    fs.copyFileSync(hookPath, backupPath);
    
    // Append our hook to existing
    const hookContent = hookType === 'pre-push' ? PRE_PUSH_HOOK : PRE_COMMIT_HOOK;
    const combined = existingHook + '\n\n' + hookContent.split('\n').slice(1).join('\n');
    fs.writeFileSync(hookPath, combined, { mode: 0o755 });
    
    return {
      success: true,
      message: `${hookType} hook updated (backup: ${path.basename(backupPath)})`,
    };
  }
  
  // Write new hook
  const hookContent = hookType === 'pre-push' ? PRE_PUSH_HOOK : PRE_COMMIT_HOOK;
  fs.writeFileSync(hookPath, hookContent, { mode: 0o755 });
  
  return {
    success: true,
    message: `${hookType} hook installed`,
  };
}

export function uninstallHook(
  gitRoot: string,
  hookType: 'pre-push' | 'pre-commit' = 'pre-push'
): { success: boolean; message: string } {
  const hookPath = path.join(gitRoot, '.git', 'hooks', hookType);
  
  if (!fs.existsSync(hookPath)) {
    return {
      success: true,
      message: `${hookType} hook not found`,
    };
  }
  
  const hookContent = fs.readFileSync(hookPath, 'utf-8');
  
  if (!hookContent.includes('Genaura Guard')) {
    return {
      success: false,
      message: `${hookType} hook exists but was not installed by Genaura Guard`,
    };
  }
  
  // Check if it's only our hook or combined
  if (hookContent.startsWith('#!/bin/sh\n# Genaura Guard')) {
    // It's only our hook, remove it
    fs.unlinkSync(hookPath);
    return {
      success: true,
      message: `${hookType} hook removed`,
    };
  }
  
  // It's combined with another hook - remove our section
  const lines = hookContent.split('\n');
  const guardStart = lines.findIndex(l => l.includes('Genaura Guard'));
  
  if (guardStart > 0) {
    // Find the end of our section (next shebang or end of file)
    let guardEnd = lines.length;
    for (let i = guardStart + 1; i < lines.length; i++) {
      if (lines[i].startsWith('#!/')) {
        guardEnd = i;
        break;
      }
    }
    
    const newContent = [
      ...lines.slice(0, guardStart - 1), // Before our section
      ...lines.slice(guardEnd), // After our section
    ].join('\n');
    
    fs.writeFileSync(hookPath, newContent, { mode: 0o755 });
    
    return {
      success: true,
      message: `Genaura Guard removed from ${hookType} hook`,
    };
  }
  
  return {
    success: false,
    message: `Could not parse ${hookType} hook`,
  };
}

export function checkHookStatus(gitRoot: string): {
  prePush: boolean;
  preCommit: boolean;
} {
  const prePushPath = path.join(gitRoot, '.git', 'hooks', 'pre-push');
  const preCommitPath = path.join(gitRoot, '.git', 'hooks', 'pre-commit');
  
  const prePush = fs.existsSync(prePushPath) && 
    fs.readFileSync(prePushPath, 'utf-8').includes('Genaura Guard');
  
  const preCommit = fs.existsSync(preCommitPath) && 
    fs.readFileSync(preCommitPath, 'utf-8').includes('Genaura Guard');
  
  return { prePush, preCommit };
}

export function printHookStatus(gitRoot: string): void {
  const status = checkHookStatus(gitRoot);
  
  console.log();
  console.log(chalk.white.bold('  Git Hooks'));
  console.log(chalk.gray('  ' + '─'.repeat(40)));
  console.log(
    `  pre-push:   ${status.prePush ? chalk.green('✓ installed') : chalk.gray('○ not installed')}`
  );
  console.log(
    `  pre-commit: ${status.preCommit ? chalk.green('✓ installed') : chalk.gray('○ not installed')}`
  );
  console.log();
}
