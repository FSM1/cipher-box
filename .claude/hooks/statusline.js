#!/usr/bin/env node

const { execSync } = require('child_process');

let input = '';
process.stdin.on('data', (chunk) => (input += chunk));
process.stdin.on('end', () => {
  try {
    const data = JSON.parse(input);
    const cwd = data.cwd || process.cwd();
    const parts = [];

    // 1. Worktree/Project directory (basename)
    const dirName = cwd.split('/').pop();
    parts.push(`\x1b[36m\u{1F4C2} ${dirName}\x1b[0m`);

    // 2. Git branch
    try {
      const branch = execSync('git rev-parse --abbrev-ref HEAD 2>/dev/null', {
        cwd,
        encoding: 'utf8',
        stdio: ['pipe', 'pipe', 'ignore'],
      }).trim();

      // Check if we're in a worktree
      const gitDir = execSync('git rev-parse --git-dir 2>/dev/null', {
        cwd,
        encoding: 'utf8',
        stdio: ['pipe', 'pipe', 'ignore'],
      }).trim();

      const isWorktree = gitDir.includes('.git/worktrees');
      const worktreeIndicator = isWorktree ? ' [wt]' : '';

      // Check for uncommitted changes
      const status = execSync('git status --porcelain 2>/dev/null', {
        cwd,
        encoding: 'utf8',
        stdio: ['pipe', 'pipe', 'ignore'],
      }).trim();
      const dirty = status.length > 0 ? '*' : '';

      parts.push(`\x1b[33m\u{1F33F} ${branch}${dirty}${worktreeIndicator}\x1b[0m`);
    } catch (e) {
      // Not a git repo
    }

    // 3. Model name (short form)
    const model = data.model?.display_name;
    if (model) {
      const shortModel = model
        .replace('Claude ', '')
        .replace('Sonnet', 'S')
        .replace('Opus', 'O')
        .replace('Haiku', 'H');
      parts.push(`\x1b[35m\u{1F9E0} ${shortModel}\x1b[0m`);
    }

    // 4. Context usage bar (always show, default to 0% used if no data)
    const remaining = data.context_window?.remaining_percentage ?? 100;
    const used = 100 - remaining;
    const barWidth = 10;
    const filledCount = Math.round((used / 100) * barWidth);
    const emptyCount = barWidth - filledCount;

    // Color based on usage (green -> yellow -> red as usage increases)
    let color;
    if (used < 50)
      color = '\x1b[32m'; // green
    else if (used < 75)
      color = '\x1b[33m'; // yellow
    else color = '\x1b[31m'; // red

    const bar = '\u2588'.repeat(filledCount) + '\u2591'.repeat(emptyCount);
    parts.push(`\u{26A1} ${color}${bar}\x1b[0m ${Math.round(used)}%`);

    console.log(parts.join(' | '));
  } catch (error) {
    console.log('Claude Code');
  }
});
