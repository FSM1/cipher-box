#!/usr/bin/env node
/**
 * Fix orval-generated import paths.
 * Orval generates '.././' paths which fail on Linux.
 * This script replaces '.././' with '../' in all generated files.
 */
import { readFileSync, writeFileSync, readdirSync, statSync } from 'fs';
import { join } from 'path';

function fixFile(filePath) {
  const content = readFileSync(filePath, 'utf8');
  if (content.includes('.././')) {
    const fixed = content.replace(/['"]\.\.\/\.\//g, (match) => match[0] + '../');
    writeFileSync(filePath, fixed);
    console.log(`Fixed: ${filePath}`);
  }
}

function walkDir(dir) {
  const files = readdirSync(dir);
  for (const file of files) {
    const filePath = join(dir, file);
    const stat = statSync(filePath);
    if (stat.isDirectory()) {
      walkDir(filePath);
    } else if (file.endsWith('.ts')) {
      fixFile(filePath);
    }
  }
}

const apiDir = new URL('../src/api', import.meta.url).pathname;
walkDir(apiDir);
