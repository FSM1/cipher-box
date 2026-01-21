import { writeFileSync, unlinkSync, existsSync } from 'fs';
import { resolve } from 'path';

/**
 * Utilities for creating and managing test files.
 * Files are created in tests/e2e/fixtures/files/ and tracked for cleanup.
 */

const FIXTURES_DIR = resolve(__dirname, '../fixtures/files');
const createdFiles: string[] = [];

interface TestTextFile {
  name: string;
  content: string;
  path: string;
}

interface TestBinaryFile {
  name: string;
  path: string;
  sizeKb: number;
}

/**
 * Creates a test text file with specified name and content.
 * File is tracked for cleanup.
 *
 * @param name - Optional file name (defaults to test-file-{timestamp}.txt)
 * @param content - Optional file content (defaults to test content with timestamp)
 * @returns Object with file name, content, and absolute path
 */
export function createTestTextFile(name?: string, content?: string): TestTextFile {
  const timestamp = Date.now();
  const fileName = name || `test-file-${timestamp}.txt`;
  const fileContent =
    content || `Test file created at ${new Date(timestamp).toISOString()}\nThis is test content.`;
  const filePath = resolve(FIXTURES_DIR, fileName);

  writeFileSync(filePath, fileContent, 'utf-8');
  createdFiles.push(filePath);

  return {
    name: fileName,
    content: fileContent,
    path: filePath,
  };
}

/**
 * Creates a test binary file with specified size.
 * File is filled with random bytes and tracked for cleanup.
 *
 * @param sizeKb - Size of file in kilobytes
 * @param name - Optional file name (defaults to test-binary-{timestamp}.bin)
 * @returns Object with file name, absolute path, and size
 */
export function createTestBinaryFile(sizeKb: number, name?: string): TestBinaryFile {
  const timestamp = Date.now();
  const fileName = name || `test-binary-${timestamp}.bin`;
  const filePath = resolve(FIXTURES_DIR, fileName);

  // Create buffer with random bytes
  const buffer = Buffer.alloc(sizeKb * 1024);
  for (let i = 0; i < buffer.length; i++) {
    buffer[i] = Math.floor(Math.random() * 256);
  }

  writeFileSync(filePath, buffer);
  createdFiles.push(filePath);

  return {
    name: fileName,
    path: filePath,
    sizeKb,
  };
}

/**
 * Removes all test files created during the test session.
 * Should be called in afterEach or afterAll hooks.
 */
export function cleanupTestFiles(): void {
  for (const filePath of createdFiles) {
    try {
      if (existsSync(filePath)) {
        unlinkSync(filePath);
      }
    } catch (error) {
      console.warn(`Failed to cleanup test file ${filePath}:`, error);
    }
  }
  createdFiles.length = 0; // Clear the array
}

/**
 * Get absolute path for a file in the test fixtures directory.
 *
 * @param name - File name
 * @returns Absolute path to the file
 */
export function getTestFilePath(name: string): string {
  return resolve(FIXTURES_DIR, name);
}

/**
 * Check if a test file exists.
 *
 * @param name - File name
 * @returns True if file exists
 */
export function testFileExists(name: string): boolean {
  return existsSync(getTestFilePath(name));
}
