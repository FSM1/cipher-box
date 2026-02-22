import { writeFileSync, unlinkSync, existsSync } from 'fs';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';

// ESM compatibility - __dirname is not available in ESM
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

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
 * Creates a minimal valid PNG test image (1x1 pixel, green).
 * File is tracked for cleanup.
 *
 * @param name - Optional file name (defaults to test-image-{timestamp}.png)
 * @returns Object with file name and absolute path
 */
export function createTestImageFile(name?: string): TestBinaryFile {
  const timestamp = Date.now();
  const fileName = name || `test-image-${timestamp}.png`;
  const filePath = resolve(FIXTURES_DIR, fileName);

  // Minimal valid 1x1 green PNG (67 bytes)
  const png = Buffer.from([
    0x89,
    0x50,
    0x4e,
    0x47,
    0x0d,
    0x0a,
    0x1a,
    0x0a, // PNG signature
    0x00,
    0x00,
    0x00,
    0x0d,
    0x49,
    0x48,
    0x44,
    0x52, // IHDR chunk
    0x00,
    0x00,
    0x00,
    0x01,
    0x00,
    0x00,
    0x00,
    0x01, // 1x1
    0x08,
    0x02,
    0x00,
    0x00,
    0x00,
    0x90,
    0x77,
    0x53, // 8-bit RGB
    0xde,
    0x00,
    0x00,
    0x00,
    0x0c,
    0x49,
    0x44,
    0x41, // IDAT chunk
    0x54,
    0x08,
    0xd7,
    0x63,
    0x60,
    0xf8,
    0xcf,
    0xc0, // deflate data
    0x00,
    0x00,
    0x00,
    0x02,
    0x00,
    0x01,
    0xe2,
    0x21, // CRC
    0xbc,
    0x33,
    0x00,
    0x00,
    0x00,
    0x00,
    0x49,
    0x45, // IEND chunk
    0x4e,
    0x44,
    0xae,
    0x42,
    0x60,
    0x82,
  ]);

  writeFileSync(filePath, png);
  createdFiles.push(filePath);

  return {
    name: fileName,
    path: filePath,
    sizeKb: 0,
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
