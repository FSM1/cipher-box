/* eslint-disable @typescript-eslint/no-explicit-any */
// @ts-expect-error - process polyfill has no types
import process from 'process/browser';
import { Buffer } from 'buffer';

(globalThis as any).process = process;
(globalThis as any).Buffer = Buffer;
(window as any).process = process;
(window as any).Buffer = Buffer;

export {};
