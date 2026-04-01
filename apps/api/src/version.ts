import { readFileSync } from 'fs';
import { join } from 'path';

export const API_VERSION: string =
  process.env.npm_package_version ||
  JSON.parse(readFileSync(join(__dirname, '..', 'package.json'), 'utf-8')).version;
