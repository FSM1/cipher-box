import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { namePrefix, OBSERVER_DIR_ENV, observerModule } from './recordReader';

const NAME = 'k51qzi5uqu5dlvj2baxnqndepeb86cbk3ng7n3i46uzyxzyqj2xjonzllnv0v8';

describe('the public routing read', () => {
  it('names a record in an error by a short prefix only', () => {
    expect(namePrefix(NAME)).toBe('k51qzi5uqu5d...');
    expect(namePrefix(NAME)).not.toContain(NAME.slice(12));
  });

  it('loads the observer module from the configured folder', () => {
    expect(observerModule({ [OBSERVER_DIR_ENV]: '/opt/observer' })).toEqual({
      glue: join('/opt/observer', 'cipherbox_wasm.js'),
      wasm: join('/opt/observer', 'cipherbox_wasm_bg.wasm'),
    });
    expect(observerModule({}).glue).toMatch(/packages[/\\]client[/\\]test[/\\]browser[/\\]pkg/);
  });
});
