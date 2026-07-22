import { describe, expect, it } from 'vitest';

import { EngineFacade } from './facade.js';
import type { EngineEventListener, EngineTransport } from './transport.js';
import type { CommandDescriptor } from './worker/protocol.js';

class FakeTransport implements EngineTransport {
  started: ArrayBuffer[] = [];
  commands: Array<{ command: CommandDescriptor; transfer: Transferable[] }> = [];
  listeners: EngineEventListener[] = [];
  closed = false;

  start(secret: ArrayBuffer): Promise<void> {
    this.started.push(secret);
    return Promise.resolve();
  }

  command(command: CommandDescriptor, transfer: Transferable[]): Promise<void> {
    this.commands.push({ command, transfer });
    return Promise.resolve();
  }

  subscribe(listener: EngineEventListener): () => void {
    this.listeners.push(listener);
    return () => {
      this.listeners = this.listeners.filter((entry) => entry !== listener);
    };
  }

  close(): void {
    this.closed = true;
  }
}

describe('EngineFacade', () => {
  it('forwards the login secret to the transport on start', async () => {
    const transport = new FakeTransport();
    const secret = new Uint8Array([9, 9, 9]).buffer;
    await new EngineFacade(transport).start(secret);
    expect(transport.started).toEqual([secret]);
  });

  it('sends logout then tears the transport down', async () => {
    const transport = new FakeTransport();
    await new EngineFacade(transport).logout();
    expect(transport.commands.map((entry) => entry.command.kind)).toEqual(['logout']);
    expect(transport.closed).toBe(true);
  });

  it('tears the transport down even when the logout command rejects', async () => {
    const transport = new FakeTransport();
    transport.command = () => Promise.reject(new Error('logout unimplemented'));
    await expect(new EngineFacade(transport).logout()).resolves.toBeUndefined();
    expect(transport.closed).toBe(true);
  });

  it('transfers file content on create and marks it as a file', async () => {
    const transport = new FakeTransport();
    const content = new Uint8Array([1, 2, 3]).buffer;
    await new EngineFacade(transport).create(new Uint8Array(16), 'a.txt', 'file', content);

    const { command, transfer } = transport.commands[0];
    expect(command).toMatchObject({ kind: 'create', name: 'a.txt', nodeKind: 'file', content });
    expect(transfer).toEqual([content]);
  });

  it('sends a folder create with no content and no transfer', async () => {
    const transport = new FakeTransport();
    await new EngineFacade(transport).create(new Uint8Array(16), 'docs', 'folder');

    const { command, transfer } = transport.commands[0];
    expect(command).toMatchObject({ kind: 'create', nodeKind: 'folder', content: null });
    expect(transfer).toEqual([]);
  });

  it('transfers content on updateContent', async () => {
    const transport = new FakeTransport();
    const content = new Uint8Array([4, 5]).buffer;
    await new EngineFacade(transport).updateContent(new Uint8Array(16), content);

    expect(transport.commands[0].command).toMatchObject({ kind: 'updateContent', content });
    expect(transport.commands[0].transfer).toEqual([content]);
  });

  it('carries the permission on a grant', async () => {
    const transport = new FakeTransport();
    const node = new Uint8Array(16);
    const recipient = new Uint8Array([7, 7]);
    await new EngineFacade(transport).grant(node, recipient, 'write');

    expect(transport.commands[0].command).toMatchObject({
      kind: 'grant',
      permission: 'write',
      recipientIdentityPublicKey: recipient,
    });
  });

  it('delegates event subscription to the transport', () => {
    const transport = new FakeTransport();
    const facade = new EngineFacade(transport);
    const unsubscribe = facade.subscribe(() => undefined);
    expect(transport.listeners).toHaveLength(1);
    unsubscribe();
    expect(transport.listeners).toHaveLength(0);
  });
});
