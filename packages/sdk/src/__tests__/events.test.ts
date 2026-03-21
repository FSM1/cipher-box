import { describe, it, expect, vi } from 'vitest';
import { SdkEventEmitter, type SdkEvent } from '../events';

describe('SdkEventEmitter', () => {
  it('delivers events to subscribers', () => {
    const emitter = new SdkEventEmitter();
    const handler = vi.fn();
    emitter.on(handler);

    const event: SdkEvent = { type: 'operation:start', operation: 'test' };
    emitter.emit(event);

    expect(handler).toHaveBeenCalledOnce();
    expect(handler).toHaveBeenCalledWith(event);
  });

  it('delivers events to multiple subscribers', () => {
    const emitter = new SdkEventEmitter();
    const handler1 = vi.fn();
    const handler2 = vi.fn();
    emitter.on(handler1);
    emitter.on(handler2);

    const event: SdkEvent = { type: 'operation:start', operation: 'test' };
    emitter.emit(event);

    expect(handler1).toHaveBeenCalledOnce();
    expect(handler2).toHaveBeenCalledOnce();
  });

  it('on() returns unsubscribe function', () => {
    const emitter = new SdkEventEmitter();
    const handler = vi.fn();
    const unsub = emitter.on(handler);

    // Should receive first event
    emitter.emit({ type: 'operation:start', operation: 'test1' });
    expect(handler).toHaveBeenCalledOnce();

    // Unsubscribe
    unsub();

    // Should NOT receive second event
    emitter.emit({ type: 'operation:start', operation: 'test2' });
    expect(handler).toHaveBeenCalledOnce();
  });

  it('off() stops delivery', () => {
    const emitter = new SdkEventEmitter();
    const handler = vi.fn();
    emitter.on(handler);

    emitter.emit({ type: 'operation:start', operation: 'test1' });
    expect(handler).toHaveBeenCalledOnce();

    emitter.off(handler);

    emitter.emit({ type: 'operation:start', operation: 'test2' });
    expect(handler).toHaveBeenCalledOnce();
  });

  it('removeAll() clears all handlers', () => {
    const emitter = new SdkEventEmitter();
    const handler1 = vi.fn();
    const handler2 = vi.fn();
    emitter.on(handler1);
    emitter.on(handler2);

    emitter.removeAll();

    emitter.emit({ type: 'operation:start', operation: 'test' });
    expect(handler1).not.toHaveBeenCalled();
    expect(handler2).not.toHaveBeenCalled();
  });

  it('handler errors do not propagate to other handlers', () => {
    const emitter = new SdkEventEmitter();
    const throwingHandler = vi.fn(() => {
      throw new Error('subscriber bug');
    });
    const normalHandler = vi.fn();

    emitter.on(throwingHandler);
    emitter.on(normalHandler);

    // Should not throw, and normalHandler should still receive the event
    expect(() => {
      emitter.emit({ type: 'operation:start', operation: 'test' });
    }).not.toThrow();

    expect(throwingHandler).toHaveBeenCalledOnce();
    expect(normalHandler).toHaveBeenCalledOnce();
  });
});
