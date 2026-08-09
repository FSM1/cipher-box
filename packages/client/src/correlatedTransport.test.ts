import { describe, expect, it } from 'vitest';

import {
  CorrelatedTransport,
  EngineRequestError,
  engineErrorCode,
  isRecoverableEngineError,
} from './correlatedTransport.js';
import type { SnapshotDescriptor, WriteHandle } from './worker/protocol.js';

function unsupported(): never {
  throw new Error('outside this probe');
}

/**
 * A concrete transport wiring only the request skeleton: `pushChunk` carries a
 * transfer, `open`/`breakDown` drive the gate and the terminal latch, and the
 * rest of the engine surface is out of scope here.
 */
class ProbeTransport extends CorrelatedTransport {
  private resolveGate!: () => void;
  private rejectGate!: (error: Error) => void;
  private readonly gate = new Promise<void>((resolve, reject) => {
    this.resolveGate = resolve;
    this.rejectGate = reject;
  });

  constructor(private readonly onSend: (id: number) => void = () => undefined) {
    super();
    this.gate.catch(() => undefined);
  }

  pushChunk(_handle: WriteHandle, chunk: ArrayBuffer): Promise<void> {
    return this.dispatch(this.gate, (id) => this.onSend(id), [chunk]);
  }

  open(): void {
    this.resolveGate();
  }

  shut(error: Error): void {
    this.rejectGate(error);
  }

  breakDown(error: Error): void {
    this.fail(error);
  }

  answer(id: number): void {
    this.settle(id, true);
  }

  start(): Promise<void> {
    return unsupported();
  }
  command(): Promise<void> {
    return unsupported();
  }
  beginWrite(): Promise<WriteHandle> {
    return unsupported();
  }
  commitWrite(): Promise<bigint> {
    return unsupported();
  }
  abortWrite(): Promise<void> {
    return unsupported();
  }
  snapshot(): Promise<SnapshotDescriptor> {
    return unsupported();
  }
  siweChallenge(): Promise<string> {
    return unsupported();
  }
  download(): Promise<ArrayBuffer> {
    return unsupported();
  }
  openContentStream(): Promise<WriteHandle> {
    return unsupported();
  }
  readStream(): Promise<ArrayBuffer> {
    return unsupported();
  }
  closeStream(): Promise<void> {
    return unsupported();
  }
  close(): void {
    unsupported();
  }
}

const plaintext = (): Uint8Array => Uint8Array.of(1, 2, 3, 4);

describe('CorrelatedTransport chunk ownership', () => {
  it('leaves the chunk alone once the send has taken it', async () => {
    const sent: number[] = [];
    const probe = new ProbeTransport((id) => sent.push(id));
    probe.open();
    const chunk = plaintext();

    const pushed = probe.pushChunk(1n, chunk.buffer as ArrayBuffer);
    await Promise.resolve();
    probe.answer(sent[0]);

    // Wiping a sent chunk would zero the bytes the receiver is about to seal.
    await expect(pushed).resolves.toBeUndefined();
    expect(chunk).toEqual(plaintext());
  });

  it('wipes the chunk of a request refused by an already-terminal transport', async () => {
    const probe = new ProbeTransport();
    probe.open();
    probe.breakDown(new Error('engine transport closed'));
    const chunk = plaintext();

    await expect(probe.pushChunk(1n, chunk.buffer as ArrayBuffer)).rejects.toThrow('closed');
    expect(chunk).toEqual(new Uint8Array(4));
  });

  it('wipes the chunk of a request the readiness gate refuses', async () => {
    const probe = new ProbeTransport();
    const chunk = plaintext();

    const pushed = probe.pushChunk(1n, chunk.buffer as ArrayBuffer);
    probe.shut(new Error('leader changed; retry'));

    await expect(pushed).rejects.toThrow('leader changed; retry');
    expect(chunk).toEqual(new Uint8Array(4));
  });

  it('wipes the chunk of a request the transport outlives its gate to refuse', async () => {
    const probe = new ProbeTransport();
    const chunk = plaintext();

    const pushed = probe.pushChunk(1n, chunk.buffer as ArrayBuffer);
    probe.breakDown(new Error('engine transport closed'));
    probe.open();

    await expect(pushed).rejects.toThrow('closed');
    expect(chunk).toEqual(new Uint8Array(4));
  });

  it('wipes the chunk of a send that throws', async () => {
    const probe = new ProbeTransport(() => {
      throw new Error('port is dead');
    });
    probe.open();
    const chunk = plaintext();

    await expect(probe.pushChunk(1n, chunk.buffer as ArrayBuffer)).rejects.toThrow('port is dead');
    expect(chunk).toEqual(new Uint8Array(4));
  });
});

describe('engineErrorCode', () => {
  it('reads the code off an engine failure and nothing else', () => {
    expect(engineErrorCode(new EngineRequestError('nope', 'unknownNode'))).toBe('unknownNode');
    expect(engineErrorCode(new EngineRequestError('nope'))).toBeUndefined();
    expect(engineErrorCode(new Error('transport died'))).toBeUndefined();
    expect(engineErrorCode({ code: 'trustViolation' })).toBeUndefined();
  });
});

describe('isRecoverableEngineError', () => {
  it('recognises the open-stream ceiling', () => {
    expect(isRecoverableEngineError('tooManyStreams')).toBe(true);
  });

  // This predicate gates the media broker's reclaim-and-retry, so a fail-closed
  // verdict widening into it would turn a trust refusal into a retry loop.
  it.each([
    'trustViolation',
    'coldStart',
    'contentUnavailable',
    'contentKeySealFailed',
    'unsupportedContentFormat',
    'unknownStreamHandle',
    'auth',
    'invalidSecret',
    'seam',
    undefined,
  ])('never treats %s as recoverable', (code) => {
    expect(isRecoverableEngineError(code)).toBe(false);
  });
});
