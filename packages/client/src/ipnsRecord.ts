/**
 * A signed IPNS record read outside any engine session: the sequence and EOL an
 * observer checks after it fetches a name's record from a routing endpoint. The
 * Rust decoder in the WASM module verifies the record under the name.
 */

/** A verified record's sequence and EOL. */
export interface IpnsRecordReading {
  sequence: bigint;
  /** The signed RFC3339 EOL text. */
  validity: string;
  /** The EOL as Unix millis; `null` where the text does not parse. */
  validUntil: bigint | null;
}

/** Throws the engine's check name for a malformed record, or one the name's key did not sign. */
export type IpnsRecordReader = (ipnsName: string, record: Uint8Array) => IpnsRecordReading;

/** wasm-bindgen `IpnsRecordReading` — a class over WASM memory, so the caller frees it. */
interface WasmIpnsRecordReading {
  readonly sequence: bigint;
  readonly validity: string;
  readonly validUntil?: bigint;
  free(): void;
}

/**
 * The slice of the wasm-bindgen glue module this reader drives. Only a module
 * built with the `observer` feature of `crates/wasm` carries `readIpnsRecord`.
 */
export interface IpnsRecordGlue {
  default(options: { module_or_path: BufferSource }): Promise<unknown>;
  readIpnsRecord?(ipnsName: string, record: Uint8Array): WasmIpnsRecordReading;
}

/**
 * Instantiates the wasm-bindgen glue at `glueUrl` over the `wasmBinary` bytes
 * and returns a record reader.
 */
export async function openIpnsRecordReader(
  glueUrl: string | URL,
  wasmBinary: BufferSource
): Promise<IpnsRecordReader> {
  const glue = (await import(/* @vite-ignore */ glueUrl.toString())) as IpnsRecordGlue;
  return recordReaderOver(glue, wasmBinary);
}

/** The reader over a loaded glue module; refuses a module with no record read. */
export async function recordReaderOver(
  glue: IpnsRecordGlue,
  wasmBinary: BufferSource
): Promise<IpnsRecordReader> {
  const readRecord = glue.readIpnsRecord;
  if (typeof readRecord !== 'function') {
    throw new Error(
      'the WASM module exports no readIpnsRecord: it was built with no `observer` feature'
    );
  }
  await glue.default({ module_or_path: wasmBinary });
  return (ipnsName, record) => {
    const reading = readRecord(ipnsName, record);
    try {
      return {
        sequence: reading.sequence,
        validity: reading.validity,
        validUntil: reading.validUntil ?? null,
      };
    } finally {
      reading.free();
    }
  };
}
