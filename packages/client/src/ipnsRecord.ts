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

/** The slice of the wasm-bindgen glue module this reader drives. */
interface IpnsRecordGlue {
  initSync(options: { module: BufferSource }): unknown;
  readIpnsRecord(ipnsName: string, record: Uint8Array): WasmIpnsRecordReading;
}

/**
 * Instantiates the wasm-bindgen glue at `glueUrl` over the `wasmBinary` bytes
 * and returns a record reader. The bytes come from the caller, so a Node host
 * reads them from disk and no fetch of a `file:` URL is needed.
 */
export async function openIpnsRecordReader(
  glueUrl: string | URL,
  wasmBinary: BufferSource
): Promise<IpnsRecordReader> {
  const glue = (await import(/* @vite-ignore */ glueUrl.toString())) as IpnsRecordGlue;
  glue.initSync({ module: wasmBinary });
  return (ipnsName, record) => {
    const reading = glue.readIpnsRecord(ipnsName, record);
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
