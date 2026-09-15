/**
 * The fixture media the staging profiles upload, generated rather than
 * committed: the bytes are deterministic, so a read-back assertion compares
 * against the same file the upload sent, and the repository carries no binaries.
 *
 * The image, the document and the audio file are real files of their format.
 * The two video files carry a real MP4 container over a deterministic payload,
 * which is what a range-request profile reads; neither decodes to pictures.
 */

import { crc32, deflateSync } from 'node:zlib';
import { mkdir, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

/** Written at setup time, and ignored by git. */
const MEDIA_DIR = join(dirname(fileURLToPath(import.meta.url)), '.media');

export interface MediaFixture {
  readonly name: string;
  readonly bytes: Uint8Array;
}

/** Deterministic and never all one byte, so a truncation cannot read as equal. */
export function filler(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  for (let i = 0; i < length; i += 1) bytes[i] = (i * 31 + 7) & 0xff;
  return bytes;
}

function chunk(type: string, body: Uint8Array): Uint8Array {
  const head = Buffer.alloc(8);
  head.writeUInt32BE(body.length, 0);
  head.write(type, 4, 'ascii');
  const typed = Buffer.concat([head.subarray(4), body]);
  const tail = Buffer.alloc(4);
  tail.writeUInt32BE(crc32(typed), 0);
  return Buffer.concat([head.subarray(0, 4), typed, tail]);
}

/** A square of one colour, as a real PNG. */
function png(side: number): Uint8Array {
  const header = Buffer.alloc(13);
  header.writeUInt32BE(side, 0);
  header.writeUInt32BE(side, 4);
  header[8] = 8; // bit depth
  header[9] = 2; // truecolour
  const raw = Buffer.alloc(side * (side * 3 + 1));
  for (let row = 0; row < side; row += 1) {
    const start = row * (side * 3 + 1);
    raw[start] = 0; // no per-row filter
    for (let column = 0; column < side; column += 1) {
      raw.set([0x00, 0x9a, 0x3c], start + 1 + column * 3);
    }
  }
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', header),
    chunk('IDAT', deflateSync(raw)),
    chunk('IEND', Buffer.alloc(0)),
  ]);
}

/** One page of text, as a real PDF; the offsets are computed, not guessed. */
function pdf(): Uint8Array {
  const objects = [
    '<</Type/Catalog/Pages 2 0 R>>',
    '<</Type/Pages/Kids[3 0 R]/Count 1>>',
    '<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R/Resources<</Font<</F1 4 0 R>>>>/Contents 5 0 R>>',
    '<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>',
    '<</Length 55>>stream\nBT /F1 24 Tf 100 700 Td (CipherBox Test Document) Tj ET\nendstream',
  ];

  let body = '%PDF-1.4\n';
  const offsets: number[] = [];
  objects.forEach((object, index) => {
    offsets.push(body.length);
    body += `${index + 1} 0 obj${object}endobj\n`;
  });

  const startxref = body.length;
  body += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
  for (const offset of offsets) body += `${String(offset).padStart(10, '0')} 00000 n \n`;
  body += `trailer<</Size ${objects.length + 1}/Root 1 0 R>>\nstartxref\n${startxref}\n%%EOF\n`;
  return Buffer.from(body, 'ascii');
}

/** A second of 8 kHz mono PCM, as a real WAV. */
function wav(samples: number): Uint8Array {
  const data = Buffer.alloc(samples * 2);
  for (let i = 0; i < samples; i += 1) {
    data.writeInt16LE(Math.round(Math.sin((i * 2 * Math.PI * 440) / 8000) * 12_000), i * 2);
  }
  const header = Buffer.alloc(44);
  header.write('RIFF', 0, 'ascii');
  header.writeUInt32LE(36 + data.length, 4);
  header.write('WAVEfmt ', 8, 'ascii');
  header.writeUInt32LE(16, 16);
  header.writeUInt16LE(1, 20); // PCM
  header.writeUInt16LE(1, 22); // mono
  header.writeUInt32LE(8_000, 24);
  header.writeUInt32LE(16_000, 28);
  header.writeUInt16LE(2, 32);
  header.writeUInt16LE(16, 34);
  header.write('data', 36, 'ascii');
  header.writeUInt32LE(data.length, 40);
  return Buffer.concat([header, data]);
}

/** An ISO base-media container over `payload` bytes of filler. */
function mp4(payload: number): Uint8Array {
  const ftyp = Buffer.alloc(32);
  ftyp.writeUInt32BE(32, 0);
  ftyp.write('ftypisom', 4, 'ascii');
  ftyp.writeUInt32BE(0x200, 12);
  ftyp.write('isomiso2mp41', 16, 'ascii');

  const mdat = Buffer.alloc(8);
  mdat.writeUInt32BE(payload + 8, 0);
  mdat.write('mdat', 4, 'ascii');
  return Buffer.concat([ftyp, mdat, filler(payload)]);
}

/** Every fixture, by the name it is uploaded and read back under. */
export function mediaFixtures(): Record<string, MediaFixture> {
  return {
    image: { name: 'cipherbox-image.png', bytes: png(64) },
    document: { name: 'cipherbox-document.pdf', bytes: pdf() },
    audio: { name: 'cipherbox-audio.wav', bytes: wav(8_000) },
    videoSmall: { name: 'cipherbox-video-small.mp4', bytes: mp4(100 * 1024) },
    videoLarge: { name: 'cipherbox-video-large.mp4', bytes: mp4(2 * 1024 * 1024) },
  };
}

/** Where a fixture lands on disk, for `setInputFiles`. */
export function mediaPath(fixture: MediaFixture): string {
  return join(MEDIA_DIR, fixture.name);
}

export async function writeMediaFixtures(): Promise<void> {
  await mkdir(MEDIA_DIR, { recursive: true });
  for (const fixture of Object.values(mediaFixtures())) {
    await writeFile(mediaPath(fixture), fixture.bytes);
  }
}
