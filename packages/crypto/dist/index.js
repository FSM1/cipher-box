"use strict";
var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/index.ts
var index_exports = {};
__export(index_exports, {
  AES_GCM_ALGORITHM: () => AES_GCM_ALGORITHM,
  AES_IV_SIZE: () => AES_IV_SIZE,
  AES_KEY_SIZE: () => AES_KEY_SIZE,
  AES_TAG_SIZE: () => AES_TAG_SIZE,
  CRYPTO_VERSION: () => CRYPTO_VERSION,
  CryptoError: () => CryptoError,
  ECIES_MIN_CIPHERTEXT_SIZE: () => ECIES_MIN_CIPHERTEXT_SIZE,
  ED25519_PRIVATE_KEY_SIZE: () => ED25519_PRIVATE_KEY_SIZE,
  ED25519_PUBLIC_KEY_SIZE: () => ED25519_PUBLIC_KEY_SIZE,
  ED25519_SIGNATURE_SIZE: () => ED25519_SIGNATURE_SIZE,
  IPNS_SIGNATURE_PREFIX: () => IPNS_SIGNATURE_PREFIX,
  SECP256K1_PRIVATE_KEY_SIZE: () => SECP256K1_PRIVATE_KEY_SIZE,
  SECP256K1_PUBLIC_KEY_SIZE: () => SECP256K1_PUBLIC_KEY_SIZE,
  bytesToHex: () => bytesToHex2,
  clearAll: () => clearAll,
  clearBytes: () => clearBytes,
  concatBytes: () => concatBytes2,
  createIpnsRecord: () => createIpnsRecord,
  decryptAesGcm: () => decryptAesGcm,
  decryptFolderMetadata: () => decryptFolderMetadata,
  decryptVaultKeys: () => decryptVaultKeys,
  deriveContextKey: () => deriveContextKey,
  deriveIpnsName: () => deriveIpnsName,
  deriveKey: () => deriveKey,
  encryptAesGcm: () => encryptAesGcm,
  encryptFolderMetadata: () => encryptFolderMetadata,
  encryptVaultKeys: () => encryptVaultKeys,
  generateEd25519Keypair: () => generateEd25519Keypair,
  generateFileKey: () => generateFileKey,
  generateFolderKey: () => generateFolderKey,
  generateIv: () => generateIv,
  generateRandomBytes: () => generateRandomBytes,
  hexToBytes: () => hexToBytes2,
  initializeVault: () => initializeVault,
  marshalIpnsRecord: () => marshalIpnsRecord,
  sealAesGcm: () => sealAesGcm,
  signEd25519: () => signEd25519,
  signIpnsData: () => signIpnsData,
  unmarshalIpnsRecord: () => unmarshalIpnsRecord,
  unsealAesGcm: () => unsealAesGcm,
  unwrapKey: () => unwrapKey,
  verifyEd25519: () => verifyEd25519,
  wrapKey: () => wrapKey
});
module.exports = __toCommonJS(index_exports);

// src/types.ts
var CryptoError = class _CryptoError extends Error {
  code;
  constructor(message, code) {
    super(message);
    this.name = "CryptoError";
    this.code = code;
    const ErrorWithCapture = Error;
    if (ErrorWithCapture.captureStackTrace) {
      ErrorWithCapture.captureStackTrace(this, _CryptoError);
    }
  }
};

// src/constants.ts
var AES_KEY_SIZE = 32;
var AES_IV_SIZE = 12;
var AES_TAG_SIZE = 16;
var SECP256K1_PUBLIC_KEY_SIZE = 65;
var SECP256K1_PRIVATE_KEY_SIZE = 32;
var ECIES_MIN_CIPHERTEXT_SIZE = 65 + 16;
var AES_GCM_ALGORITHM = "AES-GCM";
var ED25519_PUBLIC_KEY_SIZE = 32;
var ED25519_PRIVATE_KEY_SIZE = 32;
var ED25519_SIGNATURE_SIZE = 64;

// src/utils/random.ts
function generateRandomBytes(length) {
  if (typeof crypto === "undefined" || typeof crypto.getRandomValues !== "function") {
    throw new CryptoError(
      "Secure random generation unavailable - requires secure context (HTTPS or localhost)",
      "RANDOM_GENERATION_FAILED"
    );
  }
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}
function generateFileKey() {
  return generateRandomBytes(AES_KEY_SIZE);
}
function generateIv() {
  return generateRandomBytes(AES_IV_SIZE);
}

// src/ed25519/keygen.ts
var ed = __toESM(require("@noble/ed25519"));
var import_sha512 = require("@noble/hashes/sha512");
ed.etc.sha512Sync = (...m) => (0, import_sha512.sha512)(ed.etc.concatBytes(...m));
function generateEd25519Keypair() {
  const privateKey = ed.utils.randomPrivateKey();
  const publicKey = ed.getPublicKey(privateKey);
  return {
    publicKey,
    privateKey
  };
}

// src/ed25519/sign.ts
var ed2 = __toESM(require("@noble/ed25519"));
var import_sha5122 = require("@noble/hashes/sha512");
ed2.etc.sha512Sync = (...m) => (0, import_sha5122.sha512)(ed2.etc.concatBytes(...m));
async function signEd25519(message, privateKey) {
  if (privateKey.length !== ED25519_PRIVATE_KEY_SIZE) {
    throw new CryptoError("Signing failed", "INVALID_PRIVATE_KEY_SIZE");
  }
  try {
    const signature = await ed2.signAsync(message, privateKey);
    return signature;
  } catch {
    throw new CryptoError("Signing failed", "SIGNING_FAILED");
  }
}
async function verifyEd25519(signature, message, publicKey) {
  if (signature.length !== ED25519_SIGNATURE_SIZE) {
    return false;
  }
  if (publicKey.length !== ED25519_PUBLIC_KEY_SIZE) {
    return false;
  }
  try {
    return await ed2.verifyAsync(signature, message, publicKey);
  } catch {
    return false;
  }
}

// src/ecies/encrypt.ts
var import_eciesjs = require("eciesjs");

// ../../node_modules/.pnpm/@noble+secp256k1@2.3.0/node_modules/@noble/secp256k1/index.js
var secp256k1_CURVE = {
  p: 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn,
  n: 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n,
  h: 1n,
  a: 0n,
  b: 7n,
  Gx: 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n,
  Gy: 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n
};
var { p: P, n: N, Gx, Gy, b: _b } = secp256k1_CURVE;
var L = 32;
var L2 = 64;
var err = (m = "") => {
  throw new Error(m);
};
var isBig = (n) => typeof n === "bigint";
var isStr = (s) => typeof s === "string";
var isBytes = (a) => a instanceof Uint8Array || ArrayBuffer.isView(a) && a.constructor.name === "Uint8Array";
var abytes = (a, l) => !isBytes(a) || typeof l === "number" && l > 0 && a.length !== l ? err("Uint8Array expected") : a;
var u8n = (len) => new Uint8Array(len);
var u8fr = (buf) => Uint8Array.from(buf);
var padh = (n, pad) => n.toString(16).padStart(pad, "0");
var bytesToHex = (b) => Array.from(abytes(b)).map((e) => padh(e, 2)).join("");
var C = { _0: 48, _9: 57, A: 65, F: 70, a: 97, f: 102 };
var _ch = (ch) => {
  if (ch >= C._0 && ch <= C._9)
    return ch - C._0;
  if (ch >= C.A && ch <= C.F)
    return ch - (C.A - 10);
  if (ch >= C.a && ch <= C.f)
    return ch - (C.a - 10);
  return;
};
var hexToBytes = (hex) => {
  const e = "hex invalid";
  if (!isStr(hex))
    return err(e);
  const hl = hex.length;
  const al = hl / 2;
  if (hl % 2)
    return err(e);
  const array = u8n(al);
  for (let ai = 0, hi = 0; ai < al; ai++, hi += 2) {
    const n1 = _ch(hex.charCodeAt(hi));
    const n2 = _ch(hex.charCodeAt(hi + 1));
    if (n1 === void 0 || n2 === void 0)
      return err(e);
    array[ai] = n1 * 16 + n2;
  }
  return array;
};
var toU8 = (a, len) => abytes(isStr(a) ? hexToBytes(a) : u8fr(abytes(a)), len);
var concatBytes = (...arrs) => {
  const r = u8n(arrs.reduce((sum, a) => sum + abytes(a).length, 0));
  let pad = 0;
  arrs.forEach((a) => {
    r.set(a, pad);
    pad += a.length;
  });
  return r;
};
var big = BigInt;
var arange = (n, min, max, msg = "bad number: out of range") => isBig(n) && min <= n && n < max ? n : err(msg);
var M = (a, b = P) => {
  const r = a % b;
  return r >= 0n ? r : b + r;
};
var invert = (num, md) => {
  if (num === 0n || md <= 0n)
    err("no inverse n=" + num + " mod=" + md);
  let a = M(num, md), b = md, x = 0n, y = 1n, u = 1n, v = 0n;
  while (a !== 0n) {
    const q = b / a, r = b % a;
    const m = x - u * q, n = y - v * q;
    b = a, a = r, x = u, y = v, u = m, v = n;
  }
  return b === 1n ? M(x, md) : err("no inverse");
};
var apoint = (p) => p instanceof Point ? p : err("Point expected");
var koblitz = (x) => M(M(x * x) * x + _b);
var afield0 = (n) => arange(n, 0n, P);
var afield = (n) => arange(n, 1n, P);
var agroup = (n) => arange(n, 1n, N);
var isEven = (y) => (y & 1n) === 0n;
var u8of = (n) => Uint8Array.of(n);
var getPrefix = (y) => u8of(isEven(y) ? 2 : 3);
var lift_x = (x) => {
  const c = koblitz(afield(x));
  let r = 1n;
  for (let num = c, e = (P + 1n) / 4n; e > 0n; e >>= 1n) {
    if (e & 1n)
      r = r * num % P;
    num = num * num % P;
  }
  return M(r * r) === c ? r : err("sqrt invalid");
};
var Point = class _Point {
  static BASE;
  static ZERO;
  px;
  py;
  pz;
  constructor(px, py, pz) {
    this.px = afield0(px);
    this.py = afield(py);
    this.pz = afield0(pz);
    Object.freeze(this);
  }
  /** Convert Uint8Array or hex string to Point. */
  static fromBytes(bytes) {
    abytes(bytes);
    let p = void 0;
    const head = bytes[0];
    const tail = bytes.subarray(1);
    const x = sliceBytesNumBE(tail, 0, L);
    const len = bytes.length;
    if (len === L + 1 && [2, 3].includes(head)) {
      let y = lift_x(x);
      const evenY = isEven(y);
      const evenH = isEven(big(head));
      if (evenH !== evenY)
        y = M(-y);
      p = new _Point(x, y, 1n);
    }
    if (len === L2 + 1 && head === 4)
      p = new _Point(x, sliceBytesNumBE(tail, L, L2), 1n);
    return p ? p.assertValidity() : err("bad point: not on curve");
  }
  /** Equality check: compare points P&Q. */
  equals(other) {
    const { px: X1, py: Y1, pz: Z1 } = this;
    const { px: X2, py: Y2, pz: Z2 } = apoint(other);
    const X1Z2 = M(X1 * Z2);
    const X2Z1 = M(X2 * Z1);
    const Y1Z2 = M(Y1 * Z2);
    const Y2Z1 = M(Y2 * Z1);
    return X1Z2 === X2Z1 && Y1Z2 === Y2Z1;
  }
  is0() {
    return this.equals(I);
  }
  /** Flip point over y coordinate. */
  negate() {
    return new _Point(this.px, M(-this.py), this.pz);
  }
  /** Point doubling: P+P, complete formula. */
  double() {
    return this.add(this);
  }
  /**
   * Point addition: P+Q, complete, exception-free formula
   * (Renes-Costello-Batina, algo 1 of [2015/1060](https://eprint.iacr.org/2015/1060)).
   * Cost: `12M + 0S + 3*a + 3*b3 + 23add`.
   */
  // prettier-ignore
  add(other) {
    const { px: X1, py: Y1, pz: Z1 } = this;
    const { px: X2, py: Y2, pz: Z2 } = apoint(other);
    const a = 0n;
    const b = _b;
    let X3 = 0n, Y3 = 0n, Z3 = 0n;
    const b3 = M(b * 3n);
    let t0 = M(X1 * X2), t1 = M(Y1 * Y2), t2 = M(Z1 * Z2), t3 = M(X1 + Y1);
    let t4 = M(X2 + Y2);
    t3 = M(t3 * t4);
    t4 = M(t0 + t1);
    t3 = M(t3 - t4);
    t4 = M(X1 + Z1);
    let t5 = M(X2 + Z2);
    t4 = M(t4 * t5);
    t5 = M(t0 + t2);
    t4 = M(t4 - t5);
    t5 = M(Y1 + Z1);
    X3 = M(Y2 + Z2);
    t5 = M(t5 * X3);
    X3 = M(t1 + t2);
    t5 = M(t5 - X3);
    Z3 = M(a * t4);
    X3 = M(b3 * t2);
    Z3 = M(X3 + Z3);
    X3 = M(t1 - Z3);
    Z3 = M(t1 + Z3);
    Y3 = M(X3 * Z3);
    t1 = M(t0 + t0);
    t1 = M(t1 + t0);
    t2 = M(a * t2);
    t4 = M(b3 * t4);
    t1 = M(t1 + t2);
    t2 = M(t0 - t2);
    t2 = M(a * t2);
    t4 = M(t4 + t2);
    t0 = M(t1 * t4);
    Y3 = M(Y3 + t0);
    t0 = M(t5 * t4);
    X3 = M(t3 * X3);
    X3 = M(X3 - t0);
    t0 = M(t3 * t1);
    Z3 = M(t5 * Z3);
    Z3 = M(Z3 + t0);
    return new _Point(X3, Y3, Z3);
  }
  /**
   * Point-by-scalar multiplication. Scalar must be in range 1 <= n < CURVE.n.
   * Uses {@link wNAF} for base point.
   * Uses fake point to mitigate side-channel leakage.
   * @param n scalar by which point is multiplied
   * @param safe safe mode guards against timing attacks; unsafe mode is faster
   */
  multiply(n, safe = true) {
    if (!safe && n === 0n)
      return I;
    agroup(n);
    if (n === 1n)
      return this;
    if (this.equals(G))
      return wNAF(n).p;
    let p = I;
    let f = G;
    for (let d = this; n > 0n; d = d.double(), n >>= 1n) {
      if (n & 1n)
        p = p.add(d);
      else if (safe)
        f = f.add(d);
    }
    return p;
  }
  /** Convert point to 2d xy affine point. (X, Y, Z) ∋ (x=X/Z, y=Y/Z) */
  toAffine() {
    const { px: x, py: y, pz: z } = this;
    if (this.equals(I))
      return { x: 0n, y: 0n };
    if (z === 1n)
      return { x, y };
    const iz = invert(z, P);
    if (M(z * iz) !== 1n)
      err("inverse invalid");
    return { x: M(x * iz), y: M(y * iz) };
  }
  /** Checks if the point is valid and on-curve. */
  assertValidity() {
    const { x, y } = this.toAffine();
    afield(x);
    afield(y);
    return M(y * y) === koblitz(x) ? this : err("bad point: not on curve");
  }
  /** Converts point to 33/65-byte Uint8Array. */
  toBytes(isCompressed = true) {
    const { x, y } = this.assertValidity().toAffine();
    const x32b = numTo32b(x);
    if (isCompressed)
      return concatBytes(getPrefix(y), x32b);
    return concatBytes(u8of(4), x32b, numTo32b(y));
  }
  /** Create 3d xyz point from 2d xy. (0, 0) => (0, 1, 0), not (0, 0, 1) */
  static fromAffine(ap) {
    const { x, y } = ap;
    return x === 0n && y === 0n ? I : new _Point(x, y, 1n);
  }
  toHex(isCompressed) {
    return bytesToHex(this.toBytes(isCompressed));
  }
  static fromPrivateKey(k) {
    return G.multiply(toPrivScalar(k));
  }
  static fromHex(hex) {
    return _Point.fromBytes(toU8(hex));
  }
  get x() {
    return this.toAffine().x;
  }
  get y() {
    return this.toAffine().y;
  }
  toRawBytes(isCompressed) {
    return this.toBytes(isCompressed);
  }
};
var G = new Point(Gx, Gy, 1n);
var I = new Point(0n, 1n, 0n);
Point.BASE = G;
Point.ZERO = I;
var bytesToNumBE = (b) => big("0x" + (bytesToHex(b) || "0"));
var sliceBytesNumBE = (b, from, to) => bytesToNumBE(b.subarray(from, to));
var B256 = 2n ** 256n;
var numTo32b = (num) => hexToBytes(padh(arange(num, 0n, B256), L2));
var toPrivScalar = (pr) => {
  const num = isBig(pr) ? pr : bytesToNumBE(toU8(pr, L));
  return arange(num, 1n, N, "private key invalid 3");
};
var W = 8;
var scalarBits = 256;
var pwindows = Math.ceil(scalarBits / W) + 1;
var pwindowSize = 2 ** (W - 1);
var precompute = () => {
  const points = [];
  let p = G;
  let b = p;
  for (let w = 0; w < pwindows; w++) {
    b = p;
    points.push(b);
    for (let i = 1; i < pwindowSize; i++) {
      b = b.add(p);
      points.push(b);
    }
    p = b.double();
  }
  return points;
};
var Gpows = void 0;
var ctneg = (cnd, p) => {
  const n = p.negate();
  return cnd ? n : p;
};
var wNAF = (n) => {
  const comp = Gpows || (Gpows = precompute());
  let p = I;
  let f = G;
  const pow_2_w = 2 ** W;
  const maxNum = pow_2_w;
  const mask = big(pow_2_w - 1);
  const shiftBy = big(W);
  for (let w = 0; w < pwindows; w++) {
    let wbits = Number(n & mask);
    n >>= shiftBy;
    if (wbits > pwindowSize) {
      wbits -= maxNum;
      n += 1n;
    }
    const off = w * pwindowSize;
    const offF = off;
    const offP = off + Math.abs(wbits) - 1;
    const isEven2 = w % 2 !== 0;
    const isNeg = wbits < 0;
    if (wbits === 0) {
      f = f.add(ctneg(isEven2, comp[offF]));
    } else {
      p = p.add(ctneg(isNeg, comp[offP]));
    }
  }
  return { p, f };
};

// src/ecies/encrypt.ts
async function wrapKey(key, recipientPublicKey) {
  if (recipientPublicKey.length !== SECP256K1_PUBLIC_KEY_SIZE) {
    throw new CryptoError("Key wrapping failed", "INVALID_PUBLIC_KEY_SIZE");
  }
  if (recipientPublicKey[0] !== 4) {
    throw new CryptoError("Key wrapping failed", "INVALID_PUBLIC_KEY_FORMAT");
  }
  try {
    Point.fromHex(recipientPublicKey);
  } catch {
    throw new CryptoError("Key wrapping failed", "INVALID_PUBLIC_KEY_FORMAT");
  }
  try {
    const wrapped = (0, import_eciesjs.encrypt)(recipientPublicKey, key);
    return wrapped;
  } catch {
    throw new CryptoError("Key wrapping failed", "KEY_WRAPPING_FAILED");
  }
}

// src/ecies/decrypt.ts
var import_eciesjs2 = require("eciesjs");
async function unwrapKey(wrappedKey, privateKey) {
  if (privateKey.length !== SECP256K1_PRIVATE_KEY_SIZE) {
    throw new CryptoError("Key unwrapping failed", "INVALID_PRIVATE_KEY_SIZE");
  }
  if (wrappedKey.length < ECIES_MIN_CIPHERTEXT_SIZE) {
    throw new CryptoError("Key unwrapping failed", "KEY_UNWRAPPING_FAILED");
  }
  try {
    const unwrapped = (0, import_eciesjs2.decrypt)(privateKey, wrappedKey);
    return new Uint8Array(unwrapped);
  } catch {
    throw new CryptoError("Key unwrapping failed", "KEY_UNWRAPPING_FAILED");
  }
}

// src/vault/init.ts
async function initializeVault() {
  const rootFolderKey = generateFileKey();
  const rootIpnsKeypair = generateEd25519Keypair();
  return {
    rootFolderKey,
    rootIpnsKeypair
  };
}
async function encryptVaultKeys(vault, userPublicKey) {
  const encryptedRootFolderKey = await wrapKey(vault.rootFolderKey, userPublicKey);
  const encryptedIpnsPrivateKey = await wrapKey(vault.rootIpnsKeypair.privateKey, userPublicKey);
  return {
    encryptedRootFolderKey,
    encryptedIpnsPrivateKey,
    // Public key is not secret - stored in plaintext for IPNS name derivation
    rootIpnsPublicKey: vault.rootIpnsKeypair.publicKey
  };
}
async function decryptVaultKeys(encrypted, userPrivateKey) {
  const rootFolderKey = await unwrapKey(encrypted.encryptedRootFolderKey, userPrivateKey);
  const ipnsPrivateKey = await unwrapKey(encrypted.encryptedIpnsPrivateKey, userPrivateKey);
  const rootIpnsKeypair = {
    privateKey: ipnsPrivateKey,
    publicKey: encrypted.rootIpnsPublicKey
  };
  return {
    rootFolderKey,
    rootIpnsKeypair
  };
}

// src/keys/derive.ts
async function deriveKey(params) {
  const { inputKey, salt, info, outputLength = AES_KEY_SIZE } = params;
  try {
    const inputKeyBuffer = new Uint8Array(inputKey).buffer;
    const saltBuffer = new Uint8Array(salt).buffer;
    const infoBuffer = new Uint8Array(info).buffer;
    const keyMaterial = await crypto.subtle.importKey(
      "raw",
      inputKeyBuffer,
      "HKDF",
      false,
      // not extractable
      ["deriveBits"]
    );
    const derivedBits = await crypto.subtle.deriveBits(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: saltBuffer,
        info: infoBuffer
      },
      keyMaterial,
      outputLength * 8
      // deriveBits takes length in bits
    );
    return new Uint8Array(derivedBits);
  } catch {
    throw new CryptoError("Key derivation failed", "ENCRYPTION_FAILED");
  }
}

// src/keys/hierarchy.ts
var CIPHERBOX_SALT = new TextEncoder().encode("CipherBox-v1");
async function deriveContextKey(masterKey, context) {
  const info = new TextEncoder().encode(context);
  return deriveKey({
    inputKey: masterKey,
    salt: CIPHERBOX_SALT,
    info,
    outputLength: 32
  });
}
async function generateFolderKey() {
  return generateFileKey();
}

// src/aes/encrypt.ts
async function encryptAesGcm(plaintext, key, iv) {
  if (key.length !== AES_KEY_SIZE) {
    throw new CryptoError("Encryption failed", "INVALID_KEY_SIZE");
  }
  if (iv.length !== AES_IV_SIZE) {
    throw new CryptoError("Encryption failed", "INVALID_IV_SIZE");
  }
  try {
    const keyBuffer = new Uint8Array(key).buffer;
    const ivBuffer = new Uint8Array(iv).buffer;
    const plaintextBuffer = new Uint8Array(plaintext).buffer;
    const cryptoKey = await crypto.subtle.importKey(
      "raw",
      keyBuffer,
      { name: AES_GCM_ALGORITHM },
      false,
      ["encrypt"]
    );
    const ciphertext = await crypto.subtle.encrypt(
      { name: AES_GCM_ALGORITHM, iv: ivBuffer },
      cryptoKey,
      plaintextBuffer
    );
    return new Uint8Array(ciphertext);
  } catch {
    throw new CryptoError("Encryption failed", "ENCRYPTION_FAILED");
  }
}

// src/aes/decrypt.ts
async function decryptAesGcm(ciphertext, key, iv) {
  if (key.length !== AES_KEY_SIZE) {
    throw new CryptoError("Decryption failed", "INVALID_KEY_SIZE");
  }
  if (iv.length !== AES_IV_SIZE) {
    throw new CryptoError("Decryption failed", "INVALID_IV_SIZE");
  }
  if (ciphertext.length < AES_TAG_SIZE) {
    throw new CryptoError("Decryption failed", "DECRYPTION_FAILED");
  }
  try {
    const keyBuffer = new Uint8Array(key).buffer;
    const ivBuffer = new Uint8Array(iv).buffer;
    const ciphertextBuffer = new Uint8Array(ciphertext).buffer;
    const cryptoKey = await crypto.subtle.importKey(
      "raw",
      keyBuffer,
      { name: AES_GCM_ALGORITHM },
      false,
      ["decrypt"]
    );
    const plaintext = await crypto.subtle.decrypt(
      { name: AES_GCM_ALGORITHM, iv: ivBuffer },
      cryptoKey,
      ciphertextBuffer
    );
    return new Uint8Array(plaintext);
  } catch {
    throw new CryptoError("Decryption failed", "DECRYPTION_FAILED");
  }
}

// src/utils/encoding.ts
function hexToBytes2(hex) {
  const cleanHex = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (cleanHex.length % 2 !== 0) {
    throw new Error("Invalid hex string: odd length");
  }
  const bytes = new Uint8Array(cleanHex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    const byte = parseInt(cleanHex.substring(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) {
      throw new Error("Invalid hex string: non-hex character");
    }
    bytes[i] = byte;
  }
  return bytes;
}
function bytesToHex2(bytes) {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}
function concatBytes2(...arrays) {
  const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

// src/aes/seal.ts
var MIN_SEALED_SIZE = AES_IV_SIZE + AES_TAG_SIZE;
async function sealAesGcm(plaintext, key) {
  if (key.length !== AES_KEY_SIZE) {
    throw new CryptoError("Encryption failed", "INVALID_KEY_SIZE");
  }
  const iv = generateIv();
  const ciphertext = await encryptAesGcm(plaintext, key, iv);
  return concatBytes2(iv, ciphertext);
}
async function unsealAesGcm(sealed, key) {
  if (key.length !== AES_KEY_SIZE) {
    throw new CryptoError("Decryption failed", "INVALID_KEY_SIZE");
  }
  if (sealed.length < MIN_SEALED_SIZE) {
    throw new CryptoError("Decryption failed", "DECRYPTION_FAILED");
  }
  const iv = sealed.slice(0, AES_IV_SIZE);
  const ciphertext = sealed.slice(AES_IV_SIZE);
  return decryptAesGcm(ciphertext, key, iv);
}

// src/ipns/create-record.ts
var import_ipns = require("ipns");
var import_keys = require("@libp2p/crypto/keys");
var ed3 = __toESM(require("@noble/ed25519"));
var DEFAULT_LIFETIME_MS = 24 * 60 * 60 * 1e3;
async function createIpnsRecord(ed25519PrivateKey, value, sequenceNumber, lifetimeMs = DEFAULT_LIFETIME_MS) {
  if (ed25519PrivateKey.length !== 32) {
    throw new CryptoError("Invalid Ed25519 private key size", "INVALID_PRIVATE_KEY_SIZE");
  }
  if (sequenceNumber < 0n) {
    throw new CryptoError("Sequence number must be non-negative", "SIGNING_FAILED");
  }
  let libp2pKeyBytes = null;
  try {
    const publicKey = ed3.getPublicKey(ed25519PrivateKey);
    libp2pKeyBytes = new Uint8Array(64);
    libp2pKeyBytes.set(ed25519PrivateKey, 0);
    libp2pKeyBytes.set(publicKey, 32);
    const libp2pPrivateKey = (0, import_keys.privateKeyFromRaw)(libp2pKeyBytes);
    libp2pKeyBytes.fill(0);
    libp2pKeyBytes = null;
    const record = await (0, import_ipns.createIPNSRecord)(libp2pPrivateKey, value, sequenceNumber, lifetimeMs, {
      v1Compatible: true
    });
    return record;
  } catch (error) {
    if (libp2pKeyBytes) {
      libp2pKeyBytes.fill(0);
    }
    if (error instanceof CryptoError) {
      throw error;
    }
    throw new CryptoError("IPNS record creation failed", "SIGNING_FAILED");
  }
}

// src/ipns/derive-name.ts
var import_keys2 = require("@libp2p/crypto/keys");
var import_peer_id = require("@libp2p/peer-id");
var import_base36 = require("multiformats/bases/base36");
async function deriveIpnsName(ed25519PublicKey) {
  if (ed25519PublicKey.length !== ED25519_PUBLIC_KEY_SIZE) {
    throw new CryptoError("Invalid Ed25519 public key size", "INVALID_PUBLIC_KEY_SIZE");
  }
  try {
    const libp2pPublicKey = (0, import_keys2.publicKeyFromRaw)(ed25519PublicKey);
    const peerId = (0, import_peer_id.peerIdFromPublicKey)(libp2pPublicKey);
    return peerId.toCID().toString(import_base36.base36);
  } catch (error) {
    if (error instanceof CryptoError) {
      throw error;
    }
    throw new CryptoError("IPNS name derivation failed", "SIGNING_FAILED");
  }
}

// src/ipns/marshal.ts
var import_ipns2 = require("ipns");
function marshalIpnsRecord(record) {
  return (0, import_ipns2.marshalIPNSRecord)(record);
}
function unmarshalIpnsRecord(bytes) {
  return (0, import_ipns2.unmarshalIPNSRecord)(bytes);
}

// src/ipns/sign-record.ts
var IPNS_SIGNATURE_PREFIX = new Uint8Array([
  105,
  // 'i'
  112,
  // 'p'
  110,
  // 'n'
  115,
  // 's'
  45,
  // '-'
  115,
  // 's'
  105,
  // 'i'
  103,
  // 'g'
  110,
  // 'n'
  97,
  // 'a'
  116,
  // 't'
  117,
  // 'u'
  114,
  // 'r'
  101,
  // 'e'
  58
  // ':'
]);
async function signIpnsData(cborData, privateKey) {
  const dataToSign = new Uint8Array(IPNS_SIGNATURE_PREFIX.length + cborData.length);
  dataToSign.set(IPNS_SIGNATURE_PREFIX, 0);
  dataToSign.set(cborData, IPNS_SIGNATURE_PREFIX.length);
  return signEd25519(dataToSign, privateKey);
}

// src/utils/memory.ts
function clearBytes(data) {
  if (data) {
    data.fill(0);
  }
}
function clearAll(...buffers) {
  for (const buffer of buffers) {
    clearBytes(buffer);
  }
}

// src/folder/metadata.ts
function uint8ArrayToBase64(bytes) {
  const CHUNK_SIZE = 32768;
  let result = "";
  for (let i = 0; i < bytes.length; i += CHUNK_SIZE) {
    const chunk = bytes.subarray(i, Math.min(i + CHUNK_SIZE, bytes.length));
    result += String.fromCharCode(...chunk);
  }
  return btoa(result);
}
function validateFolderMetadata(data) {
  if (typeof data !== "object" || data === null) {
    throw new CryptoError("Invalid metadata format: not an object", "DECRYPTION_FAILED");
  }
  const obj = data;
  if (obj.version !== "v1") {
    throw new CryptoError("Invalid metadata format: unsupported version", "DECRYPTION_FAILED");
  }
  if (!Array.isArray(obj.children)) {
    throw new CryptoError("Invalid metadata format: children must be array", "DECRYPTION_FAILED");
  }
  for (const child of obj.children) {
    if (typeof child !== "object" || child === null) {
      throw new CryptoError("Invalid metadata format: invalid child entry", "DECRYPTION_FAILED");
    }
    const entry = child;
    if (entry.type !== "file" && entry.type !== "folder") {
      throw new CryptoError("Invalid metadata format: unknown child type", "DECRYPTION_FAILED");
    }
    if (typeof entry.id !== "string" || typeof entry.name !== "string") {
      throw new CryptoError("Invalid metadata format: missing id or name", "DECRYPTION_FAILED");
    }
  }
  return data;
}
async function encryptFolderMetadata(metadata, folderKey) {
  const iv = generateIv();
  const plaintext = new TextEncoder().encode(JSON.stringify(metadata));
  const ciphertext = await encryptAesGcm(plaintext, folderKey, iv);
  return {
    iv: bytesToHex2(iv),
    data: uint8ArrayToBase64(ciphertext)
  };
}
async function decryptFolderMetadata(encrypted, folderKey) {
  const iv = hexToBytes2(encrypted.iv);
  const ciphertext = Uint8Array.from(atob(encrypted.data), (c) => c.charCodeAt(0));
  const plaintext = await decryptAesGcm(ciphertext, folderKey, iv);
  const parsed = JSON.parse(new TextDecoder().decode(plaintext));
  return validateFolderMetadata(parsed);
}

// src/index.ts
var CRYPTO_VERSION = "0.2.0";
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  AES_GCM_ALGORITHM,
  AES_IV_SIZE,
  AES_KEY_SIZE,
  AES_TAG_SIZE,
  CRYPTO_VERSION,
  CryptoError,
  ECIES_MIN_CIPHERTEXT_SIZE,
  ED25519_PRIVATE_KEY_SIZE,
  ED25519_PUBLIC_KEY_SIZE,
  ED25519_SIGNATURE_SIZE,
  IPNS_SIGNATURE_PREFIX,
  SECP256K1_PRIVATE_KEY_SIZE,
  SECP256K1_PUBLIC_KEY_SIZE,
  bytesToHex,
  clearAll,
  clearBytes,
  concatBytes,
  createIpnsRecord,
  decryptAesGcm,
  decryptFolderMetadata,
  decryptVaultKeys,
  deriveContextKey,
  deriveIpnsName,
  deriveKey,
  encryptAesGcm,
  encryptFolderMetadata,
  encryptVaultKeys,
  generateEd25519Keypair,
  generateFileKey,
  generateFolderKey,
  generateIv,
  generateRandomBytes,
  hexToBytes,
  initializeVault,
  marshalIpnsRecord,
  sealAesGcm,
  signEd25519,
  signIpnsData,
  unmarshalIpnsRecord,
  unsealAesGcm,
  unwrapKey,
  verifyEd25519,
  wrapKey
});
/*! Bundled license information:

@noble/secp256k1/index.js:
  (*! noble-secp256k1 - MIT License (c) 2019 Paul Miller (paulmillr.com) *)
*/
//# sourceMappingURL=index.js.map