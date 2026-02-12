function getRandomBytes(n) {
  let array = new Uint8Array(n);
  // Browser & Node
  if (typeof globalThis.crypto !== "undefined") {
    // Supported
    globalThis.crypto.getRandomValues(array);
  } else {
    // fallback
    for (let i = 0; i < n; i++) {
      array[i] = (Math.random() * 4294967296) >>> 0;
    }
  }
  return array;
}

export { getRandomBytes };
