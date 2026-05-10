import forge from "node-forge";

/**
 * Hybrid crypto helper:
 * - Primary: Web Crypto API (RSA-OAEP + AES-GCM)
 * - Fallback: node-forge (for insecure/LAN HTTP origins where crypto.subtle is unavailable)
 */

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function hasWebCrypto() {
  return typeof window !== "undefined" && Boolean(window.crypto?.subtle);
}

function arrayBufferToBase64(buffer) {
  let binary = "";
  const bytes = new Uint8Array(buffer);
  for (let i = 0; i < bytes.byteLength; i += 1) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function base64ToArrayBuffer(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

function uint8ArrayToBinary(bytes) {
  let binary = "";
  for (let i = 0; i < bytes.length; i += 1) {
    binary += String.fromCharCode(bytes[i]);
  }
  return binary;
}

function binaryToUint8Array(binary) {
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function makeFallbackPublicKey(pem) {
  return { __fallback: "forge-public-key", pem };
}

function makeFallbackPrivateKey(pem) {
  return { __fallback: "forge-private-key", pem };
}

function isFallbackPublicKey(value) {
  return Boolean(value && value.__fallback === "forge-public-key");
}

function isFallbackPrivateKey(value) {
  return Boolean(value && value.__fallback === "forge-private-key");
}

function makeFallbackAesKey(rawBase64) {
  return { __fallback: "forge-aes-key", rawBase64 };
}

function isFallbackAesKey(value) {
  return Boolean(value && value.__fallback === "forge-aes-key");
}

function looksLikePemText(rawText) {
  return rawText.includes("-----BEGIN PUBLIC KEY-----") || rawText.includes("-----BEGIN RSA PUBLIC KEY-----");
}

export async function generateRsaKeyPair() {
  if (hasWebCrypto()) {
    return window.crypto.subtle.generateKey(
      {
        name: "RSA-OAEP",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256"
      },
      true,
      ["encrypt", "decrypt"]
    );
  }

  const keyPair = forge.pki.rsa.generateKeyPair({ bits: 2048, e: 0x10001 });
  return {
    publicKey: makeFallbackPublicKey(forge.pki.publicKeyToPem(keyPair.publicKey)),
    privateKey: makeFallbackPrivateKey(forge.pki.privateKeyToPem(keyPair.privateKey))
  };
}

export async function exportPublicKeyToBase64(publicKey) {
  if (isFallbackPublicKey(publicKey)) {
    return btoa(publicKey.pem);
  }
  const spki = await window.crypto.subtle.exportKey("spki", publicKey);
  return arrayBufferToBase64(spki);
}

export async function importPublicKeyFromBase64(base64Key) {
  const decodedText = atob(base64Key);
  if (!hasWebCrypto() || looksLikePemText(decodedText)) {
    return makeFallbackPublicKey(decodedText);
  }

  return window.crypto.subtle.importKey(
    "spki",
    base64ToArrayBuffer(base64Key),
    { name: "RSA-OAEP", hash: "SHA-256" },
    true,
    ["encrypt"]
  );
}

export async function exportKeyPairToJwk(keyPair) {
  if (isFallbackPublicKey(keyPair.publicKey) && isFallbackPrivateKey(keyPair.privateKey)) {
    return {
      publicJwk: { __fallback: "forge-public-key", pem: keyPair.publicKey.pem },
      privateJwk: { __fallback: "forge-private-key", pem: keyPair.privateKey.pem }
    };
  }

  const [publicJwk, privateJwk] = await Promise.all([
    window.crypto.subtle.exportKey("jwk", keyPair.publicKey),
    window.crypto.subtle.exportKey("jwk", keyPair.privateKey)
  ]);
  return { publicJwk, privateJwk };
}

export async function importKeyPairFromJwk(publicJwk, privateJwk) {
  if (publicJwk?.__fallback === "forge-public-key" && privateJwk?.__fallback === "forge-private-key") {
    return {
      publicKey: makeFallbackPublicKey(publicJwk.pem),
      privateKey: makeFallbackPrivateKey(privateJwk.pem)
    };
  }

  const [publicKey, privateKey] = await Promise.all([
    window.crypto.subtle.importKey(
      "jwk",
      publicJwk,
      { name: "RSA-OAEP", hash: "SHA-256" },
      true,
      ["encrypt"]
    ),
    window.crypto.subtle.importKey(
      "jwk",
      privateJwk,
      { name: "RSA-OAEP", hash: "SHA-256" },
      true,
      ["decrypt"]
    )
  ]);
  return { publicKey, privateKey };
}

export async function encryptWithPublicKey(publicKey, plaintext) {
  if (isFallbackPublicKey(publicKey)) {
    const rsaPublicKey = forge.pki.publicKeyFromPem(publicKey.pem);
    const encryptedBytes = rsaPublicKey.encrypt(forge.util.encodeUtf8(plaintext), "RSA-OAEP", {
      md: forge.md.sha256.create(),
      mgf1: { md: forge.md.sha256.create() }
    });
    return forge.util.encode64(encryptedBytes);
  }

  const encrypted = await window.crypto.subtle.encrypt(
    { name: "RSA-OAEP" },
    publicKey,
    encoder.encode(plaintext)
  );
  return arrayBufferToBase64(encrypted);
}

export async function decryptWithPrivateKey(privateKey, encryptedBase64) {
  if (isFallbackPrivateKey(privateKey)) {
    const rsaPrivateKey = forge.pki.privateKeyFromPem(privateKey.pem);
    const decryptedBytes = rsaPrivateKey.decrypt(forge.util.decode64(encryptedBase64), "RSA-OAEP", {
      md: forge.md.sha256.create(),
      mgf1: { md: forge.md.sha256.create() }
    });
    return forge.util.decodeUtf8(decryptedBytes);
  }

  const decrypted = await window.crypto.subtle.decrypt(
    { name: "RSA-OAEP" },
    privateKey,
    base64ToArrayBuffer(encryptedBase64)
  );
  return decoder.decode(decrypted);
}

export async function generateAesKey() {
  if (hasWebCrypto()) {
    return window.crypto.subtle.generateKey(
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt", "decrypt"]
    );
  }
  return makeFallbackAesKey(forge.util.encode64(forge.random.getBytesSync(32)));
}

export async function exportAesRawToBase64(aesKey) {
  if (isFallbackAesKey(aesKey)) {
    return aesKey.rawBase64;
  }
  const raw = await window.crypto.subtle.exportKey("raw", aesKey);
  return arrayBufferToBase64(raw);
}

export async function importAesRawFromBase64(rawBase64) {
  if (!hasWebCrypto()) {
    return makeFallbackAesKey(rawBase64);
  }
  return window.crypto.subtle.importKey(
    "raw",
    base64ToArrayBuffer(rawBase64),
    "AES-GCM",
    false,
    ["encrypt", "decrypt"]
  );
}

export async function aesEncrypt(aesKey, plaintext) {
  if (isFallbackAesKey(aesKey)) {
    const keyBytes = forge.util.decode64(aesKey.rawBase64);
    const ivBytes = forge.random.getBytesSync(12);

    const cipher = forge.cipher.createCipher("AES-GCM", keyBytes);
    cipher.start({ iv: ivBytes, tagLength: 128 });
    cipher.update(forge.util.createBuffer(forge.util.encodeUtf8(plaintext)));
    if (!cipher.finish()) {
      throw new Error("Failed to encrypt payload");
    }

    // Match WebCrypto output format: ciphertext + auth tag
    const combined = cipher.output.getBytes() + cipher.mode.tag.getBytes();
    return {
      iv: forge.util.encode64(ivBytes),
      ciphertext: forge.util.encode64(combined)
    };
  }

  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await window.crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    aesKey,
    encoder.encode(plaintext)
  );
  return {
    iv: arrayBufferToBase64(iv.buffer),
    ciphertext: arrayBufferToBase64(encrypted)
  };
}

export async function aesDecrypt(aesKey, ivBase64, ciphertextBase64) {
  if (isFallbackAesKey(aesKey)) {
    const keyBytes = forge.util.decode64(aesKey.rawBase64);
    const ivBytes = forge.util.decode64(ivBase64);
    const combinedBytes = forge.util.decode64(ciphertextBase64);

    if (combinedBytes.length < 16) {
      throw new Error("Invalid encrypted payload");
    }

    const dataBytes = combinedBytes.slice(0, -16);
    const tagBytes = combinedBytes.slice(-16);

    const decipher = forge.cipher.createDecipher("AES-GCM", keyBytes);
    decipher.start({
      iv: ivBytes,
      tagLength: 128,
      tag: forge.util.createBuffer(tagBytes)
    });
    decipher.update(forge.util.createBuffer(dataBytes));
    const success = decipher.finish();
    if (!success) {
      throw new Error("Failed to decrypt payload");
    }
    return forge.util.decodeUtf8(decipher.output.getBytes());
  }

  const iv = new Uint8Array(base64ToArrayBuffer(ivBase64));
  const decrypted = await window.crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    aesKey,
    base64ToArrayBuffer(ciphertextBase64)
  );
  return decoder.decode(decrypted);
}

export async function aesEncryptBytes(aesKey, bytesLike) {
  const sourceBytes = bytesLike instanceof Uint8Array ? bytesLike : new Uint8Array(bytesLike);
  if (isFallbackAesKey(aesKey)) {
    const keyBytes = forge.util.decode64(aesKey.rawBase64);
    const ivBytes = forge.random.getBytesSync(12);

    const cipher = forge.cipher.createCipher("AES-GCM", keyBytes);
    cipher.start({ iv: ivBytes, tagLength: 128 });
    cipher.update(forge.util.createBuffer(uint8ArrayToBinary(sourceBytes)));
    if (!cipher.finish()) {
      throw new Error("Failed to encrypt file payload");
    }

    const combined = cipher.output.getBytes() + cipher.mode.tag.getBytes();
    return {
      iv: forge.util.encode64(ivBytes),
      ciphertextBytes: binaryToUint8Array(combined)
    };
  }

  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await window.crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    aesKey,
    sourceBytes
  );
  return {
    iv: arrayBufferToBase64(iv.buffer),
    ciphertextBytes: new Uint8Array(encrypted)
  };
}

export async function aesDecryptBytes(aesKey, ivBase64, encryptedBytesLike) {
  const encryptedBytes =
    encryptedBytesLike instanceof Uint8Array ? encryptedBytesLike : new Uint8Array(encryptedBytesLike);

  if (isFallbackAesKey(aesKey)) {
    const keyBytes = forge.util.decode64(aesKey.rawBase64);
    const ivBytes = forge.util.decode64(ivBase64);
    const combinedBytes = uint8ArrayToBinary(encryptedBytes);

    if (combinedBytes.length < 16) {
      throw new Error("Invalid encrypted file payload");
    }

    const dataBytes = combinedBytes.slice(0, -16);
    const tagBytes = combinedBytes.slice(-16);

    const decipher = forge.cipher.createDecipher("AES-GCM", keyBytes);
    decipher.start({
      iv: ivBytes,
      tagLength: 128,
      tag: forge.util.createBuffer(tagBytes)
    });
    decipher.update(forge.util.createBuffer(dataBytes));
    const success = decipher.finish();
    if (!success) {
      throw new Error("Failed to decrypt file payload");
    }
    return binaryToUint8Array(decipher.output.getBytes());
  }

  const iv = new Uint8Array(base64ToArrayBuffer(ivBase64));
  const decrypted = await window.crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    aesKey,
    encryptedBytes
  );
  return new Uint8Array(decrypted);
}
