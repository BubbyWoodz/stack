/* Stack crypto core — mirrors Mneme's encryption model.
 *
 * Key hierarchy:
 *   12-word BIP39 mnemonic (128-bit entropy)
 *     -> seed = PBKDF2-HMAC-SHA512("mnemonic", 2048 iters, 64 bytes)   [BIP39]
 *       -> HKDF-SHA256(salt="stack-v1", info="data")     -> data_key (32B)
 *       -> HKDF-SHA256(salt="stack-v1", info="identity") -> identity_key (32B)
 *            -> owner_id = base64url(sha256(identity_key))  ("the account IS the phrase")
 *
 * Vault encryption: XChaCha20-Poly1305, random 24-byte nonce per encryption.
 * Envelope (version-prefixed from day one):
 *     [0x01][24-byte nonce][ciphertext + 16-byte Poly1305 tag]
 *
 * Device password seal (opt-in): the 64-byte seed is sealed with
 * XChaCha20-Poly1305 under a key from Argon2id(password, 128 MiB, t=2, p=1).
 * Stored in localStorage. Wrong password -> AEAD tag failure.
 * Caveat: offline-brute-forceable if the device is stolen; KDF cost +
 * password strength are the only protection.
 *
 * Primitives: @noble/hashes + @noble/ciphers (audited, sync, no WASM).
 */
import { argon2id } from '../vendor/noble-hashes/argon2.js';
import { hkdf } from '../vendor/noble-hashes/hkdf.js';
import { pbkdf2 } from '../vendor/noble-hashes/pbkdf2.js';
import { sha256, sha512 } from '../vendor/noble-hashes/sha2.js';
import {
  randomBytes,
  utf8ToBytes,
  bytesToHex,
  concatBytes,
} from '../vendor/noble-hashes/utils.js';
import { xchacha20poly1305 } from '../vendor/noble-ciphers/chacha.js';
import { WORDLIST } from './wordlist.js';

export const VAULT_VERSION = 0x01;
const NONCE_LEN = 24;
const HKDF_SALT = 'stack-v1';

/* ---------------- base64 helpers ---------------- */

export function b64encode(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i += 0x8000) {
    s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  }
  return btoa(s);
}

export function b64decode(b64) {
  const s = atob(b64);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

export function b64urlencode(bytes) {
  return b64encode(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/* ---------------- BIP39 mnemonic ---------------- */

function bitsToWords(entropy) {
  // entropy: 16 bytes -> 12 words (128 bits + 4-bit checksum)
  const hash = sha256(entropy);
  const bits = [];
  for (const b of entropy) for (let i = 7; i >= 0; i--) bits.push((b >> i) & 1);
  for (let i = 7; i >= 4; i--) bits.push((hash[0] >> i) & 1);
  const words = [];
  for (let i = 0; i < 12; i++) {
    let idx = 0;
    for (let j = 0; j < 11; j++) idx = (idx << 1) | bits[i * 11 + j];
    words.push(WORDLIST[idx]);
  }
  return words;
}

export function generateMnemonic() {
  return bitsToWords(randomBytes(16)).join(' ');
}

function normalizeMnemonic(mnemonic) {
  return mnemonic.toLowerCase().trim().split(/\s+/).join(' ');
}

export function validateMnemonic(mnemonic) {
  const words = normalizeMnemonic(mnemonic).split(' ');
  if (words.length !== 12) return false;
  const idx = [];
  for (const w of words) {
    const i = WORDLIST.indexOf(w);
    if (i === -1) return false;
    idx.push(i);
  }
  const bits = [];
  for (const i of idx) for (let j = 10; j >= 0; j--) bits.push((i >> j) & 1);
  const entropy = new Uint8Array(16);
  for (let i = 0; i < 16; i++) {
    let b = 0;
    for (let j = 0; j < 8; j++) b = (b << 1) | bits[i * 8 + j];
    entropy[i] = b;
  }
  const hash = sha256(entropy);
  for (let i = 0; i < 4; i++) {
    if (bits[128 + i] !== ((hash[0] >> (7 - i)) & 1)) return false;
  }
  return true;
}

/* ---------------- key derivation ---------------- */

export function mnemonicToSeed(mnemonic) {
  // BIP39 seed: PBKDF2-HMAC-SHA512, salt "mnemonic", 2048 rounds, 64 bytes
  return pbkdf2(sha512, normalizeMnemonic(mnemonic), 'mnemonic', {
    c: 2048,
    dkLen: 64,
  });
}

export function deriveKeys(seed) {
  const salt = utf8ToBytes(HKDF_SALT);
  const dataKey = hkdf(sha256, seed, salt, utf8ToBytes('data'), 32);
  const identityKey = hkdf(sha256, seed, salt, utf8ToBytes('identity'), 32);
  const ownerId = b64urlencode(sha256(identityKey));
  return { dataKey, identityKey, ownerId };
}

/* ---------------- vault AEAD ---------------- */

export function sealVault(dataKey, plaintextBytes) {
  const nonce = randomBytes(NONCE_LEN);
  const cipher = xchacha20poly1305(dataKey, nonce);
  const ct = cipher.encrypt(plaintextBytes);
  return {
    nonceB64: b64encode(nonce),
    // version-prefixed envelope
    ctB64: b64encode(concatBytes(new Uint8Array([VAULT_VERSION]), ct)),
  };
}

export function openVault(dataKey, nonceB64, ctB64) {
  const raw = b64decode(ctB64);
  if (raw.length < 1 || raw[0] !== VAULT_VERSION) {
    throw new Error('unsupported vault version');
  }
  const nonce = b64decode(nonceB64);
  if (nonce.length !== NONCE_LEN) throw new Error('bad nonce');
  const cipher = xchacha20poly1305(dataKey, nonce);
  return cipher.decrypt(raw.subarray(1)); // throws on tag mismatch (wrong code)
}

export function encodeVaultState(state) {
  return utf8ToBytes(JSON.stringify(state));
}

export function decodeVaultState(bytes) {
  return JSON.parse(new TextDecoder().decode(bytes));
}

/* ---------------- device password seal ---------------- */

const SEAL_M = 131072; // 128 MiB (KiB units)
const SEAL_T = 2;
const SEAL_P = 1;

export function createDeviceSeal(password, seedBytes, onProgress) {
  const salt = randomBytes(16);
  const key = argon2id(utf8ToBytes(password), salt, {
    m: SEAL_M,
    t: SEAL_T,
    p: SEAL_P,
    dkLen: 32,
    onProgress,
  });
  const nonce = randomBytes(NONCE_LEN);
  const ct = xchacha20poly1305(key, nonce).encrypt(seedBytes);
  const blob = {
    v: 1,
    kdf: 'argon2id',
    m: SEAL_M,
    t: SEAL_T,
    p: SEAL_P,
    salt: b64encode(salt),
    nonce: b64encode(nonce),
    ct: b64encode(concatBytes(new Uint8Array([VAULT_VERSION]), ct)),
  };
  key.fill(0);
  return JSON.stringify(blob);
}

export function openDeviceSeal(password, sealJson, onProgress) {
  const blob = JSON.parse(sealJson);
  if (blob.v !== 1 || blob.ct === undefined) throw new Error('bad seal');
  const raw = b64decode(blob.ct);
  if (raw[0] !== VAULT_VERSION) throw new Error('unsupported seal version');
  const key = argon2id(utf8ToBytes(password), b64decode(blob.salt), {
    m: blob.m || SEAL_M,
    t: blob.t || SEAL_T,
    p: blob.p || SEAL_P,
    dkLen: 32,
    onProgress,
  });
  try {
    return xchacha20poly1305(key, b64decode(blob.nonce)).decrypt(raw.subarray(1));
  } finally {
    key.fill(0);
  }
}

/* ---------------- misc ---------------- */

export function randomId() {
  // 128-bit random hex IDs — server can't infer chronology from them
  return bytesToHex(randomBytes(16));
}

export function wipe(bytes) {
  if (bytes) bytes.fill(0);
}
