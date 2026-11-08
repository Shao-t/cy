/* CIPHER v4 8+1 recovery phrase codec (88 random bits + 11-bit checksum). */
(function (global) {
  'use strict';

  const ENTROPY_BYTES = 11;
  const DATA_WORDS = 8;
  const TOTAL_WORDS = 9;
  const WORD_BITS = 11;
  const WORDLIST_SIZE = 1 << WORD_BITS;
  const DOMAIN = new TextEncoder().encode('CIPHER4-RECOVERY\0');

  class RecoveryPhraseError extends Error {
    constructor(code, message) {
      super(message);
      this.name = 'RecoveryPhraseError';
      this.code = code;
    }
  }

  function fail(code, message) {
    throw new RecoveryPhraseError(code, message);
  }

  function wordlist() {
    const words = global.CIPHER_BIP39_EN;
    if (!Array.isArray(words) || words.length !== WORDLIST_SIZE) {
      fail('WORDLIST_UNAVAILABLE', 'Recovery wordlist is unavailable');
    }
    if (new Set(words).size !== WORDLIST_SIZE || words.some(word => typeof word !== 'string' || !word)) {
      fail('INVALID_WORDLIST', 'Recovery wordlist is invalid');
    }
    return words;
  }

  function assertReady() {
    wordlist();
    if (!global.crypto || typeof global.crypto.getRandomValues !== 'function' ||
        !global.crypto.subtle || typeof global.crypto.subtle.digest !== 'function') {
      fail('CRYPTO_UNAVAILABLE', 'Secure random generation is unavailable');
    }
  }

  function asEntropy(value) {
    const bytes = value instanceof Uint8Array ? value : new Uint8Array(value);
    if (bytes.byteLength !== ENTROPY_BYTES) fail('INVALID_ENTROPY', 'Entropy must be exactly 88 bits');
    return bytes;
  }

  function entropyToIndices(value) {
    const entropy = asEntropy(value);
    const indices = [];
    let accumulator = 0;
    let bits = 0;
    for (const byte of entropy) {
      accumulator = (accumulator << 8) | byte;
      bits += 8;
      while (bits >= WORD_BITS) {
        bits -= WORD_BITS;
        indices.push((accumulator >>> bits) & (WORDLIST_SIZE - 1));
        accumulator &= bits === 0 ? 0 : (1 << bits) - 1;
      }
    }
    if (indices.length !== DATA_WORDS || bits !== 0) fail('INVALID_ENTROPY', 'Entropy encoding failed');
    return indices;
  }

  function indicesToEntropy(indices) {
    if (!Array.isArray(indices) || indices.length !== DATA_WORDS ||
        indices.some(index => !Number.isInteger(index) || index < 0 || index >= WORDLIST_SIZE)) {
      fail('INVALID_PHRASE', 'Recovery phrase data is invalid');
    }
    const output = new Uint8Array(ENTROPY_BYTES);
    let accumulator = 0;
    let bits = 0;
    let offset = 0;
    for (const index of indices) {
      accumulator = (accumulator << WORD_BITS) | index;
      bits += WORD_BITS;
      while (bits >= 8) {
        bits -= 8;
        output[offset++] = (accumulator >>> bits) & 0xFF;
        accumulator &= bits === 0 ? 0 : (1 << bits) - 1;
      }
    }
    if (offset !== ENTROPY_BYTES || bits !== 0) fail('INVALID_PHRASE', 'Recovery phrase decoding failed');
    return output;
  }

  async function checksumIndex(entropy) {
    entropy = asEntropy(entropy);
    const input = new Uint8Array(DOMAIN.byteLength + entropy.byteLength);
    input.set(DOMAIN);
    input.set(entropy, DOMAIN.byteLength);
    const digest = new Uint8Array(await global.crypto.subtle.digest('SHA-256', input));
    input.fill(0);
    const index = (digest[0] << 3) | (digest[1] >>> 5);
    digest.fill(0);
    return index;
  }

  function splitPhrase(value) {
    if (typeof value !== 'string') return [];
    const normalized = value.normalize('NFC').trim();
    if (!normalized) return [];
    const spaced = normalized.split(/\s+/u);
    if (spaced.length === 1) {
      const characters = Array.from(spaced[0]);
      if (characters.length === TOTAL_WORDS) return characters;
    }
    return spaced;
  }

  function normalizePhrase(value) {
    return splitPhrase(value).join(' ');
  }

  async function phraseFromEntropy(value) {
    assertReady();
    const entropy = asEntropy(value).slice();
    try {
      const words = wordlist();
      const indices = entropyToIndices(entropy);
      indices.push(await checksumIndex(entropy));
      return indices.map(index => words[index]).join(' ');
    } finally {
      entropy.fill(0);
    }
  }

  async function generate() {
    assertReady();
    const entropy = global.crypto.getRandomValues(new Uint8Array(ENTROPY_BYTES));
    try {
      return await phraseFromEntropy(entropy);
    } finally {
      entropy.fill(0);
    }
  }

  async function inspect(value) {
    assertReady();
    const words = splitPhrase(value);
    if (words.length !== TOTAL_WORDS) {
      return { valid: false, code: 'INVALID_WORD_COUNT', message: '復原詞必須是 8 個隨機詞加 1 個校驗詞' };
    }
    const list = wordlist();
    const lookup = new Map(list.map((word, index) => [word, index]));
    const indices = words.map(word => lookup.get(word));
    if (indices.some(index => index === undefined)) {
      return { valid: false, code: 'UNKNOWN_WORD', message: '復原詞包含不在詞庫中的字' };
    }
    const entropy = indicesToEntropy(indices.slice(0, DATA_WORDS));
    try {
      if (indices[DATA_WORDS] !== await checksumIndex(entropy)) {
        return { valid: false, code: 'CHECKSUM_MISMATCH', message: '校驗詞不正確，復原詞可能抄錯或順序錯誤' };
      }
    } finally {
      entropy.fill(0);
    }
    return { valid: true, code: 'OK', message: '88-bit 中等保護', normalized: words.join(' ') };
  }

  async function requireValid(value) {
    const result = await inspect(value);
    if (!result.valid) fail(result.code, result.message);
    return result.normalized;
  }

  global.CipherRecoveryPhrase = Object.freeze({
    constants: Object.freeze({ entropyBits: 88, dataWords: DATA_WORDS, totalWords: TOTAL_WORDS }),
    RecoveryPhraseError,
    assertReady,
    generate,
    inspect,
    requireValid,
    normalizePhrase,
    phraseFromEntropy
  });
})(typeof window !== 'undefined' ? window : globalThis);
