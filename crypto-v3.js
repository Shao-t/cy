/* CIPHER v3 authenticated, length-padded envelope codec. */
(function (global) {
  'use strict';

  const MAGIC = new Uint8Array([0x43, 0x49, 0x50, 0x48]); // CIPH
  const LEGACY_MAGIC = new Uint8Array([0xAE, 0x53, 0x47, 0x01]);
  const FORMAT_VERSION = 3;
  const TYPE_TEXT = 1;
  const TYPE_FILE = 2;
  const KDF_ARGON2ID = 1;
  const CIPHER_AES_256_GCM = 1;
  const ARGON2_VERSION = 0x13;
  const ARGON_MEMORY_KIB = 19456;
  const ARGON_ITERATIONS = 2;
  const ARGON_PARALLELISM = 1;
  const KEY_BYTES = 32;
  const SALT_BYTES = 16;
  const NONCE_BYTES = 12;
  const TAG_BYTES = 16;
  const PADDING_BLOCK_BYTES = 4096;
  const COMMON_HEADER_BYTES = 40;
  const FILE_BASE_BYTES = 56;
  const FILE_CHUNK_BYTES = 8 * 1024 * 1024;
  const MAX_METADATA_JSON_BYTES = PADDING_BLOCK_BYTES - 4;
  const TEXT_PREFIX = 'CIPHER3:';

  const encoder = new TextEncoder();
  const decoder = new TextDecoder('utf-8', { fatal: true });

  class CipherV3Error extends Error {
    constructor(code, message) {
      super(message);
      this.name = 'CipherV3Error';
      this.code = code;
    }
  }

  function fail(code, message) {
    throw new CipherV3Error(code, message);
  }

  function asBytes(value) {
    if (value instanceof Uint8Array) return value;
    if (value instanceof ArrayBuffer ||
        (value && Object.prototype.toString.call(value) === '[object ArrayBuffer]')) {
      return new Uint8Array(value);
    }
    if (ArrayBuffer.isView(value)) {
      return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
    }
    fail('INVALID_INPUT', 'Expected binary data');
  }

  function concatBytes(...values) {
    const arrays = values.map(asBytes);
    const total = arrays.reduce((sum, item) => sum + item.byteLength, 0);
    const output = new Uint8Array(total);
    let offset = 0;
    for (const item of arrays) {
      output.set(item, offset);
      offset += item.byteLength;
    }
    return output;
  }

  function equalBytes(a, b) {
    if (a.byteLength !== b.byteLength) return false;
    let different = 0;
    for (let i = 0; i < a.byteLength; i++) different |= a[i] ^ b[i];
    return different === 0;
  }

  function u32be(value) {
    if (!Number.isSafeInteger(value) || value < 0 || value > 0xFFFFFFFF) {
      fail('INVALID_LENGTH', 'Value does not fit in uint32');
    }
    const output = new Uint8Array(4);
    new DataView(output.buffer).setUint32(0, value, false);
    return output;
  }

  function readU32be(bytes, offset) {
    if (offset < 0 || offset + 4 > bytes.byteLength) {
      fail('TRUNCATED', 'Unexpected end of encrypted data');
    }
    return new DataView(bytes.buffer, bytes.byteOffset + offset, 4).getUint32(0, false);
  }

  function u64be(value) {
    if (!Number.isSafeInteger(value) || value < 0) {
      fail('INVALID_LENGTH', 'File size is not safely representable');
    }
    const output = new Uint8Array(8);
    const view = new DataView(output.buffer);
    view.setUint32(0, Math.floor(value / 0x100000000), false);
    view.setUint32(4, value >>> 0, false);
    return output;
  }

  function readU64be(bytes, offset) {
    const high = readU32be(bytes, offset);
    const low = readU32be(bytes, offset + 4);
    const value = high * 0x100000000 + low;
    if (!Number.isSafeInteger(value)) fail('INVALID_LENGTH', 'File size is too large');
    return value;
  }

  function randomBytes(length) {
    return crypto.getRandomValues(new Uint8Array(length));
  }

  function paddedLength(length) {
    if (!Number.isSafeInteger(length) || length < 0) fail('INVALID_LENGTH', 'Invalid padding length');
    const blocks = Math.max(1, Math.ceil(length / PADDING_BLOCK_BYTES));
    const result = blocks * PADDING_BLOCK_BYTES;
    if (!Number.isSafeInteger(result)) fail('INVALID_LENGTH', 'Padded data is too large');
    return result;
  }

  function padPayload(value) {
    const bytes = asBytes(value);
    if (bytes.byteLength > 0xFFFFFFFF) fail('INVALID_LENGTH', 'Payload is too large');
    const output = new Uint8Array(paddedLength(4 + bytes.byteLength));
    new DataView(output.buffer).setUint32(0, bytes.byteLength, false);
    output.set(bytes, 4);
    return output;
  }

  function unpadPayload(value) {
    const bytes = asBytes(value);
    if (bytes.byteLength < PADDING_BLOCK_BYTES || bytes.byteLength % PADDING_BLOCK_BYTES !== 0) {
      fail('INVALID_PADDING', 'Padded payload has an invalid size');
    }
    const length = readU32be(bytes, 0);
    if (length > bytes.byteLength - 4) fail('INVALID_PADDING', 'Padded payload length is invalid');
    for (let index = 4 + length; index < bytes.byteLength; index++) {
      if (bytes[index] !== 0) fail('INVALID_PADDING', 'Padded payload contains invalid data');
    }
    return bytes.slice(4, 4 + length);
  }

  function buildCommonHeader(type, salt) {
    salt = asBytes(salt);
    if (salt.byteLength !== SALT_BYTES) fail('INVALID_SALT', 'Invalid salt length');
    if (type !== TYPE_TEXT && type !== TYPE_FILE) fail('INVALID_TYPE', 'Unknown content type');

    const output = new Uint8Array(COMMON_HEADER_BYTES);
    const view = new DataView(output.buffer);
    output.set(MAGIC, 0);
    output[4] = FORMAT_VERSION;
    output[5] = type;
    output[6] = KDF_ARGON2ID;
    output[7] = CIPHER_AES_256_GCM;
    output[8] = 0; // flags
    output[9] = ARGON2_VERSION;
    view.setUint32(10, ARGON_MEMORY_KIB, false);
    view.setUint32(14, ARGON_ITERATIONS, false);
    output[18] = ARGON_PARALLELISM;
    output[19] = SALT_BYTES;
    view.setUint32(20, PADDING_BLOCK_BYTES, false);
    output.set(salt, 24);
    return output;
  }

  function parseCommonHeader(bytes, expectedType) {
    bytes = asBytes(bytes);
    if (bytes.byteLength < COMMON_HEADER_BYTES) fail('TRUNCATED', 'Encrypted data is too short');
    if (!equalBytes(bytes.subarray(0, 4), MAGIC)) fail('INVALID_MAGIC', 'Not a CIPHER v3 envelope');
    if (bytes[4] !== FORMAT_VERSION) fail('UNSUPPORTED_VERSION', 'Unsupported CIPHER version');
    if (bytes[5] !== expectedType) fail('INVALID_TYPE', 'Encrypted content type does not match');
    if (bytes[6] !== KDF_ARGON2ID || bytes[7] !== CIPHER_AES_256_GCM || bytes[8] !== 0) {
      fail('UNSUPPORTED_ALGORITHM', 'Unsupported encryption algorithm');
    }
    if (bytes[9] !== ARGON2_VERSION ||
        readU32be(bytes, 10) !== ARGON_MEMORY_KIB ||
        readU32be(bytes, 14) !== ARGON_ITERATIONS ||
        bytes[18] !== ARGON_PARALLELISM ||
        bytes[19] !== SALT_BYTES ||
        readU32be(bytes, 20) !== PADDING_BLOCK_BYTES) {
      fail('UNSUPPORTED_KDF_PARAMS', 'Unsupported Argon2id parameters');
    }
    return {
      header: bytes.slice(0, COMMON_HEADER_BYTES),
      salt: bytes.slice(24, 24 + SALT_BYTES)
    };
  }

  function assertArgonAvailable() {
    if (!global.hashwasm || typeof global.hashwasm.argon2id !== 'function') {
      fail('ARGON2_UNAVAILABLE', 'Argon2id module is unavailable');
    }
    if (!global.crypto || !global.crypto.subtle) {
      fail('WEBCRYPTO_UNAVAILABLE', 'Web Crypto is unavailable');
    }
  }

  async function deriveAesKey(password, salt) {
    assertArgonAvailable();
    if (typeof password !== 'string') fail('INVALID_PASSWORD', 'Password must be text');
    salt = asBytes(salt);
    if (salt.byteLength !== SALT_BYTES) fail('INVALID_SALT', 'Invalid salt length');

    const passwordBytes = encoder.encode(password.normalize('NFC'));
    let rawKey;
    try {
      rawKey = await global.hashwasm.argon2id({
        password: passwordBytes,
        salt,
        parallelism: ARGON_PARALLELISM,
        iterations: ARGON_ITERATIONS,
        memorySize: ARGON_MEMORY_KIB,
        hashLength: KEY_BYTES,
        outputType: 'binary'
      });
      rawKey = asBytes(rawKey);
      if (rawKey.byteLength !== KEY_BYTES) fail('ARGON2_FAILED', 'Argon2id returned an invalid key');
      return await crypto.subtle.importKey(
        'raw', rawKey, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']
      );
    } finally {
      passwordBytes.fill(0);
      if (rawKey instanceof Uint8Array) rawKey.fill(0);
    }
  }

  function bytesToBase64Url(bytes) {
    bytes = asBytes(bytes);
    let binary = '';
    const block = 0x8000;
    for (let offset = 0; offset < bytes.byteLength; offset += block) {
      binary += String.fromCharCode(...bytes.subarray(offset, offset + block));
    }
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
  }

  function base64UrlToBytes(value) {
    if (typeof value !== 'string' || value.length === 0 ||
        !/^[A-Za-z0-9_-]+$/.test(value) || value.length % 4 === 1) {
      fail('INVALID_ENCODING', 'Invalid Base64URL ciphertext');
    }
    const padded = value.replace(/-/g, '+').replace(/_/g, '/') +
      '='.repeat((4 - value.length % 4) % 4);
    let binary;
    try {
      binary = atob(padded);
    } catch (error) {
      fail('INVALID_ENCODING', 'Invalid Base64URL ciphertext');
    }
    const output = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) output[i] = binary.charCodeAt(i);
    return output;
  }

  // 只比較前綴、僅限 ASCII 大小寫不敏感；Base64URL 本體仍區分大小寫，不會被改動。
  function hasPrefixIgnoreCase(value, prefix) {
    if (typeof value !== 'string' || value.length < prefix.length) return false;
    for (let i = 0; i < prefix.length; i++) {
      let code = value.charCodeAt(i);
      if (code >= 97 && code <= 122) code -= 32;
      if (code !== prefix.charCodeAt(i)) return false;
    }
    return true;
  }

  function looksLikeV3Text(value) {
    return typeof value === 'string' && hasPrefixIgnoreCase(value.trim(), TEXT_PREFIX);
  }

  function looksLikeLegacyText(value) {
    if (typeof value !== 'string') return false;
    const trimmed = value.trim();
    if (hasPrefixIgnoreCase(trimmed, 'CIPHER2:')) return true;
    const compact = value.replace(/\s+/g, '');
    return compact.length >= 80 && /^[0-9a-fA-F]+$/.test(compact);
  }

  async function encryptText(plaintext, password) {
    if (typeof plaintext !== 'string') fail('INVALID_INPUT', 'Plaintext must be text');
    const salt = randomBytes(SALT_BYTES);
    const common = buildCommonHeader(TYPE_TEXT, salt);
    const nonce = randomBytes(NONCE_BYTES);
    const sourceBytes = encoder.encode(plaintext);
    const plainBytes = padPayload(sourceBytes);
    sourceBytes.fill(0);
    const cipherLength = plainBytes.byteLength + TAG_BYTES;
    const recordHeader = concatBytes(new Uint8Array([NONCE_BYTES]), nonce, u32be(cipherLength));
    const aad = concatBytes(common, recordHeader);
    const key = await deriveAesKey(password, salt);
    try {
      const encrypted = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength: 128 },
        key,
        plainBytes
      );
      return TEXT_PREFIX + bytesToBase64Url(concatBytes(aad, encrypted));
    } finally {
      plainBytes.fill(0);
    }
  }

  async function decryptText(ciphertext, password) {
    if (typeof ciphertext !== 'string') fail('INVALID_INPUT', 'Ciphertext must be text');
    const trimmed = ciphertext.trim();
    if (!hasPrefixIgnoreCase(trimmed, TEXT_PREFIX)) {
      if (looksLikeLegacyText(trimmed)) fail('LEGACY_FORMAT', 'Legacy PBKDF2 ciphertext is not supported');
      fail('INVALID_PREFIX', 'Not a CIPHER v3 ciphertext');
    }

    const envelope = base64UrlToBytes(trimmed.slice(TEXT_PREFIX.length));
    const parsed = parseCommonHeader(envelope, TYPE_TEXT);
    let offset = COMMON_HEADER_BYTES;
    if (offset >= envelope.byteLength || envelope[offset] !== NONCE_BYTES) {
      fail('INVALID_NONCE', 'Invalid nonce length');
    }
    offset += 1;
    if (offset + NONCE_BYTES + 4 > envelope.byteLength) fail('TRUNCATED', 'Ciphertext is truncated');
    const nonce = envelope.slice(offset, offset + NONCE_BYTES);
    offset += NONCE_BYTES;
    const cipherLength = readU32be(envelope, offset);
    offset += 4;
    if (cipherLength < TAG_BYTES || offset + cipherLength !== envelope.byteLength) {
      fail('INVALID_LENGTH', 'Ciphertext length does not match envelope');
    }
    const aad = envelope.slice(0, offset);
    const encrypted = envelope.slice(offset);
    const key = await deriveAesKey(password, parsed.salt);
    try {
      const paddedPlaintext = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength: 128 },
        key,
        encrypted
      );
      const plaintext = unpadPayload(paddedPlaintext);
      try {
        return decoder.decode(plaintext);
      } finally {
        plaintext.fill(0);
        new Uint8Array(paddedPlaintext).fill(0);
      }
    } catch (error) {
      if (error instanceof CipherV3Error) throw error;
      fail('AUTH_FAILED', 'Wrong password or modified ciphertext');
    }
  }

  function buildFileBase(common, paddedSize, totalChunks) {
    return concatBytes(common, u32be(FILE_CHUNK_BYTES), u64be(paddedSize), u32be(totalChunks));
  }

  function expectedChunkLength(fileSize, totalChunks, index) {
    if (index < 0 || index >= totalChunks) fail('INVALID_CHUNK', 'Invalid chunk index');
    if (index < totalChunks - 1) return FILE_CHUNK_BYTES;
    return fileSize - FILE_CHUNK_BYTES * (totalChunks - 1);
  }

  function metadataRecordHeader(nonce, cipherLength) {
    return concatBytes(new Uint8Array([0, NONCE_BYTES]), nonce, u32be(cipherLength));
  }

  function chunkRecordHeader(index, plainLength, nonce, cipherLength) {
    return concatBytes(
      new Uint8Array([1]),
      u32be(index),
      u32be(plainLength),
      new Uint8Array([NONCE_BYTES]),
      nonce,
      u32be(cipherLength)
    );
  }

  function safeFilename(value) {
    if (typeof value !== 'string') return 'decrypted-file';
    const pieces = value.split(/[\\/]/);
    const cleaned = (pieces[pieces.length - 1] || '')
      .replace(/[\u0000-\u001F\u007F]/g, '')
      .trim();
    return cleaned || 'decrypted-file';
  }

  function validMime(value) {
    if (typeof value !== 'string' || value.length > 255 || /[\u0000-\u001F\u007F]/.test(value)) {
      return 'application/octet-stream';
    }
    return value || 'application/octet-stream';
  }

  async function encryptFile(blob, password, options) {
    options = options || {};
    if (!blob || typeof blob.size !== 'number' || typeof blob.slice !== 'function') {
      fail('INVALID_INPUT', 'A Blob or File is required');
    }
    if (!Number.isSafeInteger(blob.size) || blob.size < 0) fail('INVALID_LENGTH', 'Invalid file size');

    const paddedSize = paddedLength(blob.size);
    const totalChunks = Math.ceil(paddedSize / FILE_CHUNK_BYTES);
    if (totalChunks > 0xFFFFFFFF) fail('INVALID_LENGTH', 'File has too many chunks');
    const salt = randomBytes(SALT_BYTES);
    const common = buildCommonHeader(TYPE_FILE, salt);
    const fileBase = buildFileBase(common, paddedSize, totalChunks);
    const key = await deriveAesKey(password, salt);
    const parts = [fileBase];

    const metadataBytes = encoder.encode(JSON.stringify({
      v: 2,
      name: typeof options.name === 'string' ? options.name : 'encrypted-file',
      type: typeof options.type === 'string' ? options.type : 'application/octet-stream',
      size: blob.size
    }));
    if (metadataBytes.byteLength > MAX_METADATA_JSON_BYTES) fail('INVALID_METADATA', 'File metadata is too large');
    const metadataPlain = padPayload(metadataBytes);
    metadataBytes.fill(0);

    const metadataNonce = randomBytes(NONCE_BYTES);
    const metadataLength = metadataPlain.byteLength + TAG_BYTES;
    const metadataHeader = metadataRecordHeader(metadataNonce, metadataLength);
    const metadataAad = concatBytes(fileBase, metadataHeader);
    const metadataCipher = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: metadataNonce, additionalData: metadataAad, tagLength: 128 },
      key,
      metadataPlain
    );
    metadataPlain.fill(0);
    parts.push(metadataHeader, metadataCipher);

    for (let index = 0; index < totalChunks; index++) {
      const start = index * FILE_CHUNK_BYTES;
      const expectedLength = expectedChunkLength(paddedSize, totalChunks, index);
      const sourceEnd = Math.min(start + expectedLength, blob.size);
      const sourceBytes = start < blob.size
        ? new Uint8Array(await blob.slice(start, sourceEnd).arrayBuffer())
        : new Uint8Array(0);
      if (sourceBytes.byteLength !== Math.max(0, sourceEnd - start)) {
        fail('FILE_CHANGED', 'File changed during encryption');
      }
      const plainBytes = sourceBytes.byteLength === expectedLength
        ? sourceBytes
        : new Uint8Array(expectedLength);
      if (plainBytes !== sourceBytes) {
        plainBytes.set(sourceBytes);
        sourceBytes.fill(0);
      }
      const nonce = randomBytes(NONCE_BYTES);
      const cipherLength = plainBytes.byteLength + TAG_BYTES;
      const header = chunkRecordHeader(index, plainBytes.byteLength, nonce, cipherLength);
      const aad = concatBytes(fileBase, header);
      const encrypted = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength: 128 },
        key,
        plainBytes
      );
      plainBytes.fill(0);
      parts.push(header, encrypted);
      if (typeof options.onProgress === 'function') {
        options.onProgress(totalChunks === 0 ? 1 : (index + 1) / totalChunks);
      }
    }
    return concatBytes(...parts).buffer;
  }

  function requireAvailable(bytes, offset, length) {
    if (!Number.isSafeInteger(length) || length < 0 || offset < 0 || offset + length > bytes.byteLength) {
      fail('TRUNCATED', 'Encrypted file is truncated');
    }
  }

  async function decryptFile(value, password, options) {
    options = options || {};
    const bytes = asBytes(value);
    if (isLegacyFile(bytes)) {
      fail('LEGACY_FORMAT', 'Legacy encrypted files are not supported');
    }
    parseCommonHeader(bytes, TYPE_FILE);
    if (bytes.byteLength < FILE_BASE_BYTES) fail('TRUNCATED', 'Encrypted file header is truncated');

    const chunkSize = readU32be(bytes, 40);
    const paddedSize = readU64be(bytes, 44);
    const totalChunks = readU32be(bytes, 52);
    if (chunkSize !== FILE_CHUNK_BYTES ||
        paddedSize < PADDING_BLOCK_BYTES ||
        paddedSize % PADDING_BLOCK_BYTES !== 0 ||
        totalChunks !== Math.ceil(paddedSize / FILE_CHUNK_BYTES)) {
      fail('INVALID_FILE_HEADER', 'Invalid encrypted file structure');
    }
    const fileBase = bytes.slice(0, FILE_BASE_BYTES);
    const salt = bytes.slice(24, 24 + SALT_BYTES);
    let offset = FILE_BASE_BYTES;

    requireAvailable(bytes, offset, 2);
    if (bytes[offset] !== 0 || bytes[offset + 1] !== NONCE_BYTES) {
      fail('INVALID_METADATA', 'Missing encrypted file metadata');
    }
    const metadataHeaderStart = offset;
    offset += 2;
    requireAvailable(bytes, offset, NONCE_BYTES + 4);
    const metadataNonce = bytes.slice(offset, offset + NONCE_BYTES);
    offset += NONCE_BYTES;
    const metadataLength = readU32be(bytes, offset);
    offset += 4;
    if (metadataLength !== PADDING_BLOCK_BYTES + TAG_BYTES) {
      fail('INVALID_METADATA', 'Invalid metadata length');
    }
    requireAvailable(bytes, offset, metadataLength);
    const metadataHeader = bytes.slice(metadataHeaderStart, offset);
    const metadataCipher = bytes.slice(offset, offset + metadataLength);
    offset += metadataLength;

    const key = await deriveAesKey(password, salt);
    let metadata;
    try {
      const paddedMetadata = await crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: metadataNonce,
          additionalData: concatBytes(fileBase, metadataHeader),
          tagLength: 128
        },
        key,
        metadataCipher
      );
      const metadataPlain = unpadPayload(paddedMetadata);
      metadata = JSON.parse(decoder.decode(metadataPlain));
      metadataPlain.fill(0);
      new Uint8Array(paddedMetadata).fill(0);
      if (!metadata || metadata.v !== 2 || typeof metadata.name !== 'string' ||
          typeof metadata.type !== 'string' || !Number.isSafeInteger(metadata.size) ||
          metadata.size < 0 || paddedLength(metadata.size) !== paddedSize) {
        fail('INVALID_METADATA', 'Invalid encrypted metadata');
      }
    } catch (error) {
      if (error instanceof CipherV3Error) throw error;
      fail('AUTH_FAILED', 'Wrong password or modified encrypted file');
    }

    const plainParts = [];
    let producedBytes = 0;
    for (let expectedIndex = 0; expectedIndex < totalChunks; expectedIndex++) {
      const headerStart = offset;
      requireAvailable(bytes, offset, 26);
      if (bytes[offset] !== 1) fail('INVALID_CHUNK', 'Invalid encrypted chunk record');
      offset += 1;
      const index = readU32be(bytes, offset);
      offset += 4;
      const plainLength = readU32be(bytes, offset);
      offset += 4;
      if (bytes[offset] !== NONCE_BYTES) fail('INVALID_NONCE', 'Invalid chunk nonce length');
      offset += 1;
      const nonce = bytes.slice(offset, offset + NONCE_BYTES);
      offset += NONCE_BYTES;
      const cipherLength = readU32be(bytes, offset);
      offset += 4;

      const expectedLength = expectedChunkLength(paddedSize, totalChunks, expectedIndex);
      if (index !== expectedIndex || plainLength !== expectedLength || cipherLength !== plainLength + TAG_BYTES) {
        fail('INVALID_CHUNK', 'Encrypted chunk order or length is invalid');
      }
      requireAvailable(bytes, offset, cipherLength);
      const encrypted = bytes.slice(offset, offset + cipherLength);
      const recordHeader = bytes.slice(headerStart, offset);
      offset += cipherLength;

      try {
        const plain = await crypto.subtle.decrypt(
          {
            name: 'AES-GCM',
            iv: nonce,
            additionalData: concatBytes(fileBase, recordHeader),
            tagLength: 128
          },
          key,
          encrypted
        );
        if (plain.byteLength !== plainLength) fail('INVALID_CHUNK', 'Decrypted chunk length is invalid');
        plainParts.push(plain);
        producedBytes += plain.byteLength;
      } catch (error) {
        if (error instanceof CipherV3Error) throw error;
        fail('AUTH_FAILED', 'Wrong password or modified encrypted file');
      }

      if (typeof options.onProgress === 'function') options.onProgress((expectedIndex + 1) / totalChunks);
    }

    if (offset !== bytes.byteLength || producedBytes !== paddedSize) {
      fail('INVALID_LENGTH', 'Encrypted file has missing or trailing data');
    }
    const paddedPlaintext = concatBytes(...plainParts);
    for (let index = metadata.size; index < paddedPlaintext.byteLength; index++) {
      if (paddedPlaintext[index] !== 0) fail('INVALID_PADDING', 'Encrypted file padding is invalid');
    }
    const output = paddedPlaintext.slice(0, metadata.size);
    paddedPlaintext.fill(0);

    return {
      buffer: output.buffer,
      name: safeFilename(metadata.name),
      type: validMime(metadata.type)
    };
  }

  function isLegacyFile(value) {
    const bytes = asBytes(value);
    return (bytes.byteLength >= 4 && equalBytes(bytes.subarray(0, 4), LEGACY_MAGIC)) ||
      (bytes.byteLength >= 5 && equalBytes(bytes.subarray(0, 4), MAGIC) && bytes[4] === 2);
  }

  function isV3File(value) {
    const bytes = asBytes(value);
    return bytes.byteLength >= 5 && equalBytes(bytes.subarray(0, 4), MAGIC) && bytes[4] === FORMAT_VERSION;
  }

  global.CipherV3 = Object.freeze({
    constants: Object.freeze({
      textPrefix: TEXT_PREFIX,
      paddingBlockSize: PADDING_BLOCK_BYTES,
      chunkSize: FILE_CHUNK_BYTES,
      argonMemoryKiB: ARGON_MEMORY_KIB,
      argonIterations: ARGON_ITERATIONS,
      argonParallelism: ARGON_PARALLELISM,
      formatVersion: FORMAT_VERSION
    }),
    CipherV3Error,
    assertReady: assertArgonAvailable,
    deriveAesKey,
    encryptText,
    decryptText,
    encryptFile,
    decryptFile,
    looksLikeV3Text,
    looksLikeLegacyText,
    isV3File,
    isLegacyFile,
    base64UrlToBytes,
    bytesToBase64Url
  });
})(typeof window !== 'undefined' ? window : globalThis);
