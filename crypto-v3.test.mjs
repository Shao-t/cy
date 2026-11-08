import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { Blob } from 'node:buffer';

if (!globalThis.crypto) Object.defineProperty(globalThis, 'crypto', { value: webcrypto });
if (!globalThis.Blob) Object.defineProperty(globalThis, 'Blob', { value: Blob });
const hashwasmModule = await import('../vendor/argon2.umd.min.js');
globalThis.hashwasm = globalThis.hashwasm || hashwasmModule.default || hashwasmModule;
await import('../crypto-v3.js');

const C = globalThis.CipherV3;

function hex(bytes) {
  return Buffer.from(bytes).toString('hex');
}

async function expectCode(action, code) {
  await assert.rejects(action, error => error && error.code === code);
}

function readU32(bytes, offset) {
  return new DataView(bytes.buffer, bytes.byteOffset + offset, 4).getUint32(0, false);
}

function readU64(bytes, offset) {
  return readU32(bytes, offset) * 0x100000000 + readU32(bytes, offset + 4);
}

function firstChunkOffset(bytes) {
  const metadataLength = readU32(bytes, 70);
  return 74 + metadataLength;
}

function recordEnd(bytes, offset) {
  const cipherLength = readU32(bytes, offset + 22);
  return offset + 26 + cipherLength;
}

async function run() {
  // Published Go x/crypto vector, generated from the Argon2 reference CLI.
  const vector = await hashwasm.argon2id({
    password: 'password',
    salt: 'somesalt',
    iterations: 2,
    memorySize: 64,
    parallelism: 1,
    hashLength: 24,
    outputType: 'binary'
  });
  assert.equal(hex(vector), '068d62b26455936aa6ebe60060b0a65870dbfa3ddf8d41f7');

  const plaintext = 'Hello 世界 🔐\n第二行';
  const password = 'correct horse battery staple';
  const ciphertext = await C.encryptText(plaintext, password);
  assert.ok(ciphertext.startsWith('CIPHER3:'));
  assert.equal(await C.decryptText(ciphertext, password), plaintext);

  const oneCjk = await C.encryptText('中', password);
  const threeAscii = await C.encryptText('abc', password);
  const maxFirstBucket = await C.encryptText('x'.repeat(4092), password);
  const secondBucket = await C.encryptText('x'.repeat(4093), password);
  assert.equal(oneCjk.length, threeAscii.length);
  assert.equal(oneCjk.length, maxFirstBucket.length);
  assert.ok(secondBucket.length > maxFirstBucket.length);
  assert.equal(await C.decryptText(secondBucket, password), 'x'.repeat(4093));

  const normalized = await C.encryptText('NFC', 'u\u0308-secret');
  assert.equal(await C.decryptText(normalized, 'ü-secret'), 'NFC');
  assert.equal(await C.decryptText(await C.encryptText('', password), password), '');
  await expectCode(() => C.decryptText(ciphertext, 'wrong password'), 'AUTH_FAILED');
  await expectCode(() => C.decryptText('00'.repeat(40), password), 'LEGACY_FORMAT');
  await expectCode(() => C.decryptText('CIPHER2:anything', password), 'LEGACY_FORMAT');
  await expectCode(() => C.decryptText('CIPHER3:***', password), 'INVALID_ENCODING');

  const envelope = C.base64UrlToBytes(ciphertext.slice('CIPHER3:'.length));
  const changedParams = envelope.slice();
  changedParams[10] ^= 1;
  await expectCode(
    () => C.decryptText('CIPHER3:' + C.bytesToBase64Url(changedParams), password),
    'UNSUPPORTED_KDF_PARAMS'
  );
  const changedTag = envelope.slice();
  changedTag[changedTag.length - 1] ^= 1;
  await expectCode(
    () => C.decryptText('CIPHER3:' + C.bytesToBase64Url(changedTag), password),
    'AUTH_FAILED'
  );
  const appendedText = new Uint8Array(envelope.length + 1);
  appendedText.set(envelope);
  await expectCode(
    () => C.decryptText('CIPHER3:' + C.bytesToBase64Url(appendedText), password),
    'INVALID_LENGTH'
  );

  const smallBytes = new TextEncoder().encode('small file 內容');
  const smallEncrypted = new Uint8Array(await C.encryptFile(new Blob([smallBytes]), password, {
    name: '秘密資料.txt',
    type: 'text/plain'
  }));
  assert.equal(Buffer.from(smallEncrypted).indexOf(Buffer.from('秘密資料.txt')), -1);
  const smallResult = await C.decryptFile(smallEncrypted, password);
  assert.equal(smallResult.name, '秘密資料.txt');
  assert.equal(smallResult.type, 'text/plain');
  assert.deepEqual(new Uint8Array(smallResult.buffer), smallBytes);
  assert.equal(readU64(smallEncrypted, 44), C.constants.paddingBlockSize);
  assert.equal(readU32(smallEncrypted, 70), C.constants.paddingBlockSize + 16);

  const emptyEncrypted = await C.encryptFile(new Blob([]), password, {
    name: 'empty.bin',
    type: 'application/octet-stream'
  });
  const emptyResult = await C.decryptFile(emptyEncrypted, password);
  assert.equal(emptyResult.buffer.byteLength, 0);
  assert.equal(emptyResult.name, 'empty.bin');

  const boundarySizes = [1, 4095, 4096, 4097];
  const boundaryEncryptedSizes = [];
  for (const size of boundarySizes) {
    const content = new Uint8Array(size);
    for (let index = 0; index < size; index++) content[index] = index % 251;
    const encrypted = new Uint8Array(await C.encryptFile(new Blob([content]), password, {
      name: `boundary-${size}.bin`,
      type: 'application/octet-stream'
    }));
    const decrypted = await C.decryptFile(encrypted, password);
    assert.deepEqual(new Uint8Array(decrypted.buffer), content);
    boundaryEncryptedSizes.push(encrypted.byteLength);
  }
  assert.equal(new Uint8Array(emptyEncrypted).byteLength, boundaryEncryptedSizes[0]);
  assert.equal(boundaryEncryptedSizes[0], boundaryEncryptedSizes[1]);
  assert.equal(boundaryEncryptedSizes[1], boundaryEncryptedSizes[2]);
  assert.ok(boundaryEncryptedSizes[3] > boundaryEncryptedSizes[2]);

  const largeBytes = new Uint8Array(C.constants.chunkSize + 257);
  for (let i = 0; i < largeBytes.length; i++) largeBytes[i] = i % 251;
  const largeEncrypted = new Uint8Array(await C.encryptFile(new Blob([largeBytes]), password, {
    name: '多分塊.bin',
    type: 'application/octet-stream'
  }));
  const largeResult = await C.decryptFile(largeEncrypted, password);
  assert.deepEqual(new Uint8Array(largeResult.buffer), largeBytes);

  for (const size of [C.constants.chunkSize - 1, C.constants.chunkSize]) {
    const content = new Uint8Array(size);
    content[0] = 1;
    content[content.length - 1] = 2;
    const encrypted = new Uint8Array(await C.encryptFile(new Blob([content]), password, {
      name: `chunk-${size}.bin`,
      type: 'application/octet-stream'
    }));
    assert.equal(readU32(encrypted, 52), 1);
    const decrypted = await C.decryptFile(encrypted, password);
    assert.deepEqual(new Uint8Array(decrypted.buffer), content);
  }
  assert.equal(readU32(largeEncrypted, 52), 2);

  const changedHeader = smallEncrypted.slice();
  changedHeader[55] ^= 1;
  await expectCode(() => C.decryptFile(changedHeader, password), 'INVALID_FILE_HEADER');

  const changedMetadata = smallEncrypted.slice();
  changedMetadata[74] ^= 1;
  await expectCode(() => C.decryptFile(changedMetadata, password), 'AUTH_FAILED');

  const changedIndex = largeEncrypted.slice();
  const chunkStart = firstChunkOffset(changedIndex);
  changedIndex[chunkStart + 4] ^= 1;
  await expectCode(() => C.decryptFile(changedIndex, password), 'INVALID_CHUNK');

  const changedChunkTag = largeEncrypted.slice();
  changedChunkTag[changedChunkTag.length - 1] ^= 1;
  await expectCode(() => C.decryptFile(changedChunkTag, password), 'AUTH_FAILED');

  const firstStart = firstChunkOffset(largeEncrypted);
  const firstEnd = recordEnd(largeEncrypted, firstStart);
  const secondEnd = recordEnd(largeEncrypted, firstEnd);
  const reordered = new Uint8Array(largeEncrypted.length);
  reordered.set(largeEncrypted.subarray(0, firstStart));
  reordered.set(largeEncrypted.subarray(firstEnd, secondEnd), firstStart);
  reordered.set(largeEncrypted.subarray(firstStart, firstEnd), firstStart + secondEnd - firstEnd);
  await expectCode(() => C.decryptFile(reordered, password), 'INVALID_CHUNK');

  await expectCode(() => C.decryptFile(largeEncrypted.slice(0, -1), password), 'TRUNCATED');
  const appendedFile = new Uint8Array(smallEncrypted.length + 1);
  appendedFile.set(smallEncrypted);
  await expectCode(() => C.decryptFile(appendedFile, password), 'INVALID_LENGTH');

  const legacy = new Uint8Array([0xAE, 0x53, 0x47, 0x01, 0, 0, 0, 0]);
  await expectCode(() => C.decryptFile(legacy, password), 'LEGACY_FORMAT');
  const v2File = new Uint8Array([0x43, 0x49, 0x50, 0x48, 0x02, 0, 0, 0]);
  await expectCode(() => C.decryptFile(v2File, password), 'LEGACY_FORMAT');

  // 前綴大小寫不敏感，本體仍區分大小寫。
  const caseV3 = await C.encryptText('大小寫測試', password);
  const bodyV3 = caseV3.slice('CIPHER3:'.length);
  for (const prefix of ['cipher3:', 'Cipher3:']) {
    assert.equal(C.looksLikeV3Text(' ' + prefix + bodyV3), true);
    assert.equal(await C.decryptText(prefix + bodyV3, password), '大小寫測試');
  }
  assert.equal(C.looksLikeV3Text('cipher4:' + bodyV3), false);
  assert.equal(C.looksLikeLegacyText('cipher2:abc'), true);

  console.log('CIPHER v3 tests passed');
}

await run();
