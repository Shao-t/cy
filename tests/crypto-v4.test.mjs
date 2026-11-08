import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { Blob } from 'node:buffer';

if (!globalThis.crypto) Object.defineProperty(globalThis, 'crypto', { value: webcrypto });
if (!globalThis.Blob) Object.defineProperty(globalThis, 'Blob', { value: Blob });
const hashwasmModule = await import('../vendor/argon2.umd.min.js');
globalThis.hashwasm = globalThis.hashwasm || hashwasmModule.default || hashwasmModule;
await import('../vendor/bip39-en.js');
await import('../recovery-phrase.js');
await import('../crypto-v3.js');
await import('../crypto-v4.js');

const R = globalThis.CipherRecoveryPhrase;
const V3 = globalThis.CipherV3;
const V4 = globalThis.CipherV4;

async function expectCode(action, code) {
  await assert.rejects(action, error => error && error.code === code);
}

async function run() {
  assert.equal(globalThis.CIPHER_BIP39_EN.length, 2048);
  assert.equal(new Set(globalThis.CIPHER_BIP39_EN).size, 2048);
  assert.equal(globalThis.CIPHER_BIP39_EN[0], 'abandon');
  assert.equal(globalThis.CIPHER_BIP39_EN[2047], 'zoo');
  assert.equal(R.constants.entropyBits, 88);
  assert.equal(R.constants.dataWords, 8);
  assert.equal(R.constants.totalWords, 9);

  const phrase = await R.phraseFromEntropy(new Uint8Array(11));
  assert.equal(phrase.split(' ').length, 9);
  assert.deepEqual(await R.inspect(phrase), {
    valid: true,
    code: 'OK',
    message: '88-bit 中等保護',
    normalized: phrase
  });
  assert.equal((await R.inspect(phrase.replaceAll(' ', ''))).code, 'INVALID_WORD_COUNT');

  const words = phrase.split(' ');
  words[0] = globalThis.CIPHER_BIP39_EN[1];
  assert.equal((await R.inspect(words.join(' '))).code, 'CHECKSUM_MISMATCH');
  const unknownWords = phrase.split(' ');
  unknownWords[0] = 'notaword';
  assert.equal((await R.inspect(unknownWords.join(' '))).code, 'UNKNOWN_WORD');

  const generated = await R.generate();
  assert.equal((await R.inspect(generated)).valid, true);
  assert.notEqual(generated, phrase);

  assert.equal(V4.constants.formatVersion, 4);
  assert.equal(V4.constants.argonMemoryKiB, 65536);
  assert.equal(V4.constants.argonIterations, 3);
  assert.equal(V4.constants.argonParallelism, 1);

  const plaintext = 'CIPHER v4 中等保護 🔐';
  const ciphertext = await V4.encryptText(plaintext, phrase);
  assert.ok(ciphertext.startsWith('CIPHER4:'));
  assert.equal(await V4.decryptText(ciphertext, phrase), plaintext);
  await expectCode(() => V4.encryptText('invalid', 'user chosen password'), 'INVALID_WORD_COUNT');

  const secondPhrase = await R.phraseFromEntropy(new Uint8Array(11).fill(1));
  await expectCode(() => V4.decryptText(ciphertext, secondPhrase), 'AUTH_FAILED');

  const envelope = V4.base64UrlToBytes(ciphertext.slice('CIPHER4:'.length));
  const changedParams = envelope.slice();
  changedParams[10] ^= 1;
  await expectCode(
    () => V4.decryptText('CIPHER4:' + V4.bytesToBase64Url(changedParams), phrase),
    'UNSUPPORTED_KDF_PARAMS'
  );
  const changedTag = envelope.slice();
  changedTag[changedTag.length - 1] ^= 1;
  await expectCode(
    () => V4.decryptText('CIPHER4:' + V4.bytesToBase64Url(changedTag), phrase),
    'AUTH_FAILED'
  );

  const fileBytes = new TextEncoder().encode('檔案內容\nsecond line');
  const encryptedFile = new Uint8Array(await V4.encryptFile(new Blob([fileBytes]), phrase, {
    name: '秘密檔案.txt',
    type: 'text/plain'
  }));
  assert.equal(encryptedFile[4], 4);
  assert.equal(Buffer.from(encryptedFile).indexOf(Buffer.from('秘密檔案.txt')), -1);
  const decryptedFile = await V4.decryptFile(encryptedFile, phrase);
  assert.equal(decryptedFile.name, '秘密檔案.txt');
  assert.equal(decryptedFile.type, 'text/plain');
  assert.deepEqual(new Uint8Array(decryptedFile.buffer), fileBytes);

  const oldPassword = 'existing CIPHER3 password';
  const oldText = await V3.encryptText('舊版可解密', oldPassword);
  assert.equal(await V3.decryptText(oldText, oldPassword), '舊版可解密');
  assert.equal(V4.looksLikeLegacyText(oldText), true);
  const oldFile = await V3.encryptFile(new Blob([fileBytes]), oldPassword, { name: 'old.txt', type: 'text/plain' });
  assert.equal(V3.isV3File(oldFile), true);
  assert.equal(V4.isLegacyFile(oldFile), true);
  assert.deepEqual(new Uint8Array((await V3.decryptFile(oldFile, oldPassword)).buffer), fileBytes);

  console.log('CIPHER v4 recovery phrase tests passed');
}

await run();
