/**
 * The QR encoder against fixed vectors. No dependencies; run it with
 *
 *   node tests/js/qr-golden.mjs
 *
 * These digests were taken from the encoder only after it had been verified
 * against an independent decoder (see qr-roundtrip.mjs), so what they guard
 * against is a later change quietly altering the output. On their own they
 * would prove nothing: a wrong encoder produces stable wrong digests just as
 * happily as a right one produces stable right ones.
 */
import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const qr = require('../../assets/allkiri-qr.js');

const CASES = [
  ['HELLO', 'L', 21, '7a381bcb34d02f3af6f20bb290409ced08ec7fb6849d56a1d721cf0f6127b363'],
  ['hello world this is a byte mode test', 'L', 29, '15174f53f11e610f03a3c0d9fa92c0752ff9616d31bf90b248db0120356f824e'],
  ['Nõustun tingimustega — õäöü ŠŽ', 'M', 29, 'e4520cdfdb27582d23dd783a25a85748e63b3c11659d9640fd5e7e9dd096696c'],
  [
    'https://smart-id.test/dl?deviceLinkType=QR&elapsedSeconds=7&sessionToken=abc&sessionType=auth&version=1.0&lang=est&authCode=aGVsbG8td29ybGQtdGhpcy1pcy1hLWZha2UtYXV0aC1jb2Rl',
    'M', 53, 'e873bef7fe85b676b43986aa5714cc2f78df7ea3b67e46a4c3e9ddde1788763e',
  ],
  ['x'.repeat(300), 'L', 61, 'd0e99d48c1aa34f5c390f2c63a707bac6f4137ba3bfc2ecf73ea5631a1f3680b'],
  ['y'.repeat(600), 'M', 93, '0d5ea9ad784f40590be97e50e99a6d7a879449e3062be93b5a6b76dd180a1eee'],
];

let failures = 0;

for (const [text, level, size, digest] of CASES) {
  const matrix = qr.encode(text, { level });
  const actual = createHash('sha256').update(matrix.map((row) => row.join('')).join('')).digest('hex');
  const label = text.length > 40 ? `${text.slice(0, 37)}…` : text;

  if (matrix.length !== size) {
    console.error(`FAIL ${label}: expected a ${size}-module matrix, got ${matrix.length}`);
    failures++;
  } else if (actual !== digest) {
    console.error(`FAIL ${label}: expected ${digest}, got ${actual}`);
    failures++;
  } else {
    console.log(`ok   ${label} (${size} modules, level ${level})`);
  }
}

// The shapes an application actually asks for.
const svg = qr.svg('https://example.test/dl?x=1', { size: 300, title: 'Smart-ID' });
for (const expected of ['<svg', 'viewBox="0 0 ', 'width="300"', 'aria-label="Smart-ID"', '</svg>']) {
  if (!svg.includes(expected)) {
    console.error(`FAIL svg output is missing ${expected}`);
    failures++;
  }
}

// Refusals worth having.
for (const [bad, why] of [['', 'empty text'], [null, 'a non-string']]) {
  try {
    qr.encode(bad);
    console.error(`FAIL ${why} should have been refused`);
    failures++;
  } catch {
    // expected
  }
}
try {
  qr.encode('x', { level: 'H' });
  console.error('FAIL an unsupported error correction level should have been refused');
  failures++;
} catch {
  // expected
}
try {
  qr.encode('x'.repeat(5000));
  console.error('FAIL too much data should have been refused');
  failures++;
} catch {
  // expected
}

console.log(failures === 0 ? '\nAll QR vectors match.' : `\n${failures} failure(s).`);
process.exit(failures === 0 ? 0 : 1);
