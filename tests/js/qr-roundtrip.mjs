/**
 * The real check on the QR encoder: encode, then decode again with something
 * that had no hand in the encoding.
 *
 * A QR encoder can be wrong in ways that look entirely convincing. The
 * generator polynomial in this one was reversed at first, which produced
 * matrices of the right size with the right finder patterns, the right timing
 * patterns and plausible-looking data — and no scanner on earth could read
 * them. Only decoding catches that.
 *
 * Needs an independent decoder, which is not a dependency of this project:
 *
 *   mkdir /tmp/qr && cd /tmp/qr && npm init -y && npm install jsqr
 *   NODE_PATH=/tmp/qr/node_modules node tests/js/qr-roundtrip.mjs
 *
 * It walks every length from 1 to 600 at both error correction levels, which
 * crosses every version boundary the encoder supports, and every mask.
 */
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const qr = require('../../assets/allkiri-qr.js');

let jsQR;
try {
  jsQR = require('jsqr');
} catch {
  console.error('This needs an independent decoder. See the comment at the top of this file.');
  process.exit(2);
}

/**
 * Render a matrix as a bitmap and read it back.
 */
function decode(matrix, scale = 4, quiet = 4) {
  const modules = matrix.length + quiet * 2;
  const size = modules * scale;
  const data = new Uint8ClampedArray(size * size * 4);

  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      const row = Math.floor(y / scale) - quiet;
      const col = Math.floor(x / scale) - quiet;
      const dark = row >= 0 && col >= 0 && row < matrix.length && col < matrix.length && matrix[row][col];
      const value = dark ? 0 : 255;
      const i = (y * size + x) * 4;
      data[i] = data[i + 1] = data[i + 2] = value;
      data[i + 3] = 255;
    }
  }

  const result = jsQR(data, size, size);
  return result ? result.data : null;
}

const ALPHABET = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.~:/?#[]@!$&\'()*+,;=%õäöüŠŽ ';

let passed = 0;
const failures = [];

for (let length = 1; length <= 600; length++) {
  let text = '';
  for (let i = 0; i < length; i++) {
    text += ALPHABET[(i * 7 + length) % ALPHABET.length];
  }

  for (const level of ['L', 'M']) {
    let got = null;
    let threw = null;
    try {
      got = decode(qr.encode(text, { level }));
    } catch (error) {
      threw = error.message;
    }

    if (got === text) {
      passed++;
    } else {
      failures.push(`length ${length}, level ${level}: ${threw ? `threw ${threw}` : got === null ? 'did not decode' : 'decoded to something else'}`);
    }
  }
}

for (let mask = 0; mask < 8; mask++) {
  const text = `mask ${mask} ${'x'.repeat(50)}`;
  if (decode(qr.encode(text, { level: 'M', mask })) === text) {
    passed++;
  } else {
    failures.push(`mask ${mask} did not decode`);
  }
}

console.log(`${passed} passed, ${failures.length} failed`);
failures.slice(0, 10).forEach((f) => console.error('  ' + f));
process.exit(failures.length === 0 ? 0 : 1);
