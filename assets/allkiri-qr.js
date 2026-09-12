/**
 * A QR encoder, just enough of one for Smart-ID device links.
 *
 * Smart-ID's QR flow rebuilds its link about once a second, so the page needs
 * to draw a new code that often. Pulling in a QR library for that is a lot of
 * dependency for one job, and a page that signs documents is a poor place to
 * add a script nobody has looked at. This is byte mode only, error correction
 * level L or M, versions 1 to 20 — which covers a device link of any plausible
 * length with room to spare.
 *
 * ISO/IEC 18004. Verified by encoding and decoding again with an independent
 * decoder; see tests/js/qr.test.js.
 *
 * No dependencies, no build step, no network. MIT, like the rest of allkiri.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.allkiriQr = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  // --- Galois field arithmetic, GF(256) with the QR primitive polynomial ----

  var EXP = new Uint8Array(512);
  var LOG = new Uint8Array(256);
  (function () {
    var x = 1;
    for (var i = 0; i < 255; i++) {
      EXP[i] = x;
      LOG[x] = i;
      x <<= 1;
      if (x & 0x100) {
        x ^= 0x11d; // the primitive polynomial QR uses
      }
    }
    for (var j = 255; j < 512; j++) {
      EXP[j] = EXP[j - 255];
    }
  }());

  function gfMultiply(a, b) {
    if (a === 0 || b === 0) {
      return 0;
    }
    return EXP[LOG[a] + LOG[b]];
  }

  /**
   * The generator polynomial for `degree` error correction codewords.
   */
  function generatorPolynomial(degree) {
    // Multiply by (x + α^i) each time round. The coefficients run from the
    // highest power down, so the x term keeps its index and the constant term
    // moves one along; swapping those two lines produces the polynomial
    // reversed, which is wrong in a way that still yields plausible-looking
    // codewords.
    var poly = [1];
    for (var i = 0; i < degree; i++) {
      var next = new Array(poly.length + 1).fill(0);
      for (var j = 0; j < poly.length; j++) {
        next[j] ^= poly[j];
        next[j + 1] ^= gfMultiply(poly[j], EXP[i]);
      }
      poly = next;
    }
    return poly;
  }

  /**
   * Reed-Solomon error correction codewords for one block.
   */
  function errorCorrection(data, count) {
    var generator = generatorPolynomial(count);
    var remainder = new Array(count).fill(0);

    for (var i = 0; i < data.length; i++) {
      var factor = data[i] ^ remainder[0];
      remainder.shift();
      remainder.push(0);
      for (var j = 0; j < count; j++) {
        remainder[j] ^= gfMultiply(generator[j + 1], factor);
      }
    }
    return remainder;
  }

  // --- Version tables ------------------------------------------------------

  // Error correction codewords per block, and the block layout, for levels L
  // and M of versions 1 to 20. Each entry is
  // [ecCodewordsPerBlock, group1Blocks, group1Codewords, group2Blocks, group2Codewords].
  var BLOCKS = {
    L: [
      [7, 1, 19, 0, 0], [10, 1, 34, 0, 0], [15, 1, 55, 0, 0], [20, 1, 80, 0, 0],
      [26, 1, 108, 0, 0], [18, 2, 68, 0, 0], [20, 2, 78, 0, 0], [24, 2, 97, 0, 0],
      [30, 2, 116, 0, 0], [18, 2, 68, 2, 69], [20, 4, 81, 0, 0], [24, 2, 92, 2, 93],
      [26, 4, 107, 0, 0], [30, 3, 115, 1, 116], [22, 5, 87, 1, 88], [24, 5, 98, 1, 99],
      [28, 1, 107, 5, 108], [30, 5, 120, 1, 121], [28, 3, 113, 4, 114], [28, 3, 107, 5, 108]
    ],
    M: [
      [10, 1, 16, 0, 0], [16, 1, 28, 0, 0], [26, 1, 44, 0, 0], [18, 2, 32, 0, 0],
      [24, 2, 43, 0, 0], [16, 4, 27, 0, 0], [18, 4, 31, 0, 0], [22, 2, 38, 2, 39],
      [22, 3, 36, 2, 37], [26, 4, 43, 1, 44], [30, 1, 50, 4, 51], [22, 6, 36, 2, 37],
      [22, 8, 37, 1, 38], [24, 4, 40, 5, 41], [24, 5, 41, 5, 42], [28, 7, 45, 3, 46],
      [28, 10, 46, 1, 47], [26, 9, 43, 4, 44], [26, 3, 44, 11, 45], [26, 3, 41, 13, 42]
    ]
  };

  // Where the alignment patterns go, per version.
  var ALIGNMENT = [
    [], [6, 18], [6, 22], [6, 26], [6, 30], [6, 34], [6, 22, 38], [6, 24, 42],
    [6, 26, 46], [6, 28, 50], [6, 30, 54], [6, 32, 58], [6, 34, 62], [6, 26, 46, 66],
    [6, 26, 48, 70], [6, 26, 50, 74], [6, 30, 54, 78], [6, 30, 56, 82], [6, 30, 58, 86],
    [6, 34, 62, 90]
  ];

  var EC_BITS = { L: 0x01, M: 0x00 };

  function totalDataCodewords(version, level) {
    var spec = BLOCKS[level][version - 1];
    return spec[1] * spec[2] + spec[3] * spec[4];
  }

  /**
   * The smallest version that holds this much data.
   */
  function chooseVersion(byteLength, level) {
    for (var version = 1; version <= 20; version++) {
      var countBits = version < 10 ? 8 : 16;
      var capacity = totalDataCodewords(version, level) * 8;
      if (4 + countBits + byteLength * 8 <= capacity) {
        return version;
      }
    }
    throw new Error('allkiri-qr: ' + byteLength + ' bytes is more than this encoder handles');
  }

  // --- Bit assembly --------------------------------------------------------

  function BitBuffer() {
    this.bits = [];
  }
  BitBuffer.prototype.put = function (value, length) {
    for (var i = length - 1; i >= 0; i--) {
      this.bits.push((value >>> i) & 1);
    }
  };
  BitBuffer.prototype.toCodewords = function (count) {
    var bits = this.bits.slice();
    // Terminator, then pad to a whole codeword.
    var capacity = count * 8;
    var terminator = Math.min(4, capacity - bits.length);
    for (var i = 0; i < terminator; i++) {
      bits.push(0);
    }
    while (bits.length % 8 !== 0) {
      bits.push(0);
    }

    var codewords = [];
    for (var j = 0; j < bits.length; j += 8) {
      var byte = 0;
      for (var k = 0; k < 8; k++) {
        byte = (byte << 1) | bits[j + k];
      }
      codewords.push(byte);
    }
    // The two pad codewords the standard fixes, alternating.
    var pads = [0xec, 0x11];
    var p = 0;
    while (codewords.length < count) {
      codewords.push(pads[p++ % 2]);
    }
    return codewords;
  };

  function utf8Bytes(text) {
    if (typeof TextEncoder !== 'undefined') {
      return Array.from(new TextEncoder().encode(text));
    }
    return Array.from(Buffer.from(text, 'utf8'));
  }

  /**
   * Data codewords and error correction, interleaved as the standard requires.
   */
  function encodeCodewords(text, version, level) {
    var bytes = utf8Bytes(text);
    var buffer = new BitBuffer();
    buffer.put(4, 4); // byte mode
    buffer.put(bytes.length, version < 10 ? 8 : 16);
    for (var i = 0; i < bytes.length; i++) {
      buffer.put(bytes[i], 8);
    }

    var spec = BLOCKS[level][version - 1];
    var ecPerBlock = spec[0];
    var data = buffer.toCodewords(totalDataCodewords(version, level));

    var blocks = [];
    var offset = 0;
    var g;
    for (g = 0; g < spec[1]; g++) {
      blocks.push(data.slice(offset, offset + spec[2]));
      offset += spec[2];
    }
    for (g = 0; g < spec[3]; g++) {
      blocks.push(data.slice(offset, offset + spec[4]));
      offset += spec[4];
    }

    var ecBlocks = blocks.map(function (block) {
      return errorCorrection(block, ecPerBlock);
    });

    var result = [];
    var longest = Math.max.apply(null, blocks.map(function (b) { return b.length; }));
    var c;
    for (c = 0; c < longest; c++) {
      for (var b = 0; b < blocks.length; b++) {
        if (c < blocks[b].length) {
          result.push(blocks[b][c]);
        }
      }
    }
    for (c = 0; c < ecPerBlock; c++) {
      for (var e = 0; e < ecBlocks.length; e++) {
        result.push(ecBlocks[e][c]);
      }
    }
    return result;
  }

  // --- The matrix ----------------------------------------------------------

  function newMatrix(size) {
    var matrix = [];
    for (var i = 0; i < size; i++) {
      matrix.push(new Array(size).fill(null));
    }
    return matrix;
  }

  function placeFinder(matrix, row, col) {
    for (var r = -1; r <= 7; r++) {
      for (var c = -1; c <= 7; c++) {
        var y = row + r;
        var x = col + c;
        if (y < 0 || y >= matrix.length || x < 0 || x >= matrix.length) {
          continue;
        }
        var onRing = (r >= 0 && r <= 6 && (c === 0 || c === 6))
          || (c >= 0 && c <= 6 && (r === 0 || r === 6));
        var inCore = r >= 2 && r <= 4 && c >= 2 && c <= 4;
        matrix[y][x] = onRing || inCore ? 1 : 0;
      }
    }
  }

  function placeAlignment(matrix, version) {
    var centres = ALIGNMENT[version - 1];
    for (var i = 0; i < centres.length; i++) {
      for (var j = 0; j < centres.length; j++) {
        var row = centres[i];
        var col = centres[j];
        if (matrix[row][col] !== null) {
          continue; // overlaps a finder pattern
        }
        for (var r = -2; r <= 2; r++) {
          for (var c = -2; c <= 2; c++) {
            var edge = Math.max(Math.abs(r), Math.abs(c));
            matrix[row + r][col + c] = edge !== 1 ? 1 : 0;
          }
        }
      }
    }
  }

  function placeTiming(matrix) {
    for (var i = 8; i < matrix.length - 8; i++) {
      var value = i % 2 === 0 ? 1 : 0;
      if (matrix[6][i] === null) {
        matrix[6][i] = value;
      }
      if (matrix[i][6] === null) {
        matrix[i][6] = value;
      }
    }
  }

  /**
   * The 15-bit format information, BCH(15,5) encoded and masked.
   */
  function formatBits(level, mask) {
    var data = (EC_BITS[level] << 3) | mask;
    var value = data << 10;
    for (var i = 4; i >= 0; i--) {
      if ((value >>> (i + 10)) & 1) {
        value ^= 0x537 << i;
      }
    }
    return ((data << 10) | value) ^ 0x5412;
  }

  /**
   * The 18-bit version information, for version 7 and above.
   */
  function versionBits(version) {
    var value = version << 12;
    for (var i = 5; i >= 0; i--) {
      if ((value >>> (i + 12)) & 1) {
        value ^= 0x1f25 << i;
      }
    }
    return (version << 12) | value;
  }

  function placeFormat(matrix, level, mask) {
    var size = matrix.length;
    var bits = formatBits(level, mask);
    for (var i = 0; i < 15; i++) {
      var bit = (bits >>> i) & 1;

      // The copy beside the top-left finder.
      if (i < 6) {
        matrix[i][8] = bit;
      } else if (i < 8) {
        matrix[i + 1][8] = bit;
      } else if (i === 8) {
        matrix[8][7] = bit;
      } else {
        matrix[8][14 - i] = bit;
      }

      // And the split copy beside the other two.
      if (i < 8) {
        matrix[8][size - 1 - i] = bit;
      } else {
        matrix[size - 15 + i][8] = bit;
      }
    }
    matrix[size - 8][8] = 1; // always dark
  }

  function placeVersion(matrix, version) {
    if (version < 7) {
      return;
    }
    var size = matrix.length;
    var bits = versionBits(version);
    for (var i = 0; i < 18; i++) {
      var bit = (bits >>> i) & 1;
      var row = Math.floor(i / 3);
      var col = i % 3;
      matrix[row][size - 11 + col] = bit;
      matrix[size - 11 + col][row] = bit;
    }
  }

  /**
   * Walk the matrix bottom-right to top-left in the zigzag the standard
   * defines, writing the codeword bits into every cell not already used.
   */
  function placeData(matrix, codewords) {
    var size = matrix.length;
    var bitIndex = 0;
    var upward = true;

    for (var right = size - 1; right >= 1; right -= 2) {
      if (right === 6) {
        right = 5; // the vertical timing pattern is skipped entirely
      }
      for (var step = 0; step < size; step++) {
        var row = upward ? size - 1 - step : step;
        for (var c = 0; c < 2; c++) {
          var col = right - c;
          if (matrix[row][col] !== null) {
            continue;
          }
          var bit = 0;
          if (bitIndex < codewords.length * 8) {
            bit = (codewords[bitIndex >>> 3] >>> (7 - (bitIndex & 7))) & 1;
          }
          matrix[row][col] = bit;
          bitIndex++;
        }
      }
      upward = !upward;
    }
  }

  var MASKS = [
    function (r, c) { return (r + c) % 2 === 0; },
    function (r) { return r % 2 === 0; },
    function (r, c) { return c % 3 === 0; },
    function (r, c) { return (r + c) % 3 === 0; },
    function (r, c) { return (Math.floor(r / 2) + Math.floor(c / 3)) % 2 === 0; },
    function (r, c) { return ((r * c) % 2) + ((r * c) % 3) === 0; },
    function (r, c) { return (((r * c) % 2) + ((r * c) % 3)) % 2 === 0; },
    function (r, c) { return (((r + c) % 2) + ((r * c) % 3)) % 2 === 0; }
  ];

  function isReserved(version, size, row, col) {
    // Finder patterns and their separators.
    if (row <= 8 && col <= 8) { return true; }
    if (row <= 8 && col >= size - 8) { return true; }
    if (row >= size - 8 && col <= 8) { return true; }
    // Timing patterns.
    if (row === 6 || col === 6) { return true; }
    // Version information.
    if (version >= 7 && ((row < 6 && col >= size - 11) || (col < 6 && row >= size - 11))) {
      return true;
    }
    // Alignment patterns.
    var centres = ALIGNMENT[version - 1];
    for (var i = 0; i < centres.length; i++) {
      for (var j = 0; j < centres.length; j++) {
        var cr = centres[i];
        var cc = centres[j];
        if (cr <= 8 && cc <= 8) { continue; }
        if (cr <= 8 && cc >= size - 9) { continue; }
        if (cr >= size - 9 && cc <= 8) { continue; }
        if (Math.abs(row - cr) <= 2 && Math.abs(col - cc) <= 2) { return true; }
      }
    }
    return false;
  }

  function applyMask(matrix, version, mask) {
    var size = matrix.length;
    for (var row = 0; row < size; row++) {
      for (var col = 0; col < size; col++) {
        if (isReserved(version, size, row, col)) {
          continue;
        }
        if (MASKS[mask](row, col)) {
          matrix[row][col] ^= 1;
        }
      }
    }
  }

  /**
   * The penalty score the standard defines, used to pick the mask that makes
   * the code easiest to read.
   */
  function penalty(matrix) {
    var size = matrix.length;
    var score = 0;
    var row, col, run, i;

    // Runs of five or more of the same colour, in both directions.
    for (row = 0; row < size; row++) {
      run = 1;
      for (col = 1; col < size; col++) {
        if (matrix[row][col] === matrix[row][col - 1]) {
          run++;
        } else {
          if (run >= 5) { score += run - 2; }
          run = 1;
        }
      }
      if (run >= 5) { score += run - 2; }
    }
    for (col = 0; col < size; col++) {
      run = 1;
      for (row = 1; row < size; row++) {
        if (matrix[row][col] === matrix[row - 1][col]) {
          run++;
        } else {
          if (run >= 5) { score += run - 2; }
          run = 1;
        }
      }
      if (run >= 5) { score += run - 2; }
    }

    // Two-by-two blocks of one colour.
    for (row = 0; row < size - 1; row++) {
      for (col = 0; col < size - 1; col++) {
        var v = matrix[row][col];
        if (v === matrix[row][col + 1] && v === matrix[row + 1][col] && v === matrix[row + 1][col + 1]) {
          score += 3;
        }
      }
    }

    // Patterns that look like a finder.
    var finder = [1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0];
    var reversed = finder.slice().reverse();
    function matches(get, start, pattern) {
      for (var k = 0; k < pattern.length; k++) {
        if (get(start + k) !== pattern[k]) { return false; }
      }
      return true;
    }
    for (row = 0; row < size; row++) {
      for (col = 0; col <= size - 11; col++) {
        var getRow = (function (r) { return function (x) { return matrix[r][x]; }; }(row));
        if (matches(getRow, col, finder) || matches(getRow, col, reversed)) { score += 40; }
      }
    }
    for (col = 0; col < size; col++) {
      for (row = 0; row <= size - 11; row++) {
        var getCol = (function (c) { return function (y) { return matrix[y][c]; }; }(col));
        if (matches(getCol, row, finder) || matches(getCol, row, reversed)) { score += 40; }
      }
    }

    // How far the balance of dark and light strays from half.
    var dark = 0;
    for (row = 0; row < size; row++) {
      for (col = 0; col < size; col++) {
        dark += matrix[row][col];
      }
    }
    var percent = (dark * 100) / (size * size);
    score += Math.floor(Math.abs(percent - 50) / 5) * 10;

    return score;
  }

  // --- The public shape ----------------------------------------------------

  /**
   * Encode text as a matrix of 0 and 1, one row per array.
   *
   * @param {string} text
   * @param {{level?: 'L'|'M'}} [options]
   * @returns {number[][]}
   */
  function encode(text, options) {
    if (typeof text !== 'string' || text === '') {
      throw new Error('allkiri-qr: nothing to encode');
    }
    var level = (options && options.level) || 'M';
    if (level !== 'L' && level !== 'M') {
      throw new Error('allkiri-qr: only error correction levels L and M are supported');
    }

    var version = chooseVersion(utf8Bytes(text).length, level);
    var codewords = encodeCodewords(text, version, level);
    var size = version * 4 + 17;

    var best = null;
    var bestScore = Infinity;
    var only = options && options.mask;
    for (var mask = 0; mask < 8; mask++) {
      if (only !== undefined && only !== null && mask !== only) {
        continue;
      }
      var matrix = newMatrix(size);
      placeFinder(matrix, 0, 0);
      placeFinder(matrix, 0, size - 7);
      placeFinder(matrix, size - 7, 0);
      placeAlignment(matrix, version);
      placeTiming(matrix);
      placeVersion(matrix, version);
      // The format cells are reserved before the data walk so it steps over them.
      placeFormat(matrix, level, mask);
      placeData(matrix, codewords);
      applyMask(matrix, version, mask);
      placeFormat(matrix, level, mask);

      var score = penalty(matrix);
      if (score < bestScore) {
        bestScore = score;
        best = matrix;
      }
    }
    return best;
  }

  /**
   * The same thing as an SVG, which is what a page actually wants.
   *
   * @param {string} text
   * @param {{level?: 'L'|'M', size?: number, quietZone?: number, dark?: string, light?: string, title?: string}} [options]
   * @returns {string}
   */
  function svg(text, options) {
    var settings = options || {};
    var matrix = encode(text, settings);
    var quiet = settings.quietZone === undefined ? 4 : settings.quietZone;
    var modules = matrix.length + quiet * 2;
    var pixels = settings.size || 256;
    var dark = settings.dark || '#000000';
    var light = settings.light || '#ffffff';

    var path = '';
    for (var row = 0; row < matrix.length; row++) {
      for (var col = 0; col < matrix.length; col++) {
        if (matrix[row][col]) {
          path += 'M' + (col + quiet) + ' ' + (row + quiet) + 'h1v1h-1z';
        }
      }
    }

    return '<svg xmlns="http://www.w3.org/2000/svg" width="' + pixels + '" height="' + pixels
      + '" viewBox="0 0 ' + modules + ' ' + modules + '" shape-rendering="crispEdges" role="img"'
      + (settings.title ? ' aria-label="' + settings.title.replace(/[<>&"]/g, '') + '"' : ' aria-hidden="true"')
      + '><rect width="' + modules + '" height="' + modules + '" fill="' + light + '"/>'
      + '<path d="' + path + '" fill="' + dark + '"/></svg>';
  }

  return { encode: encode, svg: svg };
}));
