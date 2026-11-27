#!/usr/bin/env node
/*
 * Obsor-JS classic engine + CLI.
 *
 * Node port of obsor's classic Python engine: stack together JS-native
 * encode/cipher/compress layers that each unwrap themselves at runtime via
 * `eval`. Same honest ceiling as the Python classic engine: every layer
 * resolves to a plaintext string and calls `eval()` on it, so one override
 * of the global `eval` recovers the final source, no matter how many layers
 * are stacked. See README.md -> "What classic does NOT protect against".
 *
 * No npm dependencies: everything here is a Node builtin (crypto, zlib).
 */
'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const zlib = require('zlib');

const AUTHOR = 'g0w6y';
const TOOL_NAME = 'Obsor-JS';
const VERSION = '1.0';

const NO_COLOR = !!process.env.NO_COLOR;
const col = (code, s) => (NO_COLOR ? s : `\x1b[${code}m${s}\x1b[0m`);
const cyan = (s) => col(36, s);
const yellow = (s) => col(33, s);
const green = (s) => col(32, s);
const red = (s) => col(31, s);

// Keys generated this run (for --save-keys). As with Python classic, these
// keys are ALSO embedded in the output file -- saving them is for your
// records only, never a security boundary. For an external key kept OUT of
// the file, use the PRO engine (pro/).
const GENERATED_KEYS = [];
const recordKey = (label, value) => GENERATED_KEYS.push(`${label}: ${value}`);

const BANNER = `
        _
   __.  \\ ___    ____   __.  .___
 .'   \\ |/   \\  (     .'   \\ /   \\
 |    | |    \`  \`--.  |    | |   '
  \`._.' \`___,' \\___.'  \`._.' /
`;

function randInt(min, max) {
  return min + crypto.randomInt(max - min + 1);
}
function randBytes(n) {
  return crypto.randomBytes(n);
}
function b64(buf) { return Buffer.from(buf).toString('base64'); }

// ---- Base32 (RFC 4648), Base85 (btoa85/Z85-style, base64-module-free) ----
const B32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function base32Encode(buf) {
  let bits = '';
  for (const b of buf) bits += b.toString(2).padStart(8, '0');
  while (bits.length % 5 !== 0) bits += '0';
  let out = '';
  for (let i = 0; i < bits.length; i += 5) out += B32_ALPHABET[parseInt(bits.slice(i, i + 5), 2)];
  while (out.length % 8 !== 0) out += '=';
  return out;
}
function base32Decode(str) {
  str = str.replace(/=+$/, '');
  let bits = '';
  for (const c of str) bits += B32_ALPHABET.indexOf(c).toString(2).padStart(5, '0');
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(bytes);
}
const B85_ALPHABET = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~';
function base85Encode(buf) {
  const padded = Buffer.concat([buf, Buffer.alloc((4 - (buf.length % 4)) % 4)]);
  let out = '';
  for (let i = 0; i < padded.length; i += 4) {
    let n = padded.readUInt32BE(i);
    let chunk = '';
    for (let j = 0; j < 5; j++) { chunk = B85_ALPHABET[n % 85] + chunk; n = Math.floor(n / 85); }
    out += chunk;
  }
  const pad = (4 - (buf.length % 4)) % 4;
  return pad ? out.slice(0, out.length - pad) : out;
}
function base85Decode(str) {
  const pad = (5 - (str.length % 5)) % 5;
  str = str + B85_ALPHABET[B85_ALPHABET.length - 1].repeat(pad);
  const bytes = [];
  for (let i = 0; i < str.length; i += 5) {
    let n = 0;
    for (let j = 0; j < 5; j++) n = n * 85 + B85_ALPHABET.indexOf(str[i + j]);
    bytes.push((n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff);
  }
  return Buffer.from(bytes.slice(0, bytes.length - pad));
}

// RC4, kept pure JS -- same algorithm as Python classic's rc4 method.
function rc4(data, key) {
  const S = Array.from({ length: 256 }, (_, i) => i);
  let j = 0;
  for (let i = 0; i < 256; i++) {
    j = (j + S[i] + key[i % key.length]) % 256;
    [S[i], S[j]] = [S[j], S[i]];
  }
  let i = 0; j = 0;
  const out = Buffer.alloc(data.length);
  for (let n = 0; n < data.length; n++) {
    i = (i + 1) % 256;
    j = (j + S[i]) % 256;
    [S[i], S[j]] = [S[j], S[i]];
    out[n] = data[n] ^ S[(S[i] + S[j]) % 256];
  }
  return out;
}

const jstr = (s) => JSON.stringify(s); // safe literal embed, handles backticks/quotes

// ---- Method table. Each `apply(code, opts)` returns a self-contained JS
// snippet that, when run with `node`, eval()s back to the original `code`.
const METHODS = {
  base64: {
    description: 'Base64 encoding',
    apply: (code) => {
      const enc = b64(Buffer.from(code, 'utf8'));
      return `eval(Buffer.from(${jstr(enc)}, 'base64').toString('utf8'));\n`;
    },
  },
  base32: {
    description: 'Base32 encoding (RFC 4648)',
    apply: (code) => {
      const enc = base32Encode(Buffer.from(code, 'utf8'));
      return `(function(){function d(s){const A='${B32_ALPHABET}';s=s.replace(/=+$/,'');let b='';` +
        `for(const c of s)b+=A.indexOf(c).toString(2).padStart(5,'0');const o=[];` +
        `for(let i=0;i+8<=b.length;i+=8)o.push(parseInt(b.slice(i,i+8),2));return Buffer.from(o).toString('utf8');}` +
        `eval(d(${jstr(enc)}));})();\n`;
    },
  },
  base85: {
    description: 'Base85 encoding (ASCII85-style)',
    apply: (code) => {
      const enc = base85Encode(Buffer.from(code, 'utf8'));
      return `(function(){const A='${B85_ALPHABET}';function d(s){const p=(5-(s.length%5))%5;` +
        `s=s+A[A.length-1].repeat(p);const by=[];for(let i=0;i<s.length;i+=5){let n=0;` +
        `for(let j=0;j<5;j++)n=n*85+A.indexOf(s[i+j]);by.push((n>>>24)&255,(n>>>16)&255,(n>>>8)&255,n&255);}` +
        `return Buffer.from(by.slice(0,by.length-p)).toString('utf8');}eval(d(${jstr(enc)}));})();\n`;
    },
  },
  hex: {
    description: 'Hexadecimal encoding',
    apply: (code) => `eval(Buffer.from(${jstr(Buffer.from(code, 'utf8').toString('hex'))}, 'hex').toString('utf8'));\n`,
  },
  octal: {
    description: 'Octal encoding',
    apply: (code) => {
      const oct = Array.from(Buffer.from(code, 'utf8')).map((b) => b.toString(8).padStart(3, '0')).join('');
      return `(function(){const s=${jstr(oct)};const o=[];for(let i=0;i<s.length;i+=3)o.push(parseInt(s.slice(i,i+3),8));` +
        `eval(Buffer.from(o).toString('utf8'));})();\n`;
    },
  },
  url: {
    description: 'URL percent-encoding',
    apply: (code) => `eval(decodeURIComponent(${jstr(encodeURIComponent(code))}));\n`,
  },
  charcode: {
    description: 'Convert to char codes array',
    apply: (code) => {
      const codes = Array.from(code).map((c) => c.codePointAt(0)).join(',');
      return `eval(String.fromCodePoint(${codes}));\n`;
    },
  },
  unicode: {
    description: 'JS \\u unicode-escape encoding',
    apply: (code) => {
      const esc = Array.from(code).map((c) => '\\u' + c.codePointAt(0).toString(16).padStart(4, '0')).join('');
      return `eval("${esc}");\n`;
    },
  },
  xor: {
    description: 'XOR encryption (single byte)',
    apply: (code, opts) => {
      let key = opts.key != null ? (isNaN(+opts.key) ? opts.key.charCodeAt(0) : +opts.key) : randInt(1, 255);
      key = key & 0xff;
      if (opts.key == null) { console.log(yellow(`[!] Generated random XOR key: ${key}`)); recordKey('XOR key', key); }
      const data = Buffer.from(code, 'utf8');
      const enc = Buffer.from(data.map((b) => b ^ key));
      return `(function(){const k=${key};const d=Buffer.from(${jstr(b64(enc))},'base64');` +
        `eval(Buffer.from(d.map(b=>b^k)).toString('utf8'));})();\n`;
    },
  },
  rc4: {
    description: 'RC4 stream cipher',
    apply: (code, opts) => {
      const keyBytes = opts.key != null ? Buffer.from(String(opts.key), 'latin1') : randBytes(16);
      if (opts.key == null) { console.log(yellow(`[!] Generated random RC4 key (base64): ${b64(keyBytes)}`)); recordKey('RC4 key (base64)', b64(keyBytes)); }
      const enc = rc4(Buffer.from(code, 'utf8'), keyBytes);
      return `(function(){const k=Buffer.from(${jstr(b64(keyBytes))},'base64');` +
        `const d=Buffer.from(${jstr(b64(enc))},'base64');` +
        `function rc4(data,key){const S=Array.from({length:256},(_,i)=>i);let j=0;` +
        `for(let i=0;i<256;i++){j=(j+S[i]+key[i%key.length])%256;[S[i],S[j]]=[S[j],S[i]];}` +
        `let i=0;j=0;const o=Buffer.alloc(data.length);for(let n=0;n<data.length;n++){` +
        `i=(i+1)%256;j=(j+S[i])%256;[S[i],S[j]]=[S[j],S[i]];o[n]=data[n]^S[(S[i]+S[j])%256];}return o;}` +
        `eval(rc4(d,k).toString('utf8'));})();\n`;
    },
  },
  caesar: {
    description: 'Caesar cipher with random shift (1-25)',
    apply: (code) => {
      const shift = randInt(1, 25);
      const enc = Array.from(code).map((c) => {
        if (c >= 'a' && c <= 'z') return String.fromCharCode((c.charCodeAt(0) - 97 + shift) % 26 + 97);
        if (c >= 'A' && c <= 'Z') return String.fromCharCode((c.charCodeAt(0) - 65 + shift) % 26 + 65);
        return c;
      }).join('');
      return `(function(){const sh=${shift};const s=${jstr(enc)};let r='';for(const c of s){` +
        `if(c>='a'&&c<='z')r+=String.fromCharCode((c.charCodeAt(0)-97-sh+26)%26+97);` +
        `else if(c>='A'&&c<='Z')r+=String.fromCharCode((c.charCodeAt(0)-65-sh+26)%26+65);else r+=c;}` +
        `eval(r);})();\n`;
    },
  },
  atbash: {
    description: 'Atbash cipher (reverse alphabet mapping)',
    apply: (code) => {
      const enc = Array.from(code).map((c) => {
        if (c >= 'a' && c <= 'z') return String.fromCharCode(97 + (25 - (c.charCodeAt(0) - 97)));
        if (c >= 'A' && c <= 'Z') return String.fromCharCode(65 + (25 - (c.charCodeAt(0) - 65)));
        return c;
      }).join('');
      return `(function(){const s=${jstr(enc)};let r='';for(const c of s){` +
        `if(c>='a'&&c<='z')r+=String.fromCharCode(97+(25-(c.charCodeAt(0)-97)));` +
        `else if(c>='A'&&c<='Z')r+=String.fromCharCode(65+(25-(c.charCodeAt(0)-65)));else r+=c;}` +
        `eval(r);})();\n`;
    },
  },
  vigenere: {
    description: 'Vigenère cipher with random keyword',
    apply: (code, opts) => {
      let keyword = opts.key != null ? String(opts.key).toUpperCase()
        : Array.from({ length: 8 }, () => String.fromCharCode(randInt(65, 90))).join('');
      if (opts.key == null) { console.log(yellow(`[!] Generated random Vigenère keyword: ${keyword}`)); recordKey('Vigenere keyword', keyword); }
      let ki = 0;
      const enc = Array.from(code).map((c) => {
        if (/[a-zA-Z]/.test(c)) {
          const shift = keyword.charCodeAt(ki % keyword.length) - 65;
          const base = c >= 'a' ? 97 : 65;
          const r = String.fromCharCode((c.charCodeAt(0) - base + shift) % 26 + base);
          ki++;
          return r;
        }
        return c;
      }).join('');
      return `(function(){const kw=${jstr(keyword)};const s=${jstr(enc)};let r='';let ki=0;` +
        `for(const c of s){if(/[a-zA-Z]/.test(c)){const sh=kw.charCodeAt(ki%kw.length)-65;` +
        `const base=c>='a'?97:65;r+=String.fromCharCode((c.charCodeAt(0)-base-sh+26)%26+base);ki++;}else r+=c;}` +
        `eval(r);})();\n`;
    },
  },
  polybius: {
    description: 'Polybius square cipher (A-Z, I/J combined)',
    apply: (code) => {
      const sq = ['ABCDE', 'FGHIK', 'LMNOP', 'QRSTU', 'VWXYZ'];
      const map = {};
      sq.forEach((row, r) => Array.from(row).forEach((ch, c) => { map[ch] = `${r + 1}${c + 1}`; if (ch === 'I') map.J = `${r + 1}${c + 1}`; }));
      let out = '';
      for (const ch of code) {
        const up = ch.toUpperCase();
        if (/[a-zA-Z]/.test(ch) && up === 'J') out += (ch === ch.toLowerCase() ? '6' : '') + '70';
        else if (/[a-zA-Z]/.test(ch) && map[up]) out += (ch === ch.toLowerCase() ? '6' : '') + map[up];
        else out += ch;
      }
      return `(function(){const sq=${jstr(sq)};const s=${jstr(out)};let r='';let i=0;` +
        `while(i<s.length){let lower=false;` +
        `if(s[i]==='6'&&i+2<s.length&&/\\d/.test(s[i+1])&&/\\d/.test(s[i+2])){lower=true;i++;}` +
        `if(s[i]==='7'&&i+1<s.length&&s[i+1]==='0'){r+=lower?'j':'J';i+=2;}` +
        `else if(/\\d/.test(s[i])&&i+1<s.length&&/\\d/.test(s[i+1])&&s[i]>='1'&&s[i]<='5'&&s[i+1]>='1'&&s[i+1]<='5'){` +
        `const row=sq[+s[i]-1];const ch=row[+s[i+1]-1];r+=lower?ch.toLowerCase():ch;i+=2;}` +
        `else{r+=s[i];i++;}}eval(r);})();\n`;
    },
  },
  rot13: {
    description: 'ROT13 encoding',
    apply: (code) => {
      const rot = (s) => Array.from(s).map((c) => {
        if (c >= 'a' && c <= 'z') return String.fromCharCode((c.charCodeAt(0) - 97 + 13) % 26 + 97);
        if (c >= 'A' && c <= 'Z') return String.fromCharCode((c.charCodeAt(0) - 65 + 13) % 26 + 65);
        return c;
      }).join('');
      return `(function(){function rot(s){let r='';for(const c of s){` +
        `if(c>='a'&&c<='z')r+=String.fromCharCode((c.charCodeAt(0)-97+13)%26+97);` +
        `else if(c>='A'&&c<='Z')r+=String.fromCharCode((c.charCodeAt(0)-65+13)%26+65);else r+=c;}return r;}` +
        `eval(rot(${jstr(rot(code))}));})();\n`;
    },
  },
  reverse: {
    description: 'Reverse entire code',
    apply: (code) => `eval(${jstr(Array.from(code).reverse().join(''))}.split('').reverse().join(''));\n`,
  },
  whitespace: {
    description: 'Whitespace (space/tab) binary encoding',
    apply: (code) => {
      const bits = Array.from(Buffer.from(code, 'utf8')).map((b) => b.toString(2).padStart(8, '0')).join('');
      const ws = bits.replace(/0/g, ' ').replace(/1/g, '\t');
      return `(function(){const s=${jstr(ws)};let b='';for(const c of s)b+=(c===' '?'0':'1');` +
        `const by=[];for(let i=0;i+8<=b.length;i+=8)by.push(parseInt(b.slice(i,i+8),2));` +
        `eval(Buffer.from(by).toString('utf8'));})();\n`;
    },
  },
  split: {
    description: 'Split code into chunks and reassemble',
    apply: (code, opts) => {
      const size = opts.chunkSize || 50;
      const chunks = [];
      for (let i = 0; i < code.length; i += size) chunks.push(code.slice(i, i + size));
      const enc = chunks.map((c) => b64(Buffer.from(c, 'utf8')));
      return `(function(){const cs=${jstr(enc)};eval(cs.map(c=>Buffer.from(c,'base64').toString('utf8')).join(''));})();\n`;
    },
  },
  minify: {
    description: 'Strip comments/blank lines (best-effort, regex-based)',
    apply: (code) => code
      .replace(/\/\*[\s\S]*?\*\//g, '')
      .split('\n')
      .map((l) => l.trim())
      .filter((l) => l && !l.startsWith('//'))
      .join('\n'),
  },
  zlib: {
    description: 'zlib (DEFLATE) compression + Base64',
    apply: (code) => {
      const comp = zlib.deflateSync(Buffer.from(code, 'utf8'));
      return `eval(require('zlib').inflateSync(Buffer.from(${jstr(b64(comp))},'base64')).toString('utf8'));\n`;
    },
  },
  gzip: {
    description: 'gzip compression + Base64',
    apply: (code) => {
      const comp = zlib.gzipSync(Buffer.from(code, 'utf8'));
      return `eval(require('zlib').gunzipSync(Buffer.from(${jstr(b64(comp))},'base64')).toString('utf8'));\n`;
    },
  },
  aes: {
    description: 'AES-256-CBC (node:crypto builtin, no dependency)',
    apply: (code, opts) => {
      let key;
      if (opts.key != null) key = crypto.createHash('sha256').update(String(opts.key)).digest();
      else { key = randBytes(32); console.log(yellow(`[!] Generated random AES key (base64): ${b64(key)}`)); recordKey('AES key (base64)', b64(key)); }
      const iv = randBytes(16);
      const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
      const enc = Buffer.concat([cipher.update(code, 'utf8'), cipher.final()]);
      return `(function(){const crypto=require('crypto');` +
        `const key=Buffer.from(${jstr(b64(key))},'base64');const iv=Buffer.from(${jstr(b64(iv))},'base64');` +
        `const d=crypto.createDecipheriv('aes-256-cbc',key,iv);` +
        `eval(Buffer.concat([d.update(Buffer.from(${jstr(b64(enc))},'base64')),d.final()]).toString('utf8'));})();\n`;
    },
  },
};

const PRESETS = {
  military: ['minify', 'aes', 'zlib', 'base85', 'split', 'reverse', 'vigenere'],
  max: ['minify', 'aes', 'gzip', 'base64', 'xor', 'whitespace', 'rc4'],
  light: ['base64', 'reverse'],
  stealth: ['whitespace', 'split', 'charcode', 'hex', 'url'],
};

function applyLayers(original, methodList, opts) {
  let current = original;
  const applied = [];
  for (const m of methodList) {
    if (!METHODS[m]) throw new Error(`Unknown method: ${m}`);
    current = METHODS[m].apply(current, opts);
    applied.push(m);
  }
  return { code: current, applied };
}

function listMethods() {
  console.log(cyan('\nAvailable methods:\n'));
  for (const [name, m] of Object.entries(METHODS)) console.log(yellow(`  ${name.padEnd(12)} - ${m.description}`));
  console.log('\nPresets:');
  for (const [preset, methods] of Object.entries(PRESETS)) console.log(green(`  ${preset.padEnd(10)} -> ${methods.join(', ')}`));
  console.log();
}

function testObfuscated(scriptPath) {
  console.log(yellow(`\n[test] Testing obfuscated script: ${scriptPath}`));
  const { spawnSync } = require('child_process');
  const res = spawnSync(process.execPath, [scriptPath], { encoding: 'utf8', timeout: 10000 });
  if (res.status === 0) {
    console.log(green('[ok] Test passed: script executed successfully'));
    if (res.stdout) console.log(cyan('Output:\n' + (res.stdout.length > 500 ? res.stdout.slice(0, 500) + '...' : res.stdout)));
  } else {
    console.log(red(`[!] Test failed (status ${res.status ?? 'timeout'})`));
    if (res.stderr) console.log(red('Error:\n' + res.stderr));
  }
}

function parseArgs(argv) {
  const args = { output: 'obfuscated.js', methods: 'base64', chunkSize: 50 };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = () => argv[++i];
    switch (a) {
      case '-i': case '--input': args.input = next(); break;
      case '-o': case '--output': args.output = next(); break;
      case '-m': case '--methods': args.methods = next(); break;
      case '--preset': args.preset = next(); break;
      case '-k': case '--key': args.key = next(); break;
      case '--chunk-size': args.chunkSize = parseInt(next(), 10); break;
      case '--list-methods': args.listMethods = true; break;
      case '--test': args.test = true; break;
      case '--save-keys': args.saveKeys = true; break;
      case '-h': case '--help': args.help = true; break;
      default: console.log(red(`[!] Unknown argument: ${a}`)); process.exit(1);
    }
  }
  return args;
}

function printHelp() {
  console.log(`Usage: node main.js -i INPUT [-o OUTPUT] [-m METHODS] [--preset NAME] [-k KEY]
    [--chunk-size N] [--list-methods] [--test] [--save-keys]`);
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  console.log(cyan(BANNER));
  console.log(yellow(`Author: ${AUTHOR} | ${TOOL_NAME} v${VERSION}\n`));

  if (args.help) return printHelp();
  if (args.listMethods) return listMethods();
  if (!args.input) { console.log(red('[!] -i/--input is required')); return printHelp(); }
  if (!fs.existsSync(args.input)) { console.log(red(`[!] File not found: ${args.input}`)); return; }

  let methodList;
  if (args.preset) {
    if (!PRESETS[args.preset]) { console.log(red(`[!] Unknown preset: ${args.preset}`)); return; }
    methodList = PRESETS[args.preset];
    console.log(cyan(`[*] Using preset '${args.preset}': ${methodList.join(', ')}`));
  } else {
    methodList = args.methods.split(',').map((s) => s.trim()).filter(Boolean);
  }
  for (const m of methodList) {
    if (!METHODS[m]) { console.log(red(`[!] Unknown method: ${m}`)); listMethods(); return; }
  }

  const original = fs.readFileSync(args.input, 'utf8');
  let result;
  try {
    result = applyLayers(original, methodList, { key: args.key, chunkSize: args.chunkSize });
  } catch (e) {
    console.log(red(`\n[!] Error: ${e.message}`));
    return;
  }

  fs.writeFileSync(args.output, result.code, 'utf8');
  console.log(green(`\n[ok] Saved to ${args.output}`));
  console.log(cyan(`    Layers: ${result.applied.join(' -> ')}`));

  if (args.saveKeys) {
    if (GENERATED_KEYS.length) {
      fs.writeFileSync(args.output + '.keys', GENERATED_KEYS.join('\n') + '\n', 'utf8');
      console.log(yellow(`[key] Keys saved to ${args.output}.keys`));
    } else {
      console.log(yellow('[!] No random keys generated (nothing to save)'));
    }
  }

  if (args.test) testObfuscated(args.output);
}

if (require.main === module) main();

module.exports = { METHODS, PRESETS, applyLayers };
