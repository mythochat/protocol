#!/usr/bin/env node
/**
 * Deterministic KAT vector generator for the mytho.chat protocol.
 *
 * Outputs to ../vectors/*.json. Reproducible: pinned seed + pinned library versions.
 * Conforms to docs/kat-vectors-format.md schema "mytho.chat/kat/v1".
 *
 * Usage:
 *   cd scripts && pnpm install && pnpm run generate-kat
 */

import { writeFileSync, mkdirSync, readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ml_kem768 } from '@noble/post-quantum/ml-kem';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa';
import { sha256 } from '@noble/hashes/sha2';
import { hkdf } from '@noble/hashes/hkdf';
import { hmac } from '@noble/hashes/hmac';
import { randomBytes } from '@noble/hashes/utils';

const __dirname = dirname(fileURLToPath(import.meta.url));
const VECTORS_DIR = resolve(__dirname, '../vectors');
mkdirSync(VECTORS_DIR, { recursive: true });

const PKG = JSON.parse(readFileSync(resolve(__dirname, 'package.json'), 'utf8'));
const PINNED = {
  '@noble/post-quantum': PKG.dependencies['@noble/post-quantum'],
  '@noble/hashes': PKG.dependencies['@noble/hashes'],
  '@noble/ciphers': PKG.dependencies['@noble/ciphers'],
};

// Spec uses 2026-06-01 build date as the generation timestamp anchor.
const GENERATED_AT = '2026-06-01T00:00:00Z';

// Deterministic seed for the generator (pinned).
const SEED = new Uint8Array(32);
for (let i = 0; i < 32; i++) SEED[i] = i; // 0x00 0x01 0x02 ... 0x1F

// ---- helpers ----
const hex = (u8) => Buffer.from(u8).toString('hex');
const utf8 = (s) => new TextEncoder().encode(s);
const u32be = (n) => {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n, false);
  return b;
};
const u64be = (n) => {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, BigInt(n), false);
  return b;
};

function commonMeta(primitive, specRef) {
  return {
    schema: 'mytho.chat/kat/v1',
    wire_version: 1,
    primitive,
    spec_ref: specRef,
    generator: {
      script: 'scripts/generate-kat.mjs',
      noble_versions: PINNED,
      seed: hex(SEED),
      generated_at: GENERATED_AT,
    },
    cases: [],
  };
}

// ---- 1) peerId derivation ----
function genPeerIdVector() {
  const out = commonMeta('peerid-derivation', 'docs/wire-format.md §2');
  // Two deterministic test cases using ML-DSA-65 keypairs from pinned seeds.
  const seedA = sha256(new Uint8Array([...utf8('peerid-test-a'), ...SEED]));
  const seedB = sha256(new Uint8Array([...utf8('peerid-test-b'), ...SEED]));

  const kpA = ml_dsa65.keygen(seedA);
  const kpB = ml_dsa65.keygen(seedB);
  const pkA = kpA.publicKey ?? kpA;
  const pkB = kpB.publicKey ?? kpB;

  out.cases.push({
    label: 'ML-DSA-65 keypair derived from seed = sha256("peerid-test-a" || pinned_seed)',
    inputs: {
      ik_pub_dilithium_hex: hex(pkA),
      ik_pub_dilithium_length: pkA.length,
    },
    outputs: {
      peer_id_hex: hex(sha256(pkA)),
      peer_id_length: 32,
    },
    notes: 'peerId = SHA-256(IK_pub_dilithium); raw 1952-byte ML-DSA-65 public key per FIPS 204 §7.',
  });
  out.cases.push({
    label: 'ML-DSA-65 keypair derived from seed = sha256("peerid-test-b" || pinned_seed)',
    inputs: {
      ik_pub_dilithium_hex: hex(pkB),
      ik_pub_dilithium_length: pkB.length,
    },
    outputs: {
      peer_id_hex: hex(sha256(pkB)),
      peer_id_length: 32,
    },
  });

  writeFileSync(resolve(VECTORS_DIR, 'peerid-derivation.json'), JSON.stringify(out, null, 2));
}

// ---- 2) AAD encoding ----
function genAadVector() {
  const out = commonMeta('aad-encoding', 'docs/wire-format.md §5.2');

  const cases = [
    {
      label: 'AAD case 1: zero values',
      inputs: { payload_version: 0x01, ratchet_flags: 0x00, message_number: 0, recipient_peer_id_hex: '00'.repeat(32) },
    },
    {
      label: 'AAD case 2: typical mid-chain message',
      inputs: { payload_version: 0x01, ratchet_flags: 0x02, message_number: 42, recipient_peer_id_hex: 'ab'.repeat(32) },
    },
    {
      label: 'AAD case 3: max message_number (u32 max)',
      inputs: { payload_version: 0x01, ratchet_flags: 0x03, message_number: 0xFFFFFFFF, recipient_peer_id_hex: 'ff'.repeat(32) },
    },
  ];

  for (const c of cases) {
    const aad = new Uint8Array(38);
    aad[0] = c.inputs.payload_version;
    aad[1] = c.inputs.ratchet_flags;
    aad.set(u32be(c.inputs.message_number), 2);
    aad.set(Buffer.from(c.inputs.recipient_peer_id_hex, 'hex'), 6);
    out.cases.push({
      label: c.label,
      inputs: c.inputs,
      outputs: {
        aad_hex: hex(aad),
        aad_length: 38,
      },
    });
  }

  writeFileSync(resolve(VECTORS_DIR, 'aad-encoding.json'), JSON.stringify(out, null, 2));
}

// ---- 3) ISO 7816-4 padding ----
function genPaddingVector() {
  const out = commonMeta('padding-7816', 'docs/wire-format.md §5.3');

  function pad(plaintext, bin) {
    // ISO/IEC 7816-4: append 0x80 then 0x00 until length == bin.
    // If plaintext length already == bin, append an entire extra block.
    const needed = bin - plaintext.length;
    if (needed >= 1) {
      const out = new Uint8Array(bin);
      out.set(plaintext);
      out[plaintext.length] = 0x80;
      // rest is 0x00 from default fill
      return out;
    }
    // exact-fit: append an extra block
    const out = new Uint8Array(plaintext.length + bin);
    out.set(plaintext);
    out[plaintext.length] = 0x80;
    return out;
  }

  const cases = [
    { label: 'Empty plaintext, bin=1024', plaintext: new Uint8Array([]), bin: 1024 },
    { label: 'Partial-fit plaintext (13 bytes), bin=1024', plaintext: utf8('hello mytho!!'), bin: 1024 },
    { label: 'Exact-fit plaintext (1024 bytes), bin=1024 — extra block appended', plaintext: new Uint8Array(1024).fill(0x41), bin: 1024 },
  ];

  for (const c of cases) {
    const padded = pad(c.plaintext, c.bin);
    out.cases.push({
      label: c.label,
      inputs: {
        plaintext_hex: hex(c.plaintext),
        plaintext_length: c.plaintext.length,
        bin: c.bin,
      },
      outputs: {
        padded_hex_first_32: hex(padded.slice(0, 32)),
        padded_hex_last_32: hex(padded.slice(-32)),
        padded_length: padded.length,
      },
    });
  }

  writeFileSync(resolve(VECTORS_DIR, 'padding-7816.json'), JSON.stringify(out, null, 2));
}

// ---- 4) AEAD nonce derivation via HKDF-Expand ----
function genNonceVector() {
  const out = commonMeta('aead-nonce-derivation', 'docs/wire-format.md §5.1');

  const cases = [
    { label: 'MK = all zeros', mk: new Uint8Array(32) },
    { label: 'MK = all 0xAA', mk: new Uint8Array(32).fill(0xAA) },
    { label: 'MK = derived from pinned seed', mk: sha256(SEED) },
  ];

  for (const c of cases) {
    const nonce = hkdf(sha256, c.mk, new Uint8Array(0), utf8('mytho/nonce/v1'), 24);
    out.cases.push({
      label: c.label,
      inputs: {
        mk_hex: hex(c.mk),
        info_ascii: 'mytho/nonce/v1',
        length: 24,
      },
      outputs: {
        nonce_hex: hex(nonce),
        nonce_length: 24,
      },
      notes: 'HKDF-Expand(salt=empty, ikm=MK, info="mytho/nonce/v1", L=24) — RFC 5869.',
    });
  }

  writeFileSync(resolve(VECTORS_DIR, 'aead-nonce-derivation.json'), JSON.stringify(out, null, 2));
}

// ---- 5) delivery_token HMAC ----
function genDeliveryTokenVector() {
  const out = commonMeta('delivery-token', 'docs/wire-format.md §4');

  const serverPepper = sha256(new Uint8Array([...utf8('pinned-pepper'), ...SEED]));
  const senderId = sha256(utf8('sender-A'));
  const recipientId = sha256(utf8('recipient-B'));
  const nonce = sha256(utf8('nonce-1')).slice(0, 16);
  const exp = 1717200000; // pinned epoch seconds

  const data = new Uint8Array(32 + 32 + 16 + 8);
  data.set(senderId, 0);
  data.set(recipientId, 32);
  data.set(nonce, 64);
  data.set(u64be(exp), 80);
  const mac = hmac(sha256, serverPepper, data);

  out.cases.push({
    label: 'Standard delivery_token case',
    inputs: {
      server_pepper_hex: hex(serverPepper),
      sender_peer_id_hex: hex(senderId),
      recipient_peer_id_hex: hex(recipientId),
      nonce_hex: hex(nonce),
      exp_epoch_seconds: exp,
      data_hex: hex(data),
    },
    outputs: {
      mac_hex: hex(mac),
      mac_length: 32,
    },
    notes: 'HMAC-SHA-256(server_pepper, sender || recipient || nonce || exp_be64). Full 32-byte output, no truncation.',
  });

  writeFileSync(resolve(VECTORS_DIR, 'delivery-token.json'), JSON.stringify(out, null, 2));
}

// ---- 6) HKDF chain step (RK + CK rotation) ----
function genHkdfChainStepVector() {
  const out = commonMeta('hkdf-chain-step', 'docs/ratchet-state-machine.md §4');

  const RK = sha256(new Uint8Array([...utf8('root-key-init'), ...SEED]));
  const kemSharedSecret = sha256(new Uint8Array([...utf8('kem-shared-secret'), ...SEED]));

  // Two-output HKDF: 32 bytes RK_next + 32 bytes CK_0
  const expanded = hkdf(sha256, kemSharedSecret, RK, utf8('mytho/rk/v1'), 64);
  const RK_next = expanded.slice(0, 32);
  const CK_0 = expanded.slice(32, 64);

  // Chain step: CK_0 -> CK_1 + MK_0
  const ck0Expand = hkdf(sha256, CK_0, new Uint8Array(0), utf8('mytho/ck/v1'), 32);
  const mk0Expand = hkdf(sha256, CK_0, new Uint8Array(0), utf8('mytho/mk/v1'), 32);

  out.cases.push({
    label: 'KEM ratchet step: RK_n + kem_ss -> RK_n+1, CK_0',
    inputs: {
      root_key_hex: hex(RK),
      kem_shared_secret_hex: hex(kemSharedSecret),
      info_ascii: 'mytho/rk/v1',
      length: 64,
    },
    outputs: {
      rk_next_hex: hex(RK_next),
      ck_0_hex: hex(CK_0),
    },
    notes: 'HKDF-Expand(salt=RK_n, ikm=kem_ss, info="mytho/rk/v1", L=64); split into RK_next (32B) || CK_0 (32B).',
  });

  out.cases.push({
    label: 'Chain key step: CK_0 -> CK_1 and MK_0',
    inputs: {
      chain_key_hex: hex(CK_0),
      info_ck_ascii: 'mytho/ck/v1',
      info_mk_ascii: 'mytho/mk/v1',
      length: 32,
    },
    outputs: {
      ck_1_hex: hex(ck0Expand),
      mk_0_hex: hex(mk0Expand),
    },
    notes: 'Two independent HKDF-Expand calls with distinct info labels (domain separation).',
  });

  writeFileSync(resolve(VECTORS_DIR, 'hkdf-chain-step.json'), JSON.stringify(out, null, 2));
}

// ---- 7) X3DH-PQ handshake ----
function genHandshakeVector() {
  const out = commonMeta('handshake-x3dh-pq', 'docs/ratchet-state-machine.md §3');

  // Responder publishes prekey bundle: IK, SPK, OTPK (all ML-KEM where applicable).
  // ML-KEM-768 keygen seed must be 64 bytes per FIPS 203 §7.1 (d || z).
  const spkSeed = new Uint8Array(64);
  spkSeed.set(sha256(new Uint8Array([...utf8('spk-seed-d'), ...SEED])), 0);
  spkSeed.set(sha256(new Uint8Array([...utf8('spk-seed-z'), ...SEED])), 32);
  const otpkSeed = new Uint8Array(64);
  otpkSeed.set(sha256(new Uint8Array([...utf8('otpk-seed-d'), ...SEED])), 0);
  otpkSeed.set(sha256(new Uint8Array([...utf8('otpk-seed-z'), ...SEED])), 32);
  const SPK = ml_kem768.keygen(spkSeed);
  const OTPK = ml_kem768.keygen(otpkSeed);

  const SPK_pub = SPK.publicKey ?? SPK;
  const OTPK_pub = OTPK.publicKey ?? OTPK;

  // Initiator encapsulates against both. ML-KEM-768 encapsulate seed must be 32 bytes (m).
  const encSeed1 = sha256(new Uint8Array([...utf8('init-spk'), ...SEED]));
  const encSeed2 = sha256(new Uint8Array([...utf8('init-otpk'), ...SEED]));
  const encapSpk = ml_kem768.encapsulate(SPK_pub, encSeed1);
  const encapOtpk = ml_kem768.encapsulate(OTPK_pub, encSeed2);

  const ssSpk = encapSpk.sharedSecret ?? encapSpk[1];
  const ssOtpk = encapOtpk.sharedSecret ?? encapOtpk[1];
  const ctSpk = encapSpk.cipherText ?? encapSpk[0];
  const ctOtpk = encapOtpk.cipherText ?? encapOtpk[0];

  // Combined IKM = ss_spk || ss_otpk; SK derived via HKDF-Expand info="mytho/handshake/v1", L=32.
  const ikm = new Uint8Array(ssSpk.length + ssOtpk.length);
  ikm.set(ssSpk, 0);
  ikm.set(ssOtpk, ssSpk.length);
  const SK = hkdf(sha256, ikm, new Uint8Array(0), utf8('mytho/handshake/v1'), 32);

  out.cases.push({
    label: 'X3DH-PQ handshake (PQ-only, no classical leg) — single test case',
    inputs: {
      spk_pub_length: SPK_pub.length,
      otpk_pub_length: OTPK_pub.length,
      ct_spk_length: ctSpk.length,
      ct_otpk_length: ctOtpk.length,
      ss_spk_length: ssSpk.length,
      ss_otpk_length: ssOtpk.length,
      ikm_hex: hex(ikm),
      info_ascii: 'mytho/handshake/v1',
      length: 32,
    },
    outputs: {
      sk_hex: hex(SK),
      sk_length: 32,
    },
    notes: 'PQ-only X3DH variant: SK = HKDF-Expand(salt=empty, ikm=ss_spk||ss_otpk, info="mytho/handshake/v1", L=32). No classical X25519 leg; see README.md §5 construction note.',
  });

  writeFileSync(resolve(VECTORS_DIR, 'handshake-x3dh-pq.json'), JSON.stringify(out, null, 2));
}

// ---- main ----
console.log('Generating KAT vectors for mytho.chat protocol v0.2…');
genPeerIdVector();        console.log('  ✓ vectors/peerid-derivation.json');
genAadVector();           console.log('  ✓ vectors/aad-encoding.json');
genPaddingVector();       console.log('  ✓ vectors/padding-7816.json');
genNonceVector();         console.log('  ✓ vectors/aead-nonce-derivation.json');
genDeliveryTokenVector(); console.log('  ✓ vectors/delivery-token.json');
genHkdfChainStepVector(); console.log('  ✓ vectors/hkdf-chain-step.json');
genHandshakeVector();     console.log('  ✓ vectors/handshake-x3dh-pq.json');
console.log('Done.');
