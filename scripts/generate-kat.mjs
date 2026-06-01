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
import { xchacha20poly1305 } from '@noble/ciphers/chacha';

const __dirname = dirname(fileURLToPath(import.meta.url));
const VECTORS_DIR = resolve(__dirname, '../vectors');
mkdirSync(VECTORS_DIR, { recursive: true });

/**
 * Read the RESOLVED version of a dependency from its installed
 * node_modules/<pkg>/package.json (not the specifier in our package.json).
 * This pins the exact bytes-producing library version into every vector.
 */
function resolvedVersion(pkg) {
  const p = resolve(__dirname, 'node_modules', pkg, 'package.json');
  return JSON.parse(readFileSync(p, 'utf8')).version;
}

const NOBLE_VERSIONS = {
  '@noble/post-quantum': resolvedVersion('@noble/post-quantum'),
  '@noble/hashes': resolvedVersion('@noble/hashes'),
  '@noble/ciphers': resolvedVersion('@noble/ciphers'),
};

// Spec uses 2026-06-01 build date as the generation timestamp anchor.
const GENERATED_AT = '2026-06-01T00:00:00Z';

// Deterministic seed for the generator (pinned).
const SEED = new Uint8Array(32);
for (let i = 0; i < 32; i++) SEED[i] = i; // 0x00 0x01 0x02 ... 0x1F

// Canonical HKDF labels (CANON-4).
const INFO_RK = 'mytho/rk/v1';
const INFO_CK = 'mytho/ck/v1';
const INFO_MK = 'mytho/mk/v1';
const INFO_NONCE = 'mytho/nonce/v1';
const INFO_HANDSHAKE = 'mytho/handshake/v1';

// RFC 5869 §2.2: an absent HKDF salt is treated as HashLen zero bytes.
const EMPTY_SALT = new Uint8Array(0);
const EMPTY_SALT_NOTE = 'empty salt = 32 zero bytes per RFC 5869 §2.2';

// Bounded skipped-message-key cache (ratchet §5).
const MAX_SKIP = 2000;

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

/** Symmetric chain step (CANON-2): both calls share (salt="", IKM=CK_n), distinct info. */
const chainAdvance = (ck) => hkdf(sha256, ck, EMPTY_SALT, utf8(INFO_CK), 32); // CK_{n+1}
const messageKey = (ck) => hkdf(sha256, ck, EMPTY_SALT, utf8(INFO_MK), 32); // MK_n
const aeadNonce = (mk) => hkdf(sha256, mk, EMPTY_SALT, utf8(INFO_NONCE), 24); // CANON-3

/** Build the 38-byte AAD (docs/wire-format.md §5.2). */
function buildAad({ payload_version, ratchet_flags, message_number, recipient_peer_id_hex }) {
  const aad = new Uint8Array(38);
  aad[0] = payload_version;
  aad[1] = ratchet_flags;
  aad.set(u32be(message_number), 2);
  aad.set(Buffer.from(recipient_peer_id_hex, 'hex'), 6);
  return aad;
}

/**
 * ISO/IEC 7816-4 padding: append 0x80 then 0x00 until length == bin.
 * If plaintext length already == bin, append an entire extra block.
 */
function pad7816(plaintext, bin) {
  const needed = bin - plaintext.length;
  if (needed >= 1) {
    const out = new Uint8Array(bin);
    out.set(plaintext);
    out[plaintext.length] = 0x80;
    return out; // rest is 0x00 from default fill
  }
  // exact-fit: append an extra block
  const out = new Uint8Array(plaintext.length + bin);
  out.set(plaintext);
  out[plaintext.length] = 0x80;
  return out;
}

function commonMeta(primitive, specRef) {
  return {
    schema: 'mytho.chat/kat/v1',
    wire_version: 1,
    primitive,
    spec_ref: specRef,
    generator: {
      script: 'scripts/generate-kat.mjs',
      noble_versions: NOBLE_VERSIONS,
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
    const aad = buildAad(c.inputs);
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

  const cases = [
    { label: 'Empty plaintext, bin=1024', plaintext: new Uint8Array([]), bin: 1024 },
    { label: 'Partial-fit plaintext (13 bytes), bin=1024', plaintext: utf8('hello mytho!!'), bin: 1024 },
    { label: 'Exact-fit plaintext (1024 bytes), bin=1024 — extra block appended', plaintext: new Uint8Array(1024).fill(0x41), bin: 1024 },
  ];

  for (const c of cases) {
    const padded = pad7816(c.plaintext, c.bin);
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

// ---- 4) AEAD nonce derivation via HKDF ----
function genNonceVector() {
  const out = commonMeta('aead-nonce-derivation', 'docs/wire-format.md §5.1');

  const cases = [
    { label: 'MK = all zeros', mk: new Uint8Array(32) },
    { label: 'MK = all 0xAA', mk: new Uint8Array(32).fill(0xAA) },
    { label: 'MK = derived from pinned seed', mk: sha256(SEED) },
  ];

  for (const c of cases) {
    const nonce = aeadNonce(c.mk);
    out.cases.push({
      label: c.label,
      inputs: {
        mk_hex: hex(c.mk),
        salt: '',
        salt_note: EMPTY_SALT_NOTE,
        info_ascii: INFO_NONCE,
        length: 24,
      },
      outputs: {
        nonce_hex: hex(nonce),
        nonce_length: 24,
      },
      notes: 'HKDF (Extract+Expand, RFC 5869, empty salt) over IKM=MK, info="mytho/nonce/v1", L=24.',
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

  // KEM ratchet step (CANON-1): salt = RK_n (the natural salt), IKM = kem_ss,
  // info = "mytho/rk/v1", L=64; split into RK_next (32B) || CK_0 (32B).
  const expanded = hkdf(sha256, kemSharedSecret, RK, utf8(INFO_RK), 64);
  const RK_next = expanded.slice(0, 32);
  const CK_0 = expanded.slice(32, 64);

  // Chain step (CANON-2): CK_0 -> CK_1 + MK_0
  const CK_1 = chainAdvance(CK_0);
  const MK_0 = messageKey(CK_0);

  out.cases.push({
    label: 'KEM ratchet step: RK_n + kem_ss -> RK_n+1, CK_0',
    inputs: {
      root_key_hex: hex(RK),
      kem_shared_secret_hex: hex(kemSharedSecret),
      salt: hex(RK),
      salt_note: 'KEM step uses a natural salt = the current Root Key (RK_n), not the empty salt.',
      info_ascii: INFO_RK,
      length: 64,
    },
    outputs: {
      rk_next_hex: hex(RK_next),
      ck_0_hex: hex(CK_0),
    },
    notes: 'HKDF (Extract+Expand, RFC 5869): PRK=HKDF-Extract(salt=RK_n, IKM=kem_ss); RK_next||CK_0=HKDF-Expand(PRK, info="mytho/rk/v1", L=64); split 32||32.',
  });

  out.cases.push({
    label: 'Chain key step: CK_0 -> CK_1 and MK_0',
    inputs: {
      chain_key_hex: hex(CK_0),
      salt: '',
      salt_note: EMPTY_SALT_NOTE,
      info_ck_ascii: INFO_CK,
      info_mk_ascii: INFO_MK,
      length: 32,
    },
    outputs: {
      ck_1_hex: hex(CK_1),
      mk_0_hex: hex(MK_0),
    },
    notes: 'Two HKDF (Extract+Expand, RFC 5869, empty salt) calls sharing (salt="", IKM=CK_0) with distinct info labels (domain separation).',
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

  // Combined IKM = ss_spk || ss_otpk; SK derived via HKDF info="mytho/handshake/v1", L=32.
  const ikm = new Uint8Array(ssSpk.length + ssOtpk.length);
  ikm.set(ssSpk, 0);
  ikm.set(ssOtpk, ssSpk.length);
  const SK = hkdf(sha256, ikm, EMPTY_SALT, utf8(INFO_HANDSHAKE), 32);

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
      salt: '',
      salt_note: EMPTY_SALT_NOTE,
      info_ascii: INFO_HANDSHAKE,
      length: 32,
    },
    outputs: {
      sk_hex: hex(SK),
      sk_length: 32,
    },
    notes: 'PQ-only X3DH variant: SK = HKDF (Extract+Expand, RFC 5869, empty salt) over IKM=ss_spk||ss_otpk, info="mytho/handshake/v1", L=32. No classical X25519 leg; see README.md §5 construction note.',
  });

  writeFileSync(resolve(VECTORS_DIR, 'handshake-x3dh-pq.json'), JSON.stringify(out, null, 2));
}

// ---- 8) AEAD roundtrip (XChaCha20-Poly1305) ----
function genAeadRoundtripVector() {
  const out = commonMeta('aead-roundtrip', 'docs/wire-format.md §5.1');

  const cases = [
    {
      label: 'AEAD roundtrip: MK from pinned seed, empty plaintext padded to bin=1024',
      mk: sha256(new Uint8Array([...utf8('aead-mk-1'), ...SEED])),
      aadInputs: { payload_version: 0x01, ratchet_flags: 0x00, message_number: 0, recipient_peer_id_hex: 'cc'.repeat(32) },
      plaintext: new Uint8Array([]),
      bin: 1024,
    },
    {
      label: 'AEAD roundtrip: MK from pinned seed, 13-byte plaintext padded to bin=1024',
      mk: sha256(new Uint8Array([...utf8('aead-mk-2'), ...SEED])),
      aadInputs: { payload_version: 0x01, ratchet_flags: 0x02, message_number: 7, recipient_peer_id_hex: 'dd'.repeat(32) },
      plaintext: utf8('hello mytho!!'),
      bin: 1024,
    },
  ];

  for (const c of cases) {
    const nonce = aeadNonce(c.mk); // CANON-3: deterministic, single-use, off-wire
    const aad = buildAad(c.aadInputs);
    const padded = pad7816(c.plaintext, c.bin);
    const ct = xchacha20poly1305(c.mk, nonce, aad).encrypt(padded);
    const recovered = xchacha20poly1305(c.mk, nonce, aad).decrypt(ct);
    const roundtripOk = Buffer.from(recovered).equals(Buffer.from(padded));

    out.cases.push({
      label: c.label,
      inputs: {
        mk_hex: hex(c.mk),
        nonce_hex: hex(nonce),
        nonce_derivation: 'HKDF (Extract+Expand, RFC 5869, empty salt) over IKM=MK, info="mytho/nonce/v1", L=24',
        aad_hex: hex(aad),
        aad_length: 38,
        plaintext_hex: hex(c.plaintext),
        plaintext_length: c.plaintext.length,
        padding_bin: c.bin,
        padded_plaintext_length: padded.length,
      },
      outputs: {
        ciphertext_hex_first_32: hex(ct.slice(0, 32)),
        ciphertext_hex_last_32: hex(ct.slice(-32)),
        ciphertext_length: ct.length,
        poly1305_tag_length: 16,
        decrypt_roundtrip_ok: roundtripOk,
      },
      notes: 'ct = XChaCha20-Poly1305(key=MK, nonce, aad).encrypt(pad7816(plaintext, bin)); ciphertext_length = padded_plaintext_length + 16 (Poly1305 tag). Decrypt recovers the padded plaintext exactly.',
    });
  }

  writeFileSync(resolve(VECTORS_DIR, 'aead-roundtrip.json'), JSON.stringify(out, null, 2));
}

// ---- 9) Symmetric ratchet multi-step (CANON-2) ----
function genRatchetMultistepVector() {
  const out = commonMeta('ratchet-multistep', 'docs/ratchet-state-machine.md §4');

  // CK_0 anchored on the pinned seed; advance three symmetric steps.
  const CK_0 = sha256(new Uint8Array([...utf8('ratchet-ck0'), ...SEED]));
  const CK_1 = chainAdvance(CK_0);
  const CK_2 = chainAdvance(CK_1);
  const MK_0 = messageKey(CK_0);
  const MK_1 = messageKey(CK_1);
  const MK_2 = messageKey(CK_2);

  out.cases.push({
    label: 'Symmetric chain: CK_0 -> CK_1 -> CK_2 with MK_0/MK_1/MK_2',
    inputs: {
      ck_0_hex: hex(CK_0),
      salt: '',
      salt_note: EMPTY_SALT_NOTE,
      info_ck_ascii: INFO_CK,
      info_mk_ascii: INFO_MK,
      length: 32,
      steps: 3,
    },
    outputs: {
      ck_0_hex: hex(CK_0),
      ck_1_hex: hex(CK_1),
      ck_2_hex: hex(CK_2),
      mk_0_hex: hex(MK_0),
      mk_1_hex: hex(MK_1),
      mk_2_hex: hex(MK_2),
    },
    notes: 'Per CANON-2: CK_{n+1}=HKDF(salt="", IKM=CK_n, info="mytho/ck/v1", L=32); MK_n=HKDF(salt="", IKM=CK_n, info="mytho/mk/v1", L=32). Three sequential steps from CK_0.',
  });

  writeFileSync(resolve(VECTORS_DIR, 'ratchet-multistep.json'), JSON.stringify(out, null, 2));
}

// ---- 10) Skipped message keys (out-of-order delivery, bounded by MAX_SKIP) ----
function genSkippedKeysVector() {
  const out = commonMeta('skipped-keys', 'docs/ratchet-state-machine.md §5');

  // Receiving chain anchored on the pinned seed; precompute MK_0..MK_4 in chain order.
  const chain = [];
  let ck = sha256(new Uint8Array([...utf8('skipped-ck0'), ...SEED]));
  for (let n = 0; n < 5; n++) {
    chain.push({ n, mk: messageKey(ck), ck_hex: hex(ck) });
    ck = chainAdvance(ck);
  }

  // Scenario: the receiver has consumed message N=0. The next frame to arrive is
  // N=3 (messages 1 and 2 are delayed). The receiver MUST advance the chain to
  // N=3, deriving and CACHING the skipped MK_1 and MK_2, then derive MK_3 to
  // decrypt the frame. When the delayed frames 1 and 2 arrive, they are decrypted
  // from the cache (no re-derivation). The cache size (2) must never exceed MAX_SKIP.
  const lastConsumed = 0; // N=0 already processed in this scenario
  const received = 3; // first out-of-order frame
  const skipDistance = received - lastConsumed - 1; // = 2 keys to cache (N=1, N=2)

  // Order in which message keys are produced when frame N=3 is received first.
  const derivedInOrder = [
    { n: 1, mk_hex: hex(chain[1].mk), role: 'skipped -> cached' },
    { n: 2, mk_hex: hex(chain[2].mk), role: 'skipped -> cached' },
    { n: 3, mk_hex: hex(chain[3].mk), role: 'used (decrypts the received frame)' },
  ];
  const cachedKeys = derivedInOrder.filter((k) => k.role === 'skipped -> cached');

  out.cases.push({
    label: 'Out-of-order: receive N=3 before N=1,N=2 — derive+cache MK_1,MK_2; use MK_3',
    inputs: {
      ck_0_hex: chain[0].ck_hex,
      salt: '',
      salt_note: EMPTY_SALT_NOTE,
      info_ck_ascii: INFO_CK,
      info_mk_ascii: INFO_MK,
      last_consumed_message_number: lastConsumed,
      received_message_number: received,
      max_skip: MAX_SKIP,
    },
    outputs: {
      chain_message_keys: chain.map((c) => ({ n: c.n, mk_hex: hex(c.mk) })),
      derived_in_order: derivedInOrder,
      skipped_keys_cached: cachedKeys,
      skipped_count: skipDistance,
      cache_size_after: cachedKeys.length,
      cache_within_bound: cachedKeys.length <= MAX_SKIP,
      max_skip: MAX_SKIP,
    },
    notes: 'CK_0=sha256("skipped-ck0"||seed); MK_n=HKDF(salt="", IKM=CK_n, info="mytho/mk/v1", L=32); CK_{n+1}=HKDF(salt="", IKM=CK_n, info="mytho/ck/v1", L=32). Receiving frame N=3 with N=0 last consumed derives MK_1,MK_2 (cached) then MK_3 (used). Skip distance 2 ≤ MAX_SKIP=2000; a skip distance > MAX_SKIP MUST be rejected.',
  });

  writeFileSync(resolve(VECTORS_DIR, 'skipped-keys.json'), JSON.stringify(out, null, 2));
}

// ---- 11) ML-DSA-65 sign / verify ----
function genMlDsaSignVerifyVector() {
  const out = commonMeta('mldsa-sign-verify', 'docs/wire-format.md §5.4');

  const seed = sha256(new Uint8Array([...utf8('mldsa-sign-seed'), ...SEED]));
  const kp = ml_dsa65.keygen(seed);
  const pk = kp.publicKey;
  const sk = kp.secretKey;
  const msg = utf8('mytho.chat KAT — ML-DSA-65 sign/verify');

  // @noble/post-quantum 0.2.1 ML-DSA defaults to the DETERMINISTIC (non-hedged)
  // signing mode when no `random` is supplied (FIPS 204 deterministic variant:
  // rnd = 32 zero bytes). We pass an explicit 32-zero `random` to make the
  // determinism contract self-documenting and stable across library defaults.
  const detRandom = new Uint8Array(ml_dsa65.signRandBytes); // 32 zero bytes
  const sig = ml_dsa65.sign(sk, msg, undefined, detRandom);
  const verified = ml_dsa65.verify(pk, msg, sig);
  // Negative control: a tampered message must NOT verify.
  const tampered = ml_dsa65.verify(pk, utf8('tampered message'), sig);

  out.cases.push({
    label: 'ML-DSA-65 deterministic sign + verify (32 zero-byte rnd)',
    inputs: {
      keygen_seed_hex: hex(seed),
      ik_pub_dilithium_length: pk.length,
      secret_key_length: sk.length,
      message_utf8: 'mytho.chat KAT — ML-DSA-65 sign/verify',
      message_hex: hex(msg),
      sign_random_hex: hex(detRandom),
      sign_random_note: 'FIPS 204 deterministic variant: 32 zero bytes (rnd). @noble/post-quantum 0.2.1 yields a byte-identical signature.',
    },
    outputs: {
      signature_hex_first_32: hex(sig.slice(0, 32)),
      signature_hex_last_32: hex(sig.slice(-32)),
      signature_length: sig.length,
      verify: verified,
      verify_tampered_message: tampered,
    },
    notes: 'ml_dsa65.keygen(seed); sig = ml_dsa65.sign(sk, msg, ctx=∅, rnd=0^32); verify(pk, msg, sig)=true. Deterministic in this library version, so signature is pinned; a tampered message verifies false.',
  });

  writeFileSync(resolve(VECTORS_DIR, 'mldsa-sign-verify.json'), JSON.stringify(out, null, 2));
}

// ---- 12) ML-KEM-768 encapsulate / decapsulate correctness ----
function genMlKemDecapsulateVector() {
  const out = commonMeta('mlkem-decapsulate', 'docs/ratchet-state-machine.md §3');

  // ML-KEM-768 keygen seed = 64 bytes (d || z) per FIPS 203 §7.1.
  const keygenSeed = new Uint8Array(64);
  keygenSeed.set(sha256(new Uint8Array([...utf8('mlkem-d'), ...SEED])), 0);
  keygenSeed.set(sha256(new Uint8Array([...utf8('mlkem-z'), ...SEED])), 32);
  const kp = ml_kem768.keygen(keygenSeed);

  // Encapsulation message m = 32 bytes per FIPS 203.
  const encapSeed = sha256(new Uint8Array([...utf8('mlkem-encaps-m'), ...SEED]));
  const { cipherText, sharedSecret } = ml_kem768.encapsulate(kp.publicKey, encapSeed);
  const ssDecaps = ml_kem768.decapsulate(cipherText, kp.secretKey);
  const match = Buffer.from(sharedSecret).equals(Buffer.from(ssDecaps));

  out.cases.push({
    label: 'ML-KEM-768 encapsulate then decapsulate — shared secrets equal',
    inputs: {
      keygen_seed_hex: hex(keygenSeed),
      public_key_length: kp.publicKey.length,
      secret_key_length: kp.secretKey.length,
      encapsulate_message_hex: hex(encapSeed),
      cipher_text_length: cipherText.length,
    },
    outputs: {
      ss_encaps_hex: hex(sharedSecret),
      ss_encaps_length: sharedSecret.length,
      ss_decaps_hex: hex(ssDecaps),
      ss_decaps_length: ssDecaps.length,
      shared_secret_match: match,
    },
    notes: 'ml_kem768.keygen(seed64); {cipherText, sharedSecret}=encapsulate(pk, m32); ss2=decapsulate(cipherText, sk). Correctness: ss_encaps_hex == ss_decaps_hex (32-byte ML-KEM-768 shared secret, ct=1088 bytes).',
  });

  writeFileSync(resolve(VECTORS_DIR, 'mlkem-decapsulate.json'), JSON.stringify(out, null, 2));
}

// ---- main ----
console.log('Generating KAT vectors for mytho.chat protocol v1.0…');
genPeerIdVector();           console.log('  ✓ vectors/peerid-derivation.json');
genAadVector();              console.log('  ✓ vectors/aad-encoding.json');
genPaddingVector();          console.log('  ✓ vectors/padding-7816.json');
genNonceVector();            console.log('  ✓ vectors/aead-nonce-derivation.json');
genDeliveryTokenVector();    console.log('  ✓ vectors/delivery-token.json');
genHkdfChainStepVector();    console.log('  ✓ vectors/hkdf-chain-step.json');
genHandshakeVector();        console.log('  ✓ vectors/handshake-x3dh-pq.json');
genAeadRoundtripVector();    console.log('  ✓ vectors/aead-roundtrip.json');
genRatchetMultistepVector(); console.log('  ✓ vectors/ratchet-multistep.json');
genSkippedKeysVector();      console.log('  ✓ vectors/skipped-keys.json');
genMlDsaSignVerifyVector();  console.log('  ✓ vectors/mldsa-sign-verify.json');
genMlKemDecapsulateVector(); console.log('  ✓ vectors/mlkem-decapsulate.json');
console.log('Done. 12 vectors written.');
