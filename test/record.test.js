// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const Q = require('..');

function freshKey() {
  return Q.generateKey();
}

function grantAccess(key, subject) {
  return Q.grant({ key, zone: 'Data Hall 2', accessLevel: 'staff', subject: Q.keyId(subject), validUntil: '2027-01-01T00:00:00.000Z', grantorLabel: 'Site Security' });
}

test('a grant is a well formed signed record of the grantor', () => {
  const grantor = freshKey();
  const person = freshKey();
  const g = grantAccess(grantor, person);
  assert.strictEqual(g.format, 'qentry/1');
  assert.strictEqual(g.type, 'grant');
  assert.strictEqual(g.algorithm, 'ML-DSA-65');
  assert.strictEqual(g.signer.id, Q.keyId(grantor));
  assert.strictEqual(g.statement.grantorKeyId, Q.keyId(grantor));
  assert.strictEqual(g.statement.subjectKeyId, Q.keyId(person));
  assert.match(g.statement.entryId, /^[0-9a-f]{32}$/);
  assert.strictEqual(Buffer.from(g.signature, 'base64').length, Q.SIGNATURE_BYTES);
});

test('the enter, exit and suspend records chain to the same grant', () => {
  const grantor = freshKey();
  const person = freshKey();
  const reader = freshKey();
  const g = grantAccess(grantor, person);
  const en = Q.enter({ key: reader, record: g, point: 'Door 7' });
  const ex = Q.exit({ key: reader, record: en, point: 'Door 7' });
  const sp = Q.suspend({ key: grantor, record: ex, reason: 'under review' });
  assert.strictEqual(en.statement.entryId, g.statement.entryId);
  assert.strictEqual(en.statement.priorRef, Q.recordRef(g));
  assert.strictEqual(ex.statement.priorRef, Q.recordRef(en));
  assert.strictEqual(sp.statement.priorRef, Q.recordRef(ex));
});

test('invalid inputs are refused before anything is signed', () => {
  const key = freshKey();
  const person = freshKey();
  const base = { key, zone: 'Z', accessLevel: 'staff', subject: Q.keyId(person), validUntil: '2027-01-01T00:00:00.000Z' };
  assert.throws(() => Q.grant(Object.assign({}, base, { accessLevel: 'god' })), /accessLevel must be one of/);
  assert.throws(() => Q.grant(Object.assign({}, base, { zone: '' })), /zone cannot be empty/);
  assert.throws(() => Q.grant(Object.assign({}, base, { subject: 'nothex' })), /subject is a/);
  assert.throws(() => Q.grant(Object.assign({}, base, { unknownField: 1 })), /is not an option of grant/);
});

test('a signing key must be a well formed 32 byte seed', () => {
  const person = freshKey();
  assert.throws(() => grantAccess(new Uint8Array(16), person), /32 byte Uint8Array seed/);
  assert.throws(() => grantAccess(new Uint8Array(32), person), /too few different byte values/);
});

test('a well formed record verifies and a type mismatch is invalid', async () => {
  const grantor = freshKey();
  const person = freshKey();
  const g = grantAccess(grantor, person);
  const ok = await Q.verify(g, { type: 'grant', network: 'testnet', requireAnchor: false, strict: false });
  assert.strictEqual(ok.status, 'valid');
  assert.strictEqual(ok.type, 'grant');
  assert.strictEqual(ok.entryId, g.statement.entryId);
  const wrongType = await Q.verify(g, { type: 'enter', network: 'testnet', requireAnchor: false, strict: false });
  assert.strictEqual(wrongType.status, 'invalid');
  const wrongSigner = await Q.verify(g, { type: 'grant', network: 'testnet', requireAnchor: false, strict: false, signerKeyId: Q.keyId(freshKey()) });
  assert.strictEqual(wrongSigner.status, 'invalid');
});

test('a tampered statement no longer verifies', async () => {
  const grantor = freshKey();
  const person = freshKey();
  const g = grantAccess(grantor, person);
  const forged = JSON.parse(JSON.stringify(g));
  forged.statement.accessLevel = 'restricted';
  const r = await Q.verify(forged, { type: 'grant', network: 'testnet', requireAnchor: false, strict: false });
  assert.strictEqual(r.status, 'invalid');
  assert.ok(r.checks.some((c) => c.name === 'signature' && !c.ok));
});

test('the prior link binds an entry to the grant it refers to', async () => {
  const grantor = freshKey();
  const person = freshKey();
  const reader = freshKey();
  const g = grantAccess(grantor, person);
  const en = Q.enter({ key: reader, record: g, point: 'Door 7' });
  const good = await Q.verify(en, { type: 'enter', network: 'testnet', requireAnchor: false, strict: false, prior: g });
  assert.ok(good.checks.some((c) => c.name === 'prior' && c.ok));
  const otherG = grantAccess(grantor, person);
  const bad = await Q.verify(en, { type: 'enter', network: 'testnet', requireAnchor: false, strict: false, prior: otherG });
  assert.strictEqual(bad.status, 'invalid');
  assert.ok(bad.checks.some((c) => c.name === 'prior' && !c.ok));
});

test('subjectRef is deterministic for the same secret and reference and differs otherwise', () => {
  const secret = new Uint8Array(32);
  globalThis.crypto.getRandomValues(secret);
  const a = Q.subjectRef(secret, 'STAFF 0001');
  const b = Q.subjectRef(secret, 'STAFF 0001');
  const c = Q.subjectRef(secret, 'STAFF 0002');
  assert.strictEqual(a, b);
  assert.notStrictEqual(a, c);
  assert.match(a, /^[0-9a-f]{64}$/);
});

test('the kind and constants are the ones pinned for the access line', () => {
  assert.strictEqual(Q.KIND, 1507);
  assert.strictEqual(Q.FORMAT, 'qentry/1');
  assert.deepStrictEqual([...Q.TYPES], ['grant', 'enter', 'exit', 'suspend', 'revoke']);
  assert.deepStrictEqual([...Q.LEVELS], ['visitor', 'staff', 'contractor', 'restricted']);
});
