// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

export type AccessLevel = 'visitor' | 'staff' | 'contractor' | 'restricted';
export type RecordType = 'grant' | 'enter' | 'exit' | 'suspend' | 'revoke';

export interface KeyDescription {
  format: 'qentry-key/1';
  algorithm: 'ML-DSA-65';
  id: string;
  publicKey: string;
}

export type Party = string | Uint8Array | KeyDescription;

export interface Signer {
  id: string;
  publicKey: string;
}

export interface Envelope<T = Record<string, unknown>> {
  format: 'qentry/1';
  type: RecordType;
  algorithm: 'ML-DSA-65';
  signer: Signer;
  statement: T;
  signature: string;
  anchor?: unknown;
}

export interface GrantOptions {
  key: Uint8Array;
  zone: string;
  accessLevel: AccessLevel;
  subject: Party;
  validUntil: string;
  grantorLabel?: string;
  grantedAt?: string;
  note?: string;
}

export interface EnterOptions {
  key: Uint8Array;
  record: Envelope;
  point: string;
  readerLabel?: string;
  enteredAt?: string;
  note?: string;
}

export interface ExitOptions {
  key: Uint8Array;
  record: Envelope;
  point: string;
  readerLabel?: string;
  exitedAt?: string;
  note?: string;
}

export interface SuspendOptions {
  key: Uint8Array;
  record: Envelope;
  reason: string;
  grantorLabel?: string;
  suspendedAt?: string;
  note?: string;
}

export interface RevokeOptions {
  key: Uint8Array;
  record: Envelope;
  reason: string;
  grantorLabel?: string;
  revokedAt?: string;
  note?: string;
}

export interface AnchorOptions {
  seed?: Uint8Array;
  index?: number;
  network?: string;
  rpc?: string;
  clients?: unknown[];
  trustSingleEndpoint?: boolean;
  trustCustomEndpoints?: boolean;
  allowLoopback?: boolean;
  maxFee?: string | number | bigint;
  meter?: string | number | bigint;
  timeoutMs?: number;
  onPending?: (pending: unknown) => void;
  signal?: AbortSignal;
}

export interface VerifyOptions {
  type?: RecordType;
  prior?: Envelope;
  entryId?: string;
  signerKeyId?: string;
  signerPublicKey?: string | Uint8Array;
  network: string;
  strict?: boolean;
  requireAnchor?: boolean;
  maxAnchorDelay?: number;
  at?: string;
  deadlineMs?: number;
  rpc?: string;
  clients?: unknown[];
  trustSingleEndpoint?: boolean;
  trustCustomEndpoints?: boolean;
  allowLoopback?: boolean;
}

export interface Check {
  name: string;
  ok: boolean;
  detail: string;
  transport: boolean;
  indeterminate: boolean;
  unproven: boolean;
}

export interface VerifyResult {
  valid: boolean;
  status: 'valid' | 'unproven' | 'indeterminate' | 'invalid';
  type: RecordType | null;
  entryId?: string;
  signerId?: string;
  statement?: Record<string, unknown>;
  anchoredAt?: string | null;
  endpoints: string[];
  officialEndpoints: boolean | null;
  checks: Check[];
}

export function generateKey(): Uint8Array;
export function publicKey(key: Uint8Array): Uint8Array;
export function keyId(key: Uint8Array): string;
export function describeKey(key: Uint8Array): KeyDescription;
export function subjectRef(secret: Uint8Array, reference: string): string;
export function grant(options: GrantOptions): Envelope;
export function enter(options: EnterOptions): Envelope;
export function exit(options: ExitOptions): Envelope;
export function suspend(options: SuspendOptions): Envelope;
export function revoke(options: RevokeOptions): Envelope;
export function anchor(envelopes: Envelope | Envelope[], options: AnchorOptions): Promise<Envelope[]>;
export function complete(envelopes: Envelope | Envelope[], pending: unknown, options?: AnchorOptions): Promise<Envelope[]>;
export function verify(envelope: Envelope, options: VerifyOptions): Promise<VerifyResult>;
export function anchorDigest(envelope: Envelope): string;
export function recordRef(envelope: Envelope): string;

export const FORMAT: 'qentry/1';
export const ALGORITHM: 'ML-DSA-65';
export const KIND: 1507;
export const TYPES: readonly RecordType[];
export const LEVELS: readonly AccessLevel[];
export const PUBLIC_KEY_BYTES: 1952;
export const SIGNATURE_BYTES: 3309;
