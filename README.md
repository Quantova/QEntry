# QEntry

QEntry is a live production post quantum physical access record tool for secure facilities on the Quantova network. It proves the grant, entry, exit, suspension and revocation of access to a zone, and it lets any third party confirm that history without trusting the party that created it.

QEntry proves records without disclosing them. Identities of the people granted access stay private on the systems of the party that holds them. Only a salted cryptographic commitment is written to the chain, and no personal detail is ever published. A person is named only by a chain address.

## What it records

Each record is a signed envelope of one of five types.

1. grant, a grantor states the zone, access level, holder and expiry of an access grant.
2. enter, a reader records an entry at a named point.
3. exit, a reader records an exit at a named point.
4. suspend, the grantor suspends the grant and states why.
5. revoke, the grantor revokes the grant and states why.

Every record is signed with ML-DSA-65 under FIPS 204 by the party whose role it names, and each later record links to the one before it so the whole life of a grant forms a chain.

## Proving the time

A record on its own carries only the claim of its signer. Anchoring a record on the Quantova network through Qstamp adds a post quantum evidence anchor that fixes the latest moment the record existed, provable against the record and the signer by anyone, without claiming a regulated timestamp status that Quantova Inc does not hold.

## Install

```
npm install @quantovainc/qentry
```

## Use

```js
const qentry = require('@quantovainc/qentry');

const grantor = qentry.generateKey();
const person = qentry.generateKey();
const access = qentry.grant({
  key: grantor,
  zone: 'Data Hall 2',
  accessLevel: 'staff',
  subject: qentry.keyId(person),
  validUntil: '2027-01-01T00:00:00.000Z',
  grantorLabel: 'Site Security',
});

const anchored = await qentry.anchor(access, { seed, index: 0, network: 'testnet' });
const result = await qentry.verify(anchored[0], { type: 'grant', network: 'testnet' });
```

## What a record does not establish

1. It does not show that the stated facts are true. It shows only that the signer stated them and that the statement existed unchanged at a point in time.
2. It does not identify a natural person. The holder and the grantor are chain addresses, and linking an address to a person is a separate attestation held off the chain.
3. The labels are text written by the signer, they are not a verified identity.

## License

Apache-2.0 OR MIT
