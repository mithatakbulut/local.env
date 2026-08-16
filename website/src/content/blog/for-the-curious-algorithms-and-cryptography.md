---
title: "For the curious: how algorithms and cryptography do different jobs"
description: "Algorithms make repeatable decisions; cryptography protects data in transit and at rest. Here is how those ideas meet in local.env without turning the server into a secret store."
pubDate: 2026-08-16
draft: false
---

“Algorithm” and “encryption” often get used as if they mean the same thing.
They do not. An algorithm is a precise, repeatable recipe for transforming an
input into an output. Cryptography is the set of algorithms designed to keep
particular properties true even when an attacker can watch, copy, or alter the
data.

That distinction is useful when reading how local.env works. Some algorithms
make a workflow predictable. Others make it safe to coordinate encrypted
values. Neither is magic, and neither changes the limit of the product: it is
for local-development environment values, not production, staging, CI, or
general-purpose credential storage.

## Algorithms: the boring part that makes systems dependable

An algorithm has inputs, steps, and an expected result. Sorting a list of
repository keys is an algorithm. Comparing a pull request’s schema with its
base branch is an algorithm too: collect the declared keys, compare the two
sets, and report the missing requirements precisely.

The important property is repeatability. Given the same repository contract
and pull request, two runs should reach the same readiness result. This is why
local.env keeps the repository contract explicit and checks schema changes
instead of guessing which values an application might need.

Algorithms can be public. In fact, public and reviewable rules are usually
better than hidden ones. Security does not come from obscuring the comparison
logic, the dotenv writer, or the structure of a request. It comes from using
cryptographic algorithms where secrecy and tamper detection are actually
needed.

## Encryption: turning readable data into ciphertext

Encryption takes readable data, a key, and usually a fresh random value called
a nonce. It produces ciphertext: data that can be stored or sent without
revealing the original value to someone who lacks the key.

Modern authenticated encryption does two jobs together:

- confidentiality: ciphertext should not reveal the original value;
- integrity: a modified ciphertext must fail to decrypt rather than quietly
  becoming a different value.

local.env uses XChaCha20-Poly1305 for this authenticated encryption. A client
generates a new random nonce for each encryption. The server receives the
resulting ciphertext and associated metadata, not the managed plaintext.

Encryption is not a permission system by itself. Anyone who gets the right key
can decrypt. That is why the next question is always: who can obtain the key?

## One repository key, wrapped for each approved device

Each repository has a randomly generated repository encryption key (REK).
The REK encrypts the repository’s managed values on an authorized developer
machine. Keeping one REK per repository makes it possible to encrypt a value
once while allowing more than one approved device to read it.

The REK itself is not sent to the server as plaintext. Instead, the client
wraps it separately for each approved device using that device’s age X25519
public identity. The server can keep those wrapped copies and deliver the one
intended for a device, but a wrapped copy is not the original REK.

This is an envelope pattern: the value goes in one sealed envelope, and the
key for that envelope goes in a smaller envelope addressed to each device.
Adding a device requires an already authorized device to create a new wrapped
copy. Revoking a device prevents future access; rotating the REK is the step
that protects newly encrypted data from a device that may have retained an old
key.

## Context matters: authenticated data binds a ciphertext to its job

It would be risky if a valid encrypted value for one key could be copied into a
different repository, file, scope, or version and still decrypt. To prevent
that class of mix-up, local.env authenticates fixed context alongside each
encrypted value. Cryptographers call this associated authenticated data (AAD).

For local.env, that context is deterministic and includes the instance,
repository, file, key, scope, version, and key-rotation epoch. The context is
not secret; its purpose is to make the ciphertext valid only in the place it
was created for. If someone changes the ciphertext or its bound context,
authenticated decryption fails.

This does not make metadata disappear. A coordinating server still needs some
metadata to know which encrypted update belongs to which repository and pull
request. The security boundary is narrower and more useful: it coordinates
ciphertext and device-specific wrapped keys without persisting managed secret
plaintext or plaintext REKs.

## What this does and does not protect

These choices protect against several mundane but important failures: a server
database containing readable values, an altered encrypted payload being
accepted silently, or a ciphertext being replayed in the wrong context.

They do not protect a developer machine that is already compromised, a value
that was previously synced into a local file, or a malicious modified CLI.
That is why device approval, key rotation, signed releases, restrictive local
file permissions, and ordinary endpoint security still matter.

If you want the protocol details, start with the [security model](/docs/security/security-model/)
and the [device approval and revocation guide](/docs/use-localenv/device-approval-and-revocation/).
The short version is pleasingly unglamorous: deterministic workflow rules,
well-understood cryptography, keys kept on developer devices, and a server
that has deliberately less to know.
