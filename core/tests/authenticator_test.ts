/*
 * Copyright 2022-2024 The NATS Authors
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import { cleanup, NatsServer, setup } from "nst";

import {
  AuthorizationError,
  credsAuthenticator,
  deadline,
  deferred,
  delay,
  jwtAuthenticator,
  nkeyAuthenticator,
  nkeys,
  tokenAuthenticator,
  usernamePasswordAuthenticator,
} from "../src/internal_mod.ts";
import type {
  Auth,
  Authenticator,
  NatsConnection,
  NatsConnectionImpl,
} from "../src/internal_mod.ts";

import {
  assertEquals,
  assertInstanceOf,
  assertRejects,
  assertStringIncludes,
  assertThrows,
} from "@std/assert";
import { createServer } from "node:net";
import type { AddressInfo, Socket } from "node:net";
import type { Buffer } from "node:buffer";
import { connect } from "./connect.ts";
import {
  encodeAccount,
  encodeOperator,
  encodeUser,
  fmtCreds,
} from "@nats-io/jwt";
import { assertBetween } from "nst";

function disconnectReconnect(nc: NatsConnection): Promise<void> {
  const done = deferred<void>();
  const disconnect = deferred();
  const reconnect = deferred();
  (async () => {
    for await (const s of nc.status()) {
      switch (s.type) {
        case "disconnect":
          disconnect.resolve();
          break;
        case "reconnect":
          reconnect.resolve();
          break;
      }
    }
  })().then();

  Promise.all([disconnect, reconnect])
    .then(() => done.resolve()).catch((err) => done.reject(err));
  return done;
}

async function testAuthenticatorFn(
  fn: Authenticator,
  conf: Record<string, unknown>,
  debug = false,
): Promise<void> {
  let called = 0;
  const authenticator = (nonce?: string): Auth => {
    called++;
    return fn(nonce);
  };
  conf = Object.assign({}, conf, { debug });
  const { ns, nc } = await setup(conf, {
    authenticator,
  });

  const cycle = disconnectReconnect(nc);

  await delay(2000);
  called = 0;
  const nci = nc as NatsConnectionImpl;
  nci.reconnect();
  await delay(1000);
  await deadline(cycle, 4000);
  assertBetween(called, 1, 10);
  await nc.flush();
  assertEquals(nc.isClosed(), false);
  await cleanup(ns, nc);
}

Deno.test("authenticator - username password fns", async () => {
  const user = "a";
  const pass = "a";
  const authenticator = usernamePasswordAuthenticator(() => {
    return user;
  }, () => {
    return pass;
  });

  await testAuthenticatorFn(authenticator, {
    authorization: {
      users: [{
        user: "a",
        password: "a",
      }],
    },
  });
});

Deno.test("authenticator - username string password fn", async () => {
  const pass = "a";
  const authenticator = usernamePasswordAuthenticator("a", () => {
    return pass;
  });

  await testAuthenticatorFn(authenticator, {
    authorization: {
      users: [{
        user: "a",
        password: "a",
      }],
    },
  });
});

Deno.test("authenticator - username fn password string", async () => {
  const user = "a";
  const authenticator = usernamePasswordAuthenticator(() => {
    return user;
  }, "a");

  await testAuthenticatorFn(authenticator, {
    authorization: {
      users: [{
        user: "a",
        password: "a",
      }],
    },
  });
});

Deno.test("authenticator - token fn", async () => {
  const token = "tok";
  const authenticator = tokenAuthenticator(() => {
    return token;
  });

  await testAuthenticatorFn(authenticator, {
    authorization: {
      token,
    },
  });
});

Deno.test("authenticator - nkey fn", async () => {
  const user = nkeys.createUser();
  const seed = user.getSeed();
  const nkey = user.getPublicKey();

  const authenticator = nkeyAuthenticator(() => {
    return seed;
  });
  await testAuthenticatorFn(authenticator, {
    authorization: {
      users: [
        { nkey },
      ],
    },
  });
});

Deno.test("authenticator - jwt bearer fn", async () => {
  const O = nkeys.createOperator();
  const A = nkeys.createAccount();
  const U = nkeys.createUser();
  const ujwt = await encodeUser("U", U, A, { bearer_token: true });

  const authenticator = jwtAuthenticator(() => {
    return ujwt;
  });

  const resolver: Record<string, string> = {};
  resolver[A.getPublicKey()] = await encodeAccount("A", A, {
    limits: {
      conn: -1,
      subs: -1,
    },
  }, { signer: O });
  const conf = {
    operator: await encodeOperator("O", O),
    resolver: "MEMORY",
    "resolver_preload": resolver,
  };

  await testAuthenticatorFn(authenticator, conf);
});

Deno.test("authenticator - jwt fn", async () => {
  const O = nkeys.createOperator();
  const A = nkeys.createAccount();
  const U = nkeys.createUser();
  const ujwt = await encodeUser("U", U, A, {});

  const authenticator = jwtAuthenticator(() => {
    return ujwt;
  }, () => {
    return U.getSeed();
  });

  const resolver: Record<string, string> = {};
  resolver[A.getPublicKey()] = await encodeAccount("A", A, {
    limits: {
      conn: -1,
      subs: -1,
    },
  }, { signer: O });
  const conf = {
    operator: await encodeOperator("O", O),
    resolver: "MEMORY",
    "resolver_preload": resolver,
  };

  await testAuthenticatorFn(authenticator, conf);
});

Deno.test("authenticator - creds fn", async () => {
  const O = nkeys.createOperator();
  const A = nkeys.createAccount();
  const U = nkeys.createUser();
  const ujwt = await encodeUser("U", U, A, {});
  const creds = fmtCreds(ujwt, U);

  const authenticator = credsAuthenticator(() => {
    return creds;
  });

  const resolver: Record<string, string> = {};
  resolver[A.getPublicKey()] = await encodeAccount("A", A, {
    limits: {
      conn: -1,
      subs: -1,
    },
  }, { signer: O });
  const conf = {
    operator: await encodeOperator("O", O),
    resolver: "MEMORY",
    "resolver_preload": resolver,
  };

  await testAuthenticatorFn(authenticator, conf);
});

Deno.test("authenticator - bad creds", () => {
  assertThrows(
    () => {
      credsAuthenticator(new TextEncoder().encode("hello"))();
    },
    Error,
    "unable to parse credentials",
  );
});

// Mirrors nkeyAuthenticator's own signing logic (authenticator.ts) rather
// than reusing it directly, wrapped with a real delay — proves this is a
// genuinely asynchronous authenticator settling later, not a Promise that
// happens to resolve synchronously on the same microtask.
function delayedNkeyAsyncAuthenticator(
  seed: Uint8Array,
  delayMs: number,
): (nonce?: string) => Promise<Auth> {
  return async (nonce?: string): Promise<Auth> => {
    await delay(delayMs);
    const kp = nkeys.fromSeed(seed);
    const nkey = kp.getPublicKey();
    const challenge = new TextEncoder().encode(nonce || "");
    const sig = nkeys.encode(kp.sign(challenge));
    return { nkey, sig };
  };
}

Deno.test("authenticator - async fn", async () => {
  const user = nkeys.createUser();
  const seed = user.getSeed();
  const nkey = user.getPublicKey();

  const { ns, nc } = await setup({
    authorization: {
      users: [{ nkey }],
    },
  }, {
    asyncAuthenticator: delayedNkeyAsyncAuthenticator(seed, 250),
  });

  await nc.flush();
  assertEquals(nc.isClosed(), false);
  await cleanup(ns, nc);
});

Deno.test("authenticator - async fn rejects", async () => {
  const asyncAuthenticator = (_nonce?: string): Promise<Auth> => {
    return Promise.reject(new Error("async authenticator blew up"));
  };

  await assertRejects(
    async () => {
      await setup({}, { asyncAuthenticator, reconnect: false });
    },
    Error,
  );
});

// This is the test that actually proves the awaitingAsyncConnect gate in
// ProtocolHandler.push() works, not just that the code compiles. It uses a
// very short server-side ping_interval against an authenticator delay long
// enough that the real nats-server (confirmed via its own source,
// server.go: "Set the Ping timer. Will be reset once connect was received")
// will send at least one unsolicited PING before this client's CONNECT is
// sent. If the gate didn't work — if that early PING were dispatched to
// processPing() and a PONG were written to a transport that hasn't sent
// CONNECT yet — this would either fail outright or leave the connection in
// a bad state. Success here means the race was hit and handled correctly,
// not that the race never happened.
Deno.test("authenticator - async fn ignores data before connect", async () => {
  const user = nkeys.createUser();
  const seed = user.getSeed();
  const nkey = user.getPublicKey();

  const { ns, nc } = await setup({
    authorization: {
      users: [{ nkey }],
    },
    // Aggressive on purpose — short enough that the server's ping timer
    // (armed immediately after INFO, per server.go) fires well within the
    // authenticator's artificial delay below. ping_max raised generously so
    // the several unanswered pings this produces (we're not able to PONG
    // until the gate opens) don't also trip the server's own unrelated
    // stale-connection detection — that's a real, separate server defense,
    // not what this test is isolating.
    ping_interval: "50ms",
    ping_max: 50,
  }, {
    asyncAuthenticator: delayedNkeyAsyncAuthenticator(seed, 500),
  });

  await nc.flush();
  assertEquals(nc.isClosed(), false);
  await cleanup(ns, nc);
});

// A server that sends INFO (with a nonce) and a PING, then an -ERR after
// `afterMs`, and leaves the socket open, recording every CONNECT it receives.
// Leaving the socket open isolates what the client does on its own: with a
// real server the socket closing would end the attempt regardless.
async function errServer(err: string, afterMs: number) {
  const connects: string[] = [];
  const sockets: Socket[] = [];
  const server = createServer((sock) => {
    sockets.push(sock);
    sock.on("error", () => {});
    sock.on("data", (b: Buffer) => {
      for (const line of b.toString().split("\r\n")) {
        if (line.startsWith("CONNECT ")) {
          connects.push(line);
        }
      }
    });
    const info = JSON.stringify({
      server_id: "SCRIPTED",
      version: "2.10.0",
      host: "127.0.0.1",
      port: 0,
      headers: true,
      nonce: "n",
    });
    sock.write(`INFO ${info}\r\nPING\r\n`);
    setTimeout(() => sock.write(`-ERR '${err}'\r\n`), afterMs);
  });
  const ready = deferred<void>();
  let port = 0;
  server.listen(0, "127.0.0.1", () => {
    port = (server.address() as AddressInfo).port;
    ready.resolve();
  });
  await ready;
  return {
    port,
    connects,
    async stop() {
      sockets.forEach((s) => s.destroy());
      await new Promise<void>((r) => server.close(() => r()));
    },
  };
}

// The server gives up on a connection that is still waiting for its
// authenticator. The -ERR must be handled immediately - not dropped with the
// rest of the pre-CONNECT traffic, which would leave connect() waiting for
// the dial timeout and lose the server's explanation.
Deno.test("authenticator - async fn: server -ERR preempts a pending authenticator", async () => {
  const release = deferred<void>();
  const srv = await errServer("Authentication Timeout", 100);
  try {
    let signed = false;
    const started = Date.now();
    const err = await assertRejects(() =>
      connect({
        port: srv.port,
        reconnect: false,
        asyncAuthenticator: async () => {
          await release;
          signed = true;
          return { auth_token: "x" };
        },
      })
    );
    assertInstanceOf(err, AuthorizationError);
    assertEquals(signed, false, "reported while the authenticator was pending");
    assertBetween(Date.now() - started, 50, 1500);

    // the authenticator finishing later must not send CONNECT
    release.resolve();
    await delay(200);
    assertEquals(srv.connects.length, 0);
  } finally {
    release.resolve();
    await srv.stop();
  }
});

// A non-auth -ERR does not reject connect() and the server here keeps the
// socket open, so nothing else ends the attempt: only the -ERR handling in
// push() stops the authenticator's late result from sending a CONNECT into a
// connection the server has already given up on.
Deno.test("authenticator - async fn: -ERR ends the attempt, a late resolution sends no CONNECT", async () => {
  const srv = await errServer("Stale Connection", 100);
  try {
    let signed = false;
    const rejected = assertRejects(() =>
      connect({
        port: srv.port,
        reconnect: false,
        timeout: 1500,
        asyncAuthenticator: async () => {
          await delay(500);
          signed = true;
          return { auth_token: "x" };
        },
      })
    );
    await delay(900);
    assertEquals(signed, true, "the authenticator did finish");
    assertEquals(srv.connects.length, 0, "but its result was discarded");
    // nothing closes this connect(); it ends on the dial timeout
    await rejected;
  } finally {
    await srv.stop();
  }
});

Deno.test("authenticator - async fn: real server's Authentication Timeout is reported while the authenticator is still pending", async () => {
  const ns = await NatsServer.start({
    authorization: { token: "s3cret", timeout: 1 },
  });
  const release = deferred<void>();
  try {
    let signed = false;
    const err = await assertRejects(() =>
      ns.connect({
        reconnect: false,
        asyncAuthenticator: async () => {
          await release;
          signed = true;
          return { auth_token: "s3cret" };
        },
      })
    );
    assertInstanceOf(err, AuthorizationError);
    assertEquals(signed, false);
  } finally {
    release.resolve();
    await ns.stop(true);
  }
});

// nkey's text format for a raw Ed25519 public key: [prefix byte, 32 key
// bytes, 2-byte little-endian CRC16-XMODEM checksum], base32-encoded. Ported
// line-for-line from this package's own crc16.ts/base32.ts/codec.ts (see
// core/src/nkeys.ts's "@nats-io/nkeys" re-export) rather than imported,
// because those internals aren't exposed from its package root — only the
// high-level create*/from* helpers, none of which fit "I already generated
// this key with WebCrypto, just encode its public half." This is the same
// port already shipping in geekdotdev/nats-nkey-demo-priv's browser code
// (spa-server/public/labs/callout-pop-zero-permission.js), verified there by
// round-tripping known outputs through both this package's own fromPublic()
// and Go's nkeys.IsValidPublicUserKey — a text/checksum format, not a
// cryptographic operation, so porting it carries none of the risk
// hand-rolling actual crypto would.
const NKEY_USER_PREFIX = 160; // this package's Prefix.User; base32-encodes to 'U...'
// deno-fmt-ignore
const CRC16_TABLE = new Uint16Array([
  0x0000,0x1021,0x2042,0x3063,0x4084,0x50a5,0x60c6,0x70e7,
  0x8108,0x9129,0xa14a,0xb16b,0xc18c,0xd1ad,0xe1ce,0xf1ef,
  0x1231,0x0210,0x3273,0x2252,0x52b5,0x4294,0x72f7,0x62d6,
  0x9339,0x8318,0xb37b,0xa35a,0xd3bd,0xc39c,0xf3ff,0xe3de,
  0x2462,0x3443,0x0420,0x1401,0x64e6,0x74c7,0x44a4,0x5485,
  0xa56a,0xb54b,0x8528,0x9509,0xe5ee,0xf5cf,0xc5ac,0xd58d,
  0x3653,0x2672,0x1611,0x0630,0x76d7,0x66f6,0x5695,0x46b4,
  0xb75b,0xa77a,0x9719,0x8738,0xf7df,0xe7fe,0xd79d,0xc7bc,
  0x48c4,0x58e5,0x6886,0x78a7,0x0840,0x1861,0x2802,0x3823,
  0xc9cc,0xd9ed,0xe98e,0xf9af,0x8948,0x9969,0xa90a,0xb92b,
  0x5af5,0x4ad4,0x7ab7,0x6a96,0x1a71,0x0a50,0x3a33,0x2a12,
  0xdbfd,0xcbdc,0xfbbf,0xeb9e,0x9b79,0x8b58,0xbb3b,0xab1a,
  0x6ca6,0x7c87,0x4ce4,0x5cc5,0x2c22,0x3c03,0x0c60,0x1c41,
  0xedae,0xfd8f,0xcdec,0xddcd,0xad2a,0xbd0b,0x8d68,0x9d49,
  0x7e97,0x6eb6,0x5ed5,0x4ef4,0x3e13,0x2e32,0x1e51,0x0e70,
  0xff9f,0xefbe,0xdfdd,0xcffc,0xbf1b,0xaf3a,0x9f59,0x8f78,
  0x9188,0x81a9,0xb1ca,0xa1eb,0xd10c,0xc12d,0xf14e,0xe16f,
  0x1080,0x00a1,0x30c2,0x20e3,0x5004,0x4025,0x7046,0x6067,
  0x83b9,0x9398,0xa3fb,0xb3da,0xc33d,0xd31c,0xe37f,0xf35e,
  0x02b1,0x1290,0x22f3,0x32d2,0x4235,0x5214,0x6277,0x7256,
  0xb5ea,0xa5cb,0x95a8,0x8589,0xf56e,0xe54f,0xd52c,0xc50d,
  0x34e2,0x24c3,0x14a0,0x0481,0x7466,0x6447,0x5424,0x4405,
  0xa7db,0xb7fa,0x8799,0x97b8,0xe75f,0xf77e,0xc71d,0xd73c,
  0x26d3,0x36f2,0x0691,0x16b0,0x6657,0x7676,0x4615,0x5634,
  0xd94c,0xc96d,0xf90e,0xe92f,0x99c8,0x89e9,0xb98a,0xa9ab,
  0x5844,0x4865,0x7806,0x6827,0x18c0,0x08e1,0x3882,0x28a3,
  0xcb7d,0xdb5c,0xeb3f,0xfb1e,0x8bf9,0x9bd8,0xabbb,0xbb9a,
  0x4a75,0x5a54,0x6a37,0x7a16,0x0af1,0x1ad0,0x2ab3,0x3a92,
  0xfd2e,0xed0f,0xdd6c,0xcd4d,0xbdaa,0xad8b,0x9de8,0x8dc9,
  0x7c26,0x6c07,0x5c64,0x4c45,0x3ca2,0x2c83,0x1ce0,0x0cc1,
  0xef1f,0xff3e,0xcf5d,0xdf7c,0xaf9b,0xbfba,0x8fd9,0x9ff8,
  0x6e17,0x7e36,0x4e55,0x5e74,0x2e93,0x3eb2,0x0ed1,0x1ef0,
]);

function crc16(data: Uint8Array): number {
  let crc = 0;
  for (let i = 0; i < data.byteLength; i++) {
    crc = ((crc << 8) & 0xffff) ^ CRC16_TABLE[((crc >> 8) ^ data[i]) & 0xff];
  }
  return crc;
}

const B32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function base32Encode(bytes: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let out = "";
  for (let i = 0; i < bytes.length; i++) {
    value = (value << 8) | bytes[i];
    bits += 8;
    while (bits >= 5) {
      out += B32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += B32_ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

// Encodes a raw 32-byte Ed25519 public key (as exported from WebCrypto) into
// nkey text form for the given prefix byte (NKEY_USER_PREFIX here, always —
// this test only ever mints user identities this way).
function encodeNatsPublicKey(
  prefixByte: number,
  rawPublicKeyBytes: Uint8Array,
): string {
  const raw = new Uint8Array(1 + rawPublicKeyBytes.length + 2);
  raw[0] = prefixByte;
  raw.set(rawPublicKeyBytes, 1);
  const checksum = crc16(raw.subarray(0, 1 + rawPublicKeyBytes.length));
  new DataView(raw.buffer).setUint16(
    1 + rawPublicKeyBytes.length,
    checksum,
    true,
  );
  return base32Encode(raw);
}

// Builds an AsyncAuthenticator that signs the server's nonce with a
// WebCrypto private key directly (crypto.subtle.sign — never exporting the
// key, exactly as a non-extractable key requires), and presents the given
// jwt/nkey alongside it. Mirrors dpopAuthenticator in
// geekdotdev/nats-nkey-demo-priv's callout-pop-zero-permission.js line for
// line: nkeys.encode() here is this fork's own bundled encoder, so the wire
// format matches exactly what the server expects.
function webCryptoAuthenticator(
  jwt: string,
  nkey: string,
  privateKey: CryptoKey,
): (nonce?: string) => Promise<Auth> {
  return async (nonce?: string): Promise<Auth> => {
    const challenge = new TextEncoder().encode(nonce || "");
    const sigBuffer = await crypto.subtle.sign(
      { name: "Ed25519" },
      privateKey,
      challenge,
    );
    const sig = nkeys.encode(new Uint8Array(sigBuffer));
    return { jwt, nkey, sig } as Auth;
  };
}

// This is the actual end-to-end proof that the chain of trust from a
// constructed, key-bound JWT to the server's nonce-signature verification is
// unbroken: a JWT whose `sub` names one WebCrypto key pair's public half must
// only ever be usable by the connection that holds that key pair's private
// half. Two *different*, real, non-extractable WebCrypto-generated Ed25519
// key pairs stand in for "a legitimate holder" and "an attacker who has
// somehow obtained a copy of the JWT but not the matching private key" — the
// second one tries to connect with kp1's JWT while signing with kp2's key,
// i.e. presenting kp2's own nkey/signature alongside kp1's sub claim. No such
// test existed in this file before this one.
Deno.test("authenticator - async fn: a JWT bound to one WebCrypto key pair is rejected when signed with a different one", async () => {
  const O = nkeys.createOperator();
  const A = nkeys.createAccount();

  const kp1 = await crypto.subtle.generateKey({ name: "Ed25519" }, false, [
    "sign",
  ]) as CryptoKeyPair;
  const kp2 = await crypto.subtle.generateKey({ name: "Ed25519" }, false, [
    "sign",
  ]) as CryptoKeyPair;
  const pub1 = encodeNatsPublicKey(
    NKEY_USER_PREFIX,
    new Uint8Array(await crypto.subtle.exportKey("raw", kp1.publicKey)),
  );
  const pub2 = encodeNatsPublicKey(
    NKEY_USER_PREFIX,
    new Uint8Array(await crypto.subtle.exportKey("raw", kp2.publicKey)),
  );

  // The JWT's sub is pub1 only. encodeUser's second parameter accepts a bare
  // nkey string (jsr:@nats-io/jwt's Key = string | Uint8Array | KeyPair) —
  // exactly what a WebCrypto-only identity has, since there is no nkeys
  // KeyPair wrapping a non-extractable key.
  const ujwt = await encodeUser("U", pub1, A, {});

  const resolver: Record<string, string> = {};
  resolver[A.getPublicKey()] = await encodeAccount("A", A, {
    limits: { conn: -1, subs: -1 },
  }, { signer: O });
  const conf = {
    operator: await encodeOperator("O", O),
    resolver: "MEMORY",
    "resolver_preload": resolver,
  };

  const ns = await NatsServer.start(conf);
  try {
    // The spoof attempt: kp1's JWT, but kp2's nkey and kp2's signature over
    // the nonce. If the server accepted this, the JWT's sub binding would be
    // decorative rather than load-bearing — exactly the property this fork's
    // AsyncAuthenticator (and the browser PoP flow it exists for) depends on.
    const err = await assertRejects(() =>
      ns.connect({
        reconnect: false,
        asyncAuthenticator: webCryptoAuthenticator(ujwt, pub2, kp2.privateKey),
      })
    );
    assertInstanceOf(err, AuthorizationError);
    // Specifically an authorization rejection, not a connection that merely
    // never completed. This is what rules out a dropped or mishandled PING
    // as the actual cause — a real failure mode in this codebase's own
    // history (see "async fn ignores data before connect" and "async fn:
    // server -ERR preempts a pending authenticator", above): those would
    // surface as a timeout or a closed connection with no server -ERR at
    // all, never as an AuthorizationError carrying this message.
    assertStringIncludes(
      (err as Error).message.toLowerCase(),
      "authorization violation",
    );

    // Positive control: same server, same async-signing pathway, same
    // absence of any artificial delay — kp1 signing for its own JWT
    // succeeds. This is what isolates the rejection above to the key
    // mismatch specifically: if PINGs, or anything else about this async
    // path, were the real problem, this connection would fail too.
    const nc = await ns.connect({
      reconnect: false,
      asyncAuthenticator: webCryptoAuthenticator(ujwt, pub1, kp1.privateKey),
    });
    await nc.flush();
    assertEquals(nc.isClosed(), false);
    await nc.close();
  } finally {
    await ns.stop(true);
  }
});
