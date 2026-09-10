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

import { cleanup, setup } from "nst";

import {
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

import { assertEquals, assertRejects, assertThrows } from "@std/assert";
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
