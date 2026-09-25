/*
 * Copyright 2025 The NATS Authors
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

import { NatsServer } from "nst";
import { createServer, type Server, type Socket } from "node:net";
import type { Buffer } from "node:buffer";
import {
  assert,
  assertEquals,
  assertInstanceOf,
  assertRejects,
  assertThrows,
} from "@std/assert";
import {
  asyncAuthenticator,
  AuthorizationError,
  Connect,
  deferred,
  delay,
  InvalidArgumentError,
  parseOptions,
  tokenAuthenticator,
} from "../src/internal_mod.ts";
import type { Auth, Authenticator } from "../src/internal_mod.ts";
import { AUTH_RESOLVER } from "../src/authenticator.ts";
import type { AuthResolver } from "../src/authenticator.ts";
import { connect } from "./connect.ts";

type Resolvable = { resolve: AuthResolver | undefined };

function resolverOf(opts: Parameters<typeof parseOptions>[0]): Resolvable {
  const o = parseOptions(opts) as unknown as Record<symbol, AuthResolver>;
  return { resolve: o[AUTH_RESOLVER] };
}

// ---------------------------------------------------------------------------
// option parsing / resolver (design 6.1, 6.1a)
// ---------------------------------------------------------------------------

Deno.test("async authenticator - options without an async member get no resolver", () => {
  const plain = parseOptions({ token: "t" }) as unknown as Record<
    symbol,
    unknown
  >;
  assertEquals(plain[AUTH_RESOLVER], undefined);
  assertEquals(
    (plain as unknown as { authenticator: Authenticator }).authenticator(),
    { auth_token: "t" },
  );

  const sync = parseOptions({
    authenticator: [tokenAuthenticator("a"), tokenAuthenticator("b")],
  }) as unknown as Record<symbol, unknown>;
  assertEquals(sync[AUTH_RESOLVER], undefined);
  assertEquals(
    (sync as unknown as { authenticator: Authenticator }).authenticator(),
    { auth_token: "b" },
  );
});

Deno.test("async authenticator - Connect still runs the authenticator without creds", () => {
  const c = new Connect(
    { version: "1.0.0", lang: "lang" },
    { authenticator: tokenAuthenticator("x") },
  );
  assertEquals(c.auth_token, "x");
});

Deno.test("async authenticator - Connect uses pre-resolved creds instead of the authenticator", () => {
  let called = 0;
  const c = new Connect(
    { version: "1.0.0", lang: "lang" },
    {
      authenticator: () => {
        called++;
        return { auth_token: "no" };
      },
    },
    "nonce",
    { auth_token: "yes" },
  );
  assertEquals(c.auth_token, "yes");
  assertEquals(called, 0);

  // an empty result is "no credentials", and must not fall back to the
  // authenticator either
  const empty = new Connect(
    { version: "1.0.0", lang: "lang" },
    { authenticator: () => ({ auth_token: "no" }) },
    "nonce",
    {} as Auth,
  );
  assertEquals(empty.auth_token, undefined);
});

Deno.test("async authenticator - calling it synchronously throws", () => {
  const a = asyncAuthenticator(() => Promise.resolve({ auth_token: "x" }));
  assertEquals(typeof a, "function");
  assertThrows(() => a(), InvalidArgumentError);

  // parsed options stay valid but their authenticator refuses direct use
  const o = parseOptions({ authenticator: a }) as unknown as {
    authenticator: Authenticator;
  };
  assertEquals(typeof o.authenticator, "function");
  assertThrows(() => o.authenticator(), InvalidArgumentError);

  assertThrows(
    () => asyncAuthenticator("nope" as unknown as () => Promise<Auth>),
    InvalidArgumentError,
  );
});

Deno.test("async authenticator - accepted alone and in the authenticator array", async () => {
  const a = asyncAuthenticator(() => Promise.resolve({ auth_token: "x" }));
  const alone = resolverOf({ authenticator: a });
  assert(alone.resolve);
  assertEquals(await alone.resolve!("n"), { auth_token: "x" });

  const arr = resolverOf({ authenticator: [tokenAuthenticator("s"), a] });
  assertEquals(await arr.resolve!("n"), { auth_token: "x" });
});

Deno.test("async authenticator - passes the nonce", async () => {
  const r = resolverOf({
    authenticator: asyncAuthenticator((n) =>
      Promise.resolve({ auth_token: n as string })
    ),
  });
  assertEquals(await r.resolve!("abc"), { auth_token: "abc" });
});

Deno.test("async authenticator - merge follows member order, later wins", async () => {
  const a = (t: string) =>
    asyncAuthenticator(() => Promise.resolve({ auth_token: t }));
  const s = (t: string) => tokenAuthenticator(t);

  // array order
  assertEquals(
    await resolverOf({ authenticator: [a("a1"), s("s1")] }).resolve!(),
    { auth_token: "s1" },
  );
  assertEquals(
    await resolverOf({ authenticator: [s("s1"), a("a1")] }).resolve!(),
    { auth_token: "a1" },
  );
  assertEquals(
    await resolverOf({ authenticator: [a("a1"), s("s1"), a("a2")] })
      .resolve!(),
    { auth_token: "a2" },
  );

  // same order as the sync path: authenticator(s), then token, then user/pass
  assertEquals(
    await resolverOf({ authenticator: a("a1"), token: "t" }).resolve!(),
    { auth_token: "t" },
  );
  assertEquals(
    await resolverOf({ authenticator: a("a1"), user: "u", pass: "p" })
      .resolve!(),
    { auth_token: "a1", user: "u", pass: "p" },
  );
  // ...which is exactly what the sync path does with a sync authenticator
  const syncOpts = parseOptions({
    authenticator: s("s1"),
    token: "t",
  }) as unknown as { authenticator: Authenticator };
  assertEquals(syncOpts.authenticator(), { auth_token: "t" });
});

Deno.test("async authenticator - members run concurrently", async () => {
  const slow = (ms: number, v: string) =>
    asyncAuthenticator(async () => {
      await delay(ms);
      return { auth_token: v };
    });
  const r = resolverOf({ authenticator: [slow(300, "a"), slow(300, "b")] });
  const start = Date.now();
  assertEquals(await r.resolve!(), { auth_token: "b" });
  const elapsed = Date.now() - start;
  assert(elapsed < 550, `expected concurrent members, took ${elapsed}ms`);
});

Deno.test("async authenticator - a rejecting member rejects the result", async () => {
  const bad = asyncAuthenticator(() => Promise.reject(new Error("boom")));
  const other = asyncAuthenticator(() => Promise.reject(new Error("other")));
  const r = resolverOf({ authenticator: [bad, other] });
  await assertRejects(async () => await r.resolve!(), Error, "boom");
  // the second rejection was handled by Promise.all: nothing left unhandled
  await delay(20);
});

Deno.test("async authenticator - a sync member throwing after an async one started leaks nothing", async () => {
  const bad = asyncAuthenticator(() => Promise.reject(new Error("async-boom")));
  const throwing: Authenticator = () => {
    throw new Error("sync-boom");
  };
  const r = resolverOf({ authenticator: [bad, throwing] });
  assertThrows(() => r.resolve!(), Error, "sync-boom");
  // an unhandled "async-boom" rejection would fail this test
  await delay(20);
});

Deno.test("async authenticator - an async member returning a non-promise is treated as sync", () => {
  const r = resolverOf({
    authenticator: asyncAuthenticator(
      (() => ({ auth_token: "x" })) as unknown as () => Promise<Auth>,
    ),
  });
  assertEquals(r.resolve!(), { auth_token: "x" });
});

Deno.test("async authenticator - null result is no credentials", async () => {
  const r = resolverOf({
    authenticator: asyncAuthenticator(() =>
      Promise.resolve(null as unknown as Auth)
    ),
  });
  assertEquals(await r.resolve!(), {} as unknown as Auth);
});

// ---------------------------------------------------------------------------
// the connect hold against a scripted server (design 5, 6.3-6.6)
// ---------------------------------------------------------------------------

type Conn = { socket: Socket; received: string; lines: string[] };

/**
 * A scripted server: sends INFO (with a nonce) followed by PING in one write,
 * like nats-server does, records everything the client writes, and answers
 * PING with PONG.
 */
class Scripted {
  server!: Server;
  port = 0;
  conns: Conn[] = [];
  onConn?: (c: Conn, n: number) => void;

  static async start(onConn?: (c: Conn, n: number) => void) {
    const s = new Scripted();
    s.onConn = onConn;
    const ready = deferred<void>();
    s.server = createServer((socket) => {
      const c: Conn = { socket, received: "", lines: [] };
      s.conns.push(c);
      socket.on("error", () => {});
      socket.on("data", (b: Buffer) => {
        const t = b.toString();
        c.received += t;
        for (const line of t.split("\r\n")) {
          if (line === "") continue;
          c.lines.push(line);
          if (line === "PING") {
            socket.write("PONG\r\n");
          }
        }
      });
      const info = JSON.stringify({
        server_id: "SCRIPTED",
        version: "2.10.0",
        host: "127.0.0.1",
        port: s.port,
        headers: true,
        auth_required: true,
        nonce: "nonce-1",
      });
      // INFO and the first PING in the same write
      socket.write(`INFO ${info}\r\nPING\r\n`);
      s.onConn?.(c, s.conns.length);
    });
    s.server.listen(0, "127.0.0.1", () => {
      s.port = (s.server.address() as { port: number }).port;
      ready.resolve();
    });
    await ready;
    return s;
  }

  connects(): string[] {
    return this.conns.flatMap((c) =>
      c.lines.filter((l) => l.startsWith("CONNECT "))
    );
  }

  async stop() {
    this.conns.forEach((c) => c.socket.destroy());
    await new Promise<void>((r) => this.server.close(() => r()));
  }
}

function connectJson(line: string): Record<string, unknown> {
  return JSON.parse(line.slice("CONNECT ".length));
}

Deno.test("async authenticator - early PING is answered after CONNECT, in order", async () => {
  const s = await Scripted.start((c) => {
    // a second server PING arrives while the authenticator is still pending
    setTimeout(() => c.socket.write("PING\r\n"), 100);
  });
  try {
    const nc = await connect({
      port: s.port,
      reconnect: false,
      authenticator: asyncAuthenticator(async (nonce) => {
        await delay(300);
        return { auth_token: `t:${nonce}` };
      }),
    });
    await delay(50);
    const lines = s.conns[0].lines;
    // CONNECT first, then our PING, then a PONG for each held server PING
    assert(lines[0].startsWith("CONNECT "), `first line was ${lines[0]}`);
    assertEquals(connectJson(lines[0]).auth_token, "t:nonce-1");
    assertEquals(lines.slice(1), ["PING", "PONG", "PONG"]);
    await nc.close();
  } finally {
    await s.stop();
  }
});

Deno.test("async authenticator - sync credentials still send CONNECT inline", async () => {
  const s = await Scripted.start();
  try {
    const nc = await connect({
      port: s.port,
      reconnect: false,
      token: "sync",
    });
    await delay(50);
    const lines = s.conns[0].lines;
    assert(lines[0].startsWith("CONNECT "));
    assertEquals(connectJson(lines[0]).auth_token, "sync");
    // the early server PING is answered right away, after CONNECT+PING
    assertEquals(lines.slice(1), ["PING", "PONG"]);
    await nc.close();
  } finally {
    await s.stop();
  }
});

Deno.test("async authenticator - merges with token in CONNECT", async () => {
  const s = await Scripted.start();
  try {
    const nc = await connect({
      port: s.port,
      reconnect: false,
      user: "u",
      pass: "p",
      authenticator: asyncAuthenticator(() =>
        Promise.resolve({ jwt: "j", nkey: "k", sig: "sg" })
      ),
    });
    const c = connectJson(s.conns[0].lines[0]);
    assertEquals(
      [c.jwt, c.nkey, c.sig, c.user, c.pass],
      ["j", "k", "sg", "u", "p"],
    );
    await nc.close();
  } finally {
    await s.stop();
  }
});

Deno.test("async authenticator - rejecting authenticator rejects connect() with its error", async () => {
  const s = await Scripted.start();
  try {
    await assertRejects(
      () =>
        connect({
          port: s.port,
          reconnect: false,
          authenticator: asyncAuthenticator(() =>
            Promise.reject(new Error("signer offline"))
          ),
        }),
      Error,
      "signer offline",
    );
    // and nothing was ever written
    assertEquals(s.connects().length, 0);
  } finally {
    await s.stop();
  }
});

Deno.test("async authenticator - a throwing (non-async) function rejects connect() too", async () => {
  const s = await Scripted.start();
  try {
    await assertRejects(
      () =>
        connect({
          port: s.port,
          reconnect: false,
          authenticator: asyncAuthenticator(() => {
            throw new Error("sync throw");
          }),
        }),
      Error,
      "sync throw",
    );
  } finally {
    await s.stop();
  }
});

Deno.test("async authenticator - server -ERR during the window is reported, late result dropped", async () => {
  const release = deferred<void>();
  const s = await Scripted.start((c) => {
    setTimeout(() => c.socket.write("-ERR 'Authentication Timeout'\r\n"), 100);
  });
  try {
    let resolved = false;
    const p = connect({
      port: s.port,
      reconnect: false,
      authenticator: asyncAuthenticator(async () => {
        await release;
        resolved = true;
        return { auth_token: "late" };
      }),
    });
    const err = await assertRejects(() => p);
    assertInstanceOf(err, AuthorizationError);
    assert(!resolved, "must be reported before the authenticator settles");
    // the authenticator finishing later must not write CONNECT
    release.resolve();
    await delay(100);
    assertEquals(s.connects().length, 0);
  } finally {
    release.resolve();
    await s.stop();
  }
});

Deno.test("async authenticator - reconnect while an attempt is pending abandons it", async () => {
  const gates: Array<ReturnType<typeof deferred<void>>> = [];
  let calls = 0;
  const s = await Scripted.start();
  try {
    const nc = await connect({
      port: s.port,
      reconnectTimeWait: 20,
      reconnectJitter: 0,
      // a dial whose socket dies before the server's reply only gives way to
      // the next attempt when the dial timeout fires (same as sync credentials)
      timeout: 500,
      authenticator: asyncAuthenticator(async () => {
        const n = ++calls;
        if (n === 2) {
          // second attempt: stays pending until the server drops it
          const d = deferred<void>();
          gates.push(d);
          await d;
        }
        return { auth_token: `attempt-${n}` };
      }),
    });
    assertEquals(s.conns.length, 1);

    // drop the connection: attempt 2 starts and stays pending
    s.conns[0].socket.destroy();
    while (s.conns.length < 2) await delay(10);
    await delay(50);
    // drop that one while still pending: attempt 3 starts and succeeds
    s.conns[1].socket.destroy();
    while (s.conns.length < 3) await delay(10);
    await delay(200);

    // now the abandoned attempt 2 settles: it must not write anywhere
    gates[0].resolve();
    await delay(100);

    assertEquals(s.conns[1].lines.length, 0, "abandoned attempt wrote");
    const third = s.conns[2].lines;
    assert(third[0].startsWith("CONNECT "));
    assertEquals(connectJson(third[0]).auth_token, "attempt-3");
    // no connection saw a PONG before its CONNECT
    for (const c of s.conns) {
      const pong = c.lines.indexOf("PONG");
      const conn = c.lines.findIndex((l) => l.startsWith("CONNECT "));
      if (pong !== -1) assert(conn !== -1 && conn < pong);
    }
    assertEquals(calls, 3);
    assertEquals(nc.isClosed(), false);
    await nc.close();
  } finally {
    await s.stop();
  }
});

Deno.test("async authenticator - close() while a reconnect attempt is pending writes nothing", async () => {
  const gate = deferred<void>();
  let calls = 0;
  const s = await Scripted.start();
  try {
    const nc = await connect({
      port: s.port,
      reconnectTimeWait: 20,
      reconnectJitter: 0,
      authenticator: asyncAuthenticator(async () => {
        if (++calls === 2) {
          await gate;
        }
        return { auth_token: "x" };
      }),
    });
    s.conns[0].socket.destroy();
    while (s.conns.length < 2) await delay(10);
    await delay(50);

    await nc.close();
    gate.resolve();
    await delay(100);
    assertEquals(s.conns[1].lines.length, 0);
    assertEquals(s.connects().length, 1);
  } finally {
    gate.resolve();
    await s.stop();
  }
});

// ---------------------------------------------------------------------------
// against a real nats-server (design 8, rows G/H)
// ---------------------------------------------------------------------------

Deno.test("async authenticator - connects to nats-server and flushes", async () => {
  const ns = await NatsServer.start({ authorization: { token: "s3cret" } });
  try {
    const nc = await ns.connect({
      authenticator: asyncAuthenticator(async () => {
        await delay(200);
        return { auth_token: "s3cret" };
      }),
    });
    await nc.flush();
    await nc.close();
  } finally {
    await ns.stop(true);
  }
});

Deno.test("async authenticator - stays connected when the server pings during a slow authenticator", async () => {
  // The server pings before CONNECT. Those pings must be answered, but only
  // after CONNECT: dropping them leaves the server's unanswered-ping count at
  // ping_max, and the next tick closes the connection with 'Stale
  // Connection'. So the window must span two server pings (t=400ms, 800ms)
  // yet end before the server's own deadline of ping_interval * (ping_max + 1)
  // = 1200ms: CONNECT goes out at ~1000ms.
  const ns = await NatsServer.start({
    authorization: { token: "s3cret", timeout: 10 },
    ping_interval: "400ms",
    ping_max: 2,
  });
  try {
    const nc = await ns.connect({
      authenticator: asyncAuthenticator(async () => {
        await delay(1000);
        return { auth_token: "s3cret" };
      }),
    });
    const events: string[] = [];
    (async () => {
      for await (const s of nc.status()) {
        events.push(s.type);
      }
    })().then();
    await delay(1500);
    await nc.flush();
    assertEquals(nc.isClosed(), false);
    assertEquals(events, []);
    await nc.close();
  } finally {
    await ns.stop(true);
  }
});

Deno.test("async authenticator - reports the server's Authentication Timeout instead of a generic error", async () => {
  const ns = await NatsServer.start({
    authorization: { token: "s3cret", timeout: 1 },
  });
  const release = deferred<void>();
  try {
    let resolved = false;
    const err = await assertRejects(() =>
      ns.connect({
        reconnect: false,
        authenticator: asyncAuthenticator(async () => {
          await release;
          resolved = true;
          return { auth_token: "s3cret" };
        }),
      })
    );
    assertInstanceOf(err, AuthorizationError);
    assert(!resolved, "reported before the authenticator settled");
    assert(/timeout/i.test((err as Error).message), (err as Error).message);
  } finally {
    release.resolve();
    await ns.stop(true);
  }
});

Deno.test("async authenticator - reconnects to nats-server, calling the authenticator each time", async () => {
  const ns = await NatsServer.start({
    authorization: { token: "s3cret", timeout: 10 },
    ping_interval: "200ms",
    ping_max: 2,
  });
  try {
    let calls = 0;
    const nc = await ns.connect({
      reconnectTimeWait: 50,
      reconnectJitter: 0,
      authenticator: asyncAuthenticator(async () => {
        calls++;
        await delay(250);
        return { auth_token: "s3cret" };
      }),
    });
    const reconnected = deferred<void>();
    (async () => {
      for await (const s of nc.status()) {
        if (s.type === "reconnect") reconnected.resolve();
      }
    })().then();
    // deno-lint-ignore no-explicit-any
    await (nc as any).reconnect();
    await reconnected;
    await delay(500);
    await nc.flush();
    assertEquals(nc.isClosed(), false);
    assertEquals(calls, 2);
    await nc.close();
  } finally {
    await ns.stop(true);
  }
});
