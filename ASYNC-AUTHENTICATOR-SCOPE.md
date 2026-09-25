# Scope: Async-Capable Authenticator (for Browser-Based DPoP)

Revision 2 — replaces the "widen `Dispatcher`/`Authenticator`/`parser.parse()`
everywhere" approach from the first pass with a smaller, additive,
opt-in design. Traced against this fork's actual source (`core/src/`), not
from memory — every file/line reference below was read directly before being
listed here, and the server-side behavior below was verified against
`nats-server`'s actual source, not assumed.

## Why this is needed

A browser-side DPoP design (see the referencing project's
`DPoP-REFACTORING.md`) needs the NATS connection handshake to sign the
server's nonce with a WebCrypto `CryptoKey` — `crypto.subtle.sign()`, which
is unavoidably asynchronous on every browser, by spec, with no synchronous
alternative. Confirmed (issue history: nats-io/nats.js#282, #292) that the
current `Authenticator` contract is synchronous by design, not oversight —
the maintainer's own reference authenticator code uses synchronous
`nkeys.js` signing, and a synchronous `try/catch` around the authenticator
call in `protocol.ts` only makes sense if a thrown error is expected
synchronously.

## Design: additive opt-in, not a widened shared type

The first pass of this scope proposed widening `Dispatcher<T>.push()`,
`Authenticator`, and making `Parser.parse()` itself `async` — correct, but a
large, cross-cutting diff touching code every existing user of the library
depends on, for a capability almost none of them need. Revised approach:
leave every existing type and code path **completely untouched**, and add a
new, separately-named, opt-in mechanism instead.

Naming: **not** DPoP-specific. From the library's perspective this is just
"an authenticator that needs to do async work" — could be WebCrypto signing,
could be a remote credential fetch, could be anything. Baking a narrow
OAuth-specific term into a general-purpose client's public API is exactly
what a maintainer reviewing for a general audience would push back on. Named
to match the existing convention instead:

```ts
export type AsyncAuthenticator = (nonce?: string) => Promise<Auth>;

export interface ConnectionOptions {
  ...
  authenticator?: Authenticator | Authenticator[]; // existing, untouched
  asyncAuthenticator?: AsyncAuthenticator;           // new, additive
}
```

### The core change: fire-and-forget from a still-synchronous `processInfo`

`Connect` is a plain class; JS constructors cannot be `async` — this
constraint doesn't go away just because of the naming/typing change above.
What changes is *where* the async boundary lives: instead of making
`processInfo` itself `async` and awaiting inline (which would force `push`
and `parser.parse` to become awaitable too, rippling into code every
non-DPoP user also runs), `processInfo` stays synchronous and kicks off the
async resolution without awaiting it inline — the resulting `.then()`
callback is responsible for constructing and sending `CONNECT` once ready,
entirely decoupled from the synchronous call stack that invoked
`processInfo`.

```ts
// protocol.ts, processInfo — sketch, not final code
processInfo(m: Uint8Array): void {   // signature UNCHANGED — still sync
  const info = JSON.parse(decode(m));
  ...
  if (!this.infoReceived) {
    this.infoReceived = true;
    const { version, lang } = this.transport;

    if (this.options.asyncAuthenticator) {
      this.awaitingAsyncConnect = true;         // see ignore-gate below
      this.options.asyncAuthenticator(info.nonce)
        .then((creds) => {
          this.sendConnect({ version, lang }, info.nonce, creds, info.headers);
          this.awaitingAsyncConnect = false;
        })
        .catch((err) => {
          this.awaitingAsyncConnect = false;
          this.close(err).catch();
        });
    } else {
      // existing path, byte-for-byte unchanged
      const c = new Connect({ version, lang }, this.options, info.nonce);
      if (info.headers) { c.headers = true; c.no_responders = true; }
      this.transport.send(encode(`CONNECT ${JSON.stringify(c)}${CR_LF}`));
      this.transport.send(PING_CMD);
    }
  }
  ...
}
```

(`sendConnect` here is a small extracted helper doing what the `else`
branch does inline — used by both paths so the actual frame-construction
logic isn't duplicated.)

### Server-verified: the ordering gap is real, and there's a second, sharper deadline

Checked directly against `nats-server`'s own source (`server.go`,
`const.go`) rather than assumed:

- **A PING timer is armed immediately after `INFO` is sent**, confirmed by
  the server's own comment at `server.go:3575-3576`: *"Set the Ping timer.
  Will be reset once connect was received."* — explicit confirmation the
  timer runs *before* `CONNECT` arrives, not after.
- **A separate, sharper deadline**: `c.setAuthTimer(secondsToDuration(opts.AuthTimeout))`
  at `server.go:3570`, using default `AUTH_TIMEOUT = 2 * time.Second`
  (`const.go:117`). If the full round trip — WebCrypto sign plus the
  browser→spa-server→dpop-signing-service hop, including a cold JWKS fetch
  against Keycloak — takes longer than 2 seconds, `nats-server` closes the
  connection outright. This is a deployment/config concern for the
  referencing project (`nats-server.conf` doesn't currently set
  `authTimeout` explicitly), not something this fork's code can fix, but
  worth carrying back to that project as a finding from this work.

### Closing the ordering gap deterministically, not by assuming it's harmless

Per explicit instruction: the reader loop must **ignore** any data arriving
before this connection's own `CONNECT` has actually been sent — not rely on
`nats-server` happening not to send anything meaningful in that window.

Gate this at `ProtocolHandler.push()` — the single chokepoint every parsed
event already flows through before dispatch:

```ts
// protocol.ts
private awaitingAsyncConnect = false; // true only between kicking off
                                       // asyncAuthenticator and CONNECT
                                       // actually being sent

push(e: ParserEvent): void {          // signature UNCHANGED — still sync
  if (this.awaitingAsyncConnect && e.kind !== Kind.INFO) {
    // We haven't sent our own CONNECT yet — nothing the server sends here
    // should be acted on. Bytes are still parsed (parser state/framing
    // stays correct), the resulting event is just dropped.
    return;
  }
  switch (e.kind) {
    ...
  }
}
```

`e.kind !== Kind.INFO` matters: the very `INFO` event that triggers
`processInfo` (and thus sets the gate) must still reach `processInfo` —
the exemption is for that one case only, not a way back in for anything
else. Every other event kind (`PING`, a second `INFO`, anything) arriving
in the window is silently dropped, full stop, regardless of what it is.

This does mean a `PING` arriving in that window won't get a `PONG` reply
from this client. Given the window is normally sub-second (a fast
Ed25519 sign plus one internal HTTP hop) and the server's own `AUTH_TIMEOUT`
already bounds how long the server will wait before giving up regardless,
not replying to an early, unsolicited `PING` doesn't introduce a new
failure mode — the connection was already racing the 2-second auth
deadline either way.

`parser.parse()` and `Dispatcher<T>` are untouched by this — the gate lives
entirely inside `push()`'s existing synchronous body, one new field, one
new early-return check.

## Every file that needs to change

1. **`core/src/core.ts`**
   - Add `AsyncAuthenticator` type (new, alongside existing `Authenticator`)
   - Add `asyncAuthenticator?: AsyncAuthenticator` to `ConnectionOptions`
   - `Authenticator`, `Auth`, `Dispatcher<T>` — **unchanged**

2. **`core/src/protocol.ts`** (the entire real change)
   - `ProtocolHandler`: add `private awaitingAsyncConnect = false`
   - `push(e)`: add the ignore-gate early return — one `if`, no signature change
   - `processInfo(m)`: branch on `this.options.asyncAuthenticator` — existing
     branch untouched, new branch does the fire-and-forget resolution above
   - Extract the `Connect`-construct-and-send logic (currently inline in
     `processInfo`) into a small `sendConnect(...)` helper, called from both
     branches — avoids duplicating frame-construction between them
   - `Connect` class itself: **unchanged** — the new path still constructs
     a normal `Connect`, just with `creds` already resolved and merged in
     (via the existing `extend(this, creds)` call, or passed as a
     constructor parameter — either preserves the existing class shape)

3. **`core/src/parser.ts`, `core/src/authenticator.ts`** — **unchanged**.
   `multiAuthenticator` is a separate, sync-only composition mechanism for
   the existing `Authenticator` type; out of scope here since this design
   doesn't touch that type at all. (If composing multiple async
   authenticators together is ever needed, that's a distinct, later
   addition — not required for a single DPoP `asyncAuthenticator`.)

## What does *not* need to change

- `WsTransport` (`ws_transport.ts`) — untouched, as before.
- `Dispatcher<T>`, the existing `Authenticator` type, `Parser.parse()` — all
  **completely unmodified**, not just "compatible." This is the main
  improvement over the first scope pass.
- Every existing authenticator (`nkeyAuthenticator`, `jwtAuthenticator`,
  `credsAuthenticator`, any user-supplied sync function) and `multiAuthenticator`
  — entirely unaffected; they're a different option (`authenticator`) taking
  a different, untouched code path.
- The public `connect()`/`wsconnect()` entry points.

## Test surface

- `core/tests/authenticator_test.ts`, `core/tests/auth_test.ts` — must keep
  passing with zero changes, since nothing they exercise is modified.
- `core/tests/reconnect_test.ts` — `processInfo` is the same code path for
  both initial connect and every reconnect (`infoReceived` reset to `false`
  on disconnect, confirmed at `protocol.ts:483`, rechecked at `:859`), so
  this is also where an async-authenticator-across-reconnect test belongs.

New coverage needed:
- `asyncAuthenticator` resolving after a real delay — connects successfully,
  `CONNECT` observed on the wire only after the delay.
- `asyncAuthenticator` rejecting — connection closes with that error
  surfaced (not the silent-timeout behavior #282 reported for synchronous
  throws).
- A `PING` (or any other frame) injected between `INFO` and the resolved
  `CONNECT` — assert it's dropped and never reaches `processPing`/etc., and
  that the connection still completes normally once the authenticator
  resolves. This is the test that actually proves the ignore-gate works,
  not just that it compiles.
- Confirm `awaitingAsyncConnect` is correctly reset to `false` on both the
  success and rejection paths (a stuck `true` would silently black-hole
  every subsequent message on a connection that otherwise looks fine).

## Effort/risk assessment

- **Smaller than the first pass**: two files instead of four, one of them
  (`core.ts`) just adding new, unused-by-default type surface.
- **Structurally safer**: no shared, always-executed code path (`push`,
  `parse`) changes behavior for existing users in any way — the diff is
  entirely inside a new conditional branch nobody hits unless they set
  `asyncAuthenticator`.
- **The auth-timeout finding is the one item that isn't a code-scope
  concern at all** — it's a deployment finding for the referencing project,
  worth raising there independent of whether/when this fork change lands.
