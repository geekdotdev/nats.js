# Async-capable connection handshake for `nats-core` — design (connect-time hold queue + unified credential resolver)

**Status:** implemented in the working tree (uncommitted); see §12 for what
implementation changed · **Base:** `3a7b736b175d9a387130210c88f851d71e1b014f`
(`feat(jetstream): add consumers.addOrUpdate (#412)`) · **Assumes:** the
AsyncAuthenticator commit `375fa189` is reverted / not applied. Every claim
about `nats-server` behavior below was verified against `nats-server` v2.14.6
(§4).

All file/line references are to the base commit. Code in this document is a
**design sketch**; it has not been compiled or run against the repo.

---

## 1. Summary

Today a NATS credential must be computed **synchronously**: `Connect`'s
constructor calls the authenticator, `processInfo` builds `Connect` inline,
`ProtocolHandler.push` and `Parser.parse` are `void`. That excludes anything
whose signature is async by spec — chiefly `crypto.subtle.sign` with a
non-extractable WebCrypto key, or a token fetch.

**This design leaves the parser, `Dispatcher<T>`, `Authenticator` and every
shared type untouched.** The event-buffering policy lives in its own module,
`HoldQueue<T>` (`core/src/hold_queue.ts`), which knows nothing about NATS and is
unit-tested on its own (§6.2). `ProtocolHandler` only wires it in:

1. While an async credential source is pending, `ProtocolHandler` holds a
   **hold** on its `HoldQueue`. `push(e)` offers each event to the queue, which
   **queues** it instead of letting it be handled (defer, not drop).
2. `-ERR` frames bypass the queue (**control lane**, the queue's `isUrgent`
   predicate): they never write to the wire, so handling them immediately is
   safe, and it is what lets the client report the server's explanation (e.g.
   `Authentication Timeout`) instead of a generic disconnect — on every
   transport including Deno.
3. When the credentials settle, one synchronous continuation writes
   `CONNECT`+`PING` and **releases the hold**, which replays the queue in order
   through the ordinary handler switch.
4. **There is no second option.** The repo already normalizes every credential
   source (`authenticator` function or array, `token`, `user`/`pass`) into one
   `multiAuthenticator` in `parseOptions` → `buildAuthenticator`
   (`options.ts:74-119`). That step is extended into a _resolver_ that may
   return a promise, and one new public helper, `asyncAuthenticator(fn)`, marks
   an async member. It goes wherever an `Authenticator` goes today, so it
   composes with the other members using the existing merge rules. `processInfo`
   resolves credentials itself and hands them to `Connect`, which removes the
   constructor limitation.

Outside the handshake window nothing is queued: with no hold open,
`connectHold.offer()` returns `false` and `push()` dispatches inline exactly as
today. The steady-state cost is one method call and one field read per event.

The queue holds events only while a hold is active. A variant with an always-on
consumer coroutine draining every event was discounted (§7).

---

## 2. Problem, in code

| Link                                                     | Location                                      | Why it is sync                                     |
| -------------------------------------------------------- | --------------------------------------------- | -------------------------------------------------- |
| `Connect` ctor calls `opts.authenticator(nonce)`         | `protocol.ts:80-118`                          | constructors cannot be `async`                     |
| `processInfo` builds + sends `CONNECT` inline            | `protocol.ts:853-902`                         | called from `push`, returns `void`                 |
| `ProtocolHandler.push(e)`                                | `protocol.ts:904-926`                         | implements `Dispatcher<ParserEvent>.push(): void`  |
| `Parser.parse` calls `dispatcher.push` inline at 7 sites | `parser.ts:222 :244 :286 :355 :404 :433 :502` | hot per-byte loop                                  |
| read loop `for await (b of transport) parser.parse(b)`   | `protocol.ts:578-586`                         | already an async IIFE, but does not await anything |

`Dispatcher<T>` (`core.ts:765`) is also implemented by `QueuedIteratorImpl`
(`queued_iterator.ts:21`), whose `push` is an array append; widening it would
put an async signature on every subscription/consumer/KV delivery path for no
benefit. That coupling is why the path _looks_ necessarily synchronous.

### What is wrong with the reverted fire-and-forget commit

It sets `awaitingAsyncConnect` and makes `push()` **discard** every event except
the triggering `INFO` until `CONNECT` is sent. Two problems, one of them newly
established:

1. **Dropped early `PING`s are not free (§4 row H).** The server's count of
   unanswered pings survives `CONNECT`. With the window spanning more than
   `ping_max` ping intervals, the server closes the connection with
   `-ERR 'Stale Connection'` right after `CONNECT`. The commit's own test only
   passed because it raised `ping_max` to 50.
2. **Dropped `-ERR` frames.** `Authentication Timeout` / `Stale Connection`
   raised during the window are parsed and discarded.

Plus correctness bookkeeping in four places (flag, generation counter, `.then`
closure, `push` filter). This design keeps the good idea (holding in `push`) and
fixes both defects with one piece of state.

---

## 3. Goals and non-goals

**Goals**

- G1. An `asyncAuthenticator()` member may take as long as the server allows
  (§4) without any event being handled out of order or lost.
- G2. **Zero change** for sync users: same call order, same timing, no extra
  microtask, no allocation.
- G3. No change to `Parser`, `Dispatcher<T>`, `QueuedIteratorImpl`, or any
  subscription/JetStream/KV path.
- G4. A superseded attempt (reconnect, `close()`) never acts on the current
  connection.
- G5. Authenticator failure surfaces the same way a sync authenticator failure
  does today.
- G6. The server's `-ERR` during the window is reported, on every transport.
- G7. One credential model: sync and async sources compose in a single
  `authenticator` option, merged with today's rules. No parallel option, no
  "both set" case.

**Non-goals**

- Changing reconnect/backoff policy.
- Cancelling an in-flight authenticator (a signal is proposed in §11).

---

## 4. Protocol facts that constrain the design (empirically verified)

Setup: local `nats-server` v2.14.6, `authorization { token: "s3cret" }`, raw TCP
socket in Python, fresh connection per row. Rows A–F:
`ping_interval: 1s, timeout: 2`. Rows G, H, H′:
`ping_interval: 200ms,
ping_max: 2, timeout: 10`.

| #  | Client action                                                                                                  | Server result                                                    |
| -- | -------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------- |
| A  | read `INFO`, then wait                                                                                         | server sends **`PING` before any `CONNECT`**                     |
| B  | send `PONG` before `CONNECT`                                                                                   | `-ERR 'Authorization Violation'` + **close**                     |
| C  | send `PING` before `CONNECT`                                                                                   | `-ERR 'Authorization Violation'` + **close**                     |
| D  | send nothing for 2 s                                                                                           | `PING`, then `-ERR 'Authentication Timeout'` + close             |
| E  | `CONNECT`+`PING` after 1.3 s, then a **late `PONG`** for the early `PING`                                      | `PONG`; late `PONG` accepted; connection healthy                 |
| F  | `CONNECT` after the auth timeout                                                                               | connection already closed (EOF)                                  |
| G  | send nothing, `ping_interval 200ms`, `ping_max 2`                                                              | closed at **~0.61 s** with `-ERR 'Stale Connection'`             |
| H  | wait 0.35 s (2 server `PING`s arrive), send `CONNECT`+`PING`, answer only `PING`s arriving **after** `CONNECT` | closed **0.21 s after `CONNECT`** with `-ERR 'Stale Connection'` |
| H′ | as H, plus one `PONG` per early `PING` right after `CONNECT`                                                   | healthy for the full 3 s observed                                |

Consequences:

- **Do not answer pre-`CONNECT` events before `CONNECT`** (B, C).
- **Do answer them after `CONNECT`** (E, H vs H′). Deferral is _required_, not
  merely safe: this is the hold queue's raison d'être.
- **Hard server-side deadline the client cannot extend:**
  `min(auth_timeout, ping_interval × (ping_max + 1))` (D, G). Document it on
  `asyncAuthenticator`.
- **Every `-ERR` the server can send before `CONNECT` is terminal**
  (Authorization Violation, Authentication Timeout, Stale Connection, parser
  errors, TLS-required, max-connections). Assumption behind the control lane and
  abort rule (§6.3); test 9 checks the ones we can provoke.
- The server's `-ERR` is its only explanation (D, G) and must not be lost.

---

## 5. Design overview

```
 transport ──chunk──▶ Parser.parse(buf)          (UNCHANGED, sync)
                        └─ dispatcher.push(e) ──▶ ProtocolHandler.push(e)
                                                    │  if (!connectHold.offer(e)) dispatch(e)
                                                    ▼
                                  HoldQueue.offer(e)
                          no hold open ─────────▶ false   (caller dispatches inline)
                          hold open:
                              isUrgent(e) (ERR) ─▶ abort hold; false     control lane
                              otherwise ─────────▶ queue; true           defer

 processInfo(INFO), credential resolver present (a tagged async member exists):
     hold = connectHold.hold(transport)     ◀── opened synchronously, before any later event
     resolve(nonce).then(creds =>
         if (!hold.current) return            ◀── superseded / aborted / closed
         sendConnect(creds); tail();
         hold.release(dispatch)               ◀── sync replay, in order, no interleaving
     )
```

Invariants:

- **I1 (order).** Held events are replayed FIFO in one synchronous loop; no
  transport callback can interleave, and an event offered _during_ the replay is
  queued behind those still waiting, so order across the release boundary is
  exact.
- **I2 (pre-CONNECT).** The hold is started _inside_ `processInfo(INFO)` before
  it returns, hence before the parser hands over the next event of the same
  chunk. Nothing that follows `INFO` reaches a handler until `CONNECT` is
  written.
- **I3 (currency).** The `Hold` is the attempt token. The continuation acts only
  if `hold.current`; `resetOutbound()`, `close()`, a newer `open()` and the
  control lane all end it.
- **I4 (no rejection).** Both `.then` branches are attached; the returned
  promise is never rejected and never left unhandled.
- **I5 (reads never stop).** The hold does not block the read loop, so the
  transport keeps reading (and observes EOF) during the window.

---

## 6. Detailed design

### 6.1 Public API — one new helper, no new option

```ts
/** Wraps an async credential source so it can be used anywhere an
 *  Authenticator can: alone, in the `authenticator` array, next to `token`. */
export function asyncAuthenticator(
  fn: (nonce?: string) => Promise<Auth>,
): Authenticator;
```

`ConnectionOptions.authenticator?: Authenticator | Authenticator[]`
(`core.ts:879`) is **unchanged**. The helper returns a function `f` that:

- passes `typeof f === "function"` (the check at `options.ts:121-125`), so it
  works alone or inside the array form;
- carries the async function under a module-private symbol (`ASYNC_AUTH`), which
  is how `buildAuthenticator` recognizes it — an explicit tag, **not** runtime
  sniffing for a returned promise, so an existing user who already (wrongly)
  passes an `async` function to `authenticator` sees no behavior change;
- throws an `InvalidArgumentError` if called synchronously, so direct callers
  (e.g. `multiAuthenticator([asyncAuthenticator(…)])` used by hand) get a clear
  error instead of a `Promise` silently spread into `CONNECT`.

Typing the result as `Authenticator` is a deliberate small lie kept for drop-in
composition; the throw-if-called-sync behavior is what keeps it safe (Q3
discusses a branded type instead).

**Nothing else in the public surface changes.** The sync builders
(`nkeyAuthenticator`, `jwtAuthenticator`, `credsAuthenticator`,
`tokenAuthenticator`, `usernamePasswordAuthenticator`, `multiAuthenticator`)
keep their signatures and return types; a "factory" that re-declares each of
them was considered and rejected (§7).

TSDoc semantics for `asyncAuthenticator`: invoked once per connection attempt
(every reconnect and every resolved alternative, `_doDial` → `dial`,
`protocol.ts:609-635`), each call with that attempt's nonce; must settle inside
the §4 deadline; `nonce` may be `undefined`; a `null`/`undefined` result is `{}`
(matches `|| {}` at `protocol.ts:115`).

### 6.1a Credential resolution (`options.ts`)

`buildAuthenticator` keeps its signature and its behavior whenever no member is
tagged. The member list is built in today's order — `authenticator`
function/array elements in array order, then `token`, then `user`/`pass` — and
is merged with today's rule: `Object.assign` in member order, **later wins**
(`multiAuthenticator`, `authenticator.ts:27-36`).

```ts
const members: Array<Authenticator> = [/* same collection code as today */];
if (!members.some(isAsyncMember)) {
  return members.length === 0 ? noAuthFn() : multiAuthenticator(members); // byte-for-byte today (G2)
}
// at least one tagged member:
const resolve: AuthResolver = (nonce) => {
  const parts: Array<Auth | Promise<Auth>> = [];
  try {
    for (const m of members) {
      parts.push(isAsyncMember(m) ? m[ASYNC_AUTH](nonce) : m(nonce));
    }
  } catch (err) { // a sync member threw after an async one started
    parts.forEach((x) => isThenable(x) && x.catch(() => {})); // don't leak its rejection
    throw err;
  }
  return parts.some(isThenable)
    ? Promise.all(parts).then(mergeInOrder) // async members run concurrently
    : mergeInOrder(parts); // e.g. an async member that returned a non-promise
};
```

- `parseOptions` stores `resolve` under a module-private symbol on the parsed
  options (`options[AUTH_RESOLVER]`) and sets `options.authenticator` to a
  function that throws the same `InvalidArgumentError` as above, so the existing
  `typeof … === "function"` validation still passes and a stray synchronous call
  fails loudly. Options with no tagged member get no resolver and behave exactly
  as today.
- `parseOptions` is called once per connection object (`nats.ts:60`) and the
  parsed options are what `ProtocolHandler` receives; verify at implementation
  that no path hands `ProtocolHandler` un-parsed options with a tagged member
  (if one exists, `ProtocolHandler`'s ctor can call the same builder).
- **Merge across sync and async members is order-preserving**, so
  `{ token, authenticator: asyncAuthenticator(f) }` behaves exactly like
  `{ token, authenticator: syncF }` does today: members are the `authenticator`
  function/array elements, **then `token`, then `user`/`pass`**, later wins, so
  on a conflicting field **`token` beats the authenticator**. This is what
  retires the old "both set" question (Q1).
- Async members are started concurrently, not one after another, so several
  async sources cost `max`, not `sum`, of their latencies against the §4
  deadline. Sync members still run inline, in order.

### 6.2 The hold queue module (`core/src/hold_queue.ts`)

A generic, protocol-free component. It decides _what to hold and in what order_;
it never decides what an event means.

```ts
class HoldQueue<T> {
  constructor(isUrgent: (e: T) => boolean = () => false);
  get isHolding(): boolean;
  hold(owner: unknown): Hold<T>; // starts holding; supersedes any active hold
  offer(e: T): boolean; // true: queued, caller must not handle it
  // false: caller handles it now (no hold, or urgent)
  abortFor(owner?: unknown): void; // abort the hold (only if owner matches, when given)
}
interface Hold<T> {
  readonly current: boolean; // false once released, aborted or superseded
  release(deliver: (e: T) => void): void;
  abort(): void;
}
```

Behavior (each point has a unit test in `core/tests/hold_queue_test.ts`, which
needs no socket, server or timer):

- With no hold open, `offer()` is a field read returning `false`.
- With a hold open, events are queued FIFO; an **urgent** event is not queued:
  the hold is aborted, its queued events are dropped, and `offer()` returns
  `false` so the caller handles the urgent event at once.
- `open()` while a hold is open **supersedes** it: the old hold is aborted and
  can no longer release or abort anything.
- `release(deliver)` delivers every queued event synchronously, in order, then
  closes the hold. It is **atomic with respect to ordering**: an event offered
  by `deliver` (or otherwise during the replay) is appended and delivered after
  the ones already waiting, and is not treated as urgent — the handshake is
  finished, so nothing needs to bypass. `abort()` during the replay stops it. If
  `deliver` throws, the undelivered events are dropped, the hold is closed and
  the error propagates.
- `release()` and `abort()` on a hold that is no longer current do nothing, so a
  stale continuation can call them safely.
- `abortFor(owner)` aborts only a hold opened for that owner (the transport), so
  an old transport's close cannot cancel a newer attempt's hold.

### 6.3 Wiring in `ProtocolHandler` (`protocol.ts`)

```ts
// -ERR before CONNECT is always terminal and handling it writes nothing to the
// wire, so it is never held: it is handled at once and abandons the hold
private readonly connectHold = new HoldQueue<ParserEvent>((e) => e.kind === Kind.ERR);

push(e: ParserEvent): void {            // was the big switch; the switch is now dispatch()
  if (!this.connectHold.offer(e)) this.dispatch(e);
}
```

`dispatch(e)` is today's `push` body, unchanged. `resetOutbound()` and `close()`
call `this.connectHold.abortFor()`.

Why handling `ERR` immediately is safe: `processError` only records the error,
dispatches status, and calls `handleAuthError`/`handleError`
(`protocol.ts:789-840`); none of it writes to the transport. The queue's abort
makes the pending authenticator's continuation a no-op (I3), so an authenticator
that resolves a moment later cannot write `CONNECT` into a connection the server
is already tearing down.

**Payload lifetime.** Held events outlive the parser call that produced them.
Inside the window the server sends only `INFO`, `PING`, `-ERR`, `+OK`; the
`INFO`/`ERR` payloads are `arg` slices created per event by the parser, and no
`MSG` can occur before `CONNECT`. So no aliasing hazard exists for held events.
(A design that batched whole chunks in the parser would not have this property:
every event of a chunk would outlive the scan.)

### 6.4 `processInfo` and the handshake

`processInfo` keeps its exact order of effects; only the CONNECT step forks, and
it forks on the resolver's presence, not on a separate option:

```ts
processInfo(m: Uint8Array) {
  const info = JSON.parse(decode(m));
  this.info = info;
  const updates = /* unchanged */;
  if (!this.infoReceived) {
    this.features.update(parseSemVer(info.version));
    this.infoReceived = true;
    if (this.transport.isEncrypted()) this.servers.updateTLSName();
    const resolve = this.options[AUTH_RESOLVER];
    if (resolve) {
      // "update"/"ldm" tail runs after CONNECT is written, as in the sync path
      this.beginAsyncConnect(info, resolve, () => this.infoTail(updates, info));
      return;
    }
    try { this.sendConnect(info); }                       // today's path, byte for byte
    catch (err) { this.close(err as Error).catch(); }
  }
  this.infoTail(updates, info);                           // "update" and "ldm" dispatch, unchanged
}
```

```ts
private beginAsyncConnect(info: ServerInfo, resolve: AuthResolver, tail: () => void): void {
  let r: Auth | Promise<Auth>;
  try { r = resolve(info.nonce); }                        // a sync member may throw
  catch (err) { this.close(err as Error).catch(); return; }   // same as today's ctor-throw path
  if (!isThenable(r)) {                                   // resolver produced no promise: no hold
    try { this.sendConnect(info, r || {}); }
    catch (err) { this.close(err as Error).catch(); return; }
    tail();
    return;
  }
  const transport = this.transport;
  const hold = this.connectHold.hold(transport);                 // I2: before returning to the parser
  r.then(
    (creds) => {
      if (!hold.current || transport.isClosed) { hold.abort(); return; }
      try { this.sendConnect(info, creds || {}); }
      catch (err) { hold.abort(); this.close(err as Error).catch(); return; }
      tail();                                             // status dispatch only: never feeds the parser
      hold.release((e) => this.dispatch(e));              // I1: sync, FIFO
    },
    (err) => {                                            // I4: never rejects
      if (!hold.current) return;
      hold.abort();
      this.close(err as Error).catch();                   // G5
    },
  );
}
```

`sendConnect(info, creds?)` builds `Connect`, sets `headers`/`no_responders`
when `info.headers`, and writes `CONNECT …\r\n` then `PING`. **`Connect` gains
an optional fourth constructor parameter, `creds?: Auth`:** when given, the
constructor `extend`s it in _instead of_ calling `opts.authenticator`
(`protocol.ts:112-117`); when omitted it behaves exactly as today. This keeps
`Connect`'s existing direct callers — `core/tests/properties_test.ts` constructs
it five times with `opts.authenticator` — working unmodified, and keeps the
class usable from `@nats-io/nats-core/internal`.

**Ordering walkthrough** (server sends `INFO`, `PING` in one chunk; the async
member takes 500 ms; server `ping_interval` 200 ms): `parse` → `push(INFO)` →
resolver started, hold started → `push(PING)` → queued → `push(PING)` (second
server ping, later chunk) → queued → 500 ms later: `CONNECT`+`PING` written,
hold released, replay: `PONG`, `PONG` written _after_ `CONNECT` — the H′
sequence, which the server accepts. The server's `PONG` reply to our `CONNECT`
`PING` then resolves the dial promise.

### 6.5 Reconnect, `close()`, teardown

- `resetOutbound()` (`protocol.ts:471`), called from `prepare()` at the start of
  every attempt, gains `this.connectHold.abortFor()`. A stale continuation then
  sees `hold.current === false` and does nothing. There is no suspended parser
  to cancel, because the parser never suspends.
- `close()` (`:1091`) gains `this.connectHold.abortFor()` early.
- The abandoned authenticator promise still settles and both branches are
  attached ⇒ no unhandled rejection.
- The continuation also checks `transport.isClosed`, so a resolve after the
  transport closed (server hung up, socket error) is dropped even before
  `prepare()` has run for the next attempt.

### 6.6 Error fidelity (G6) — what the hold buys

The read loop (`protocol.ts:578-586`) is untouched and keeps pulling during the
window, on **every** transport, including Deno's pull-based one. (A design that
parks the read loop while the authenticator is pending cannot observe a server
`-ERR` or EOF there.) Consequences:

| Situation during the window            | Behavior                                                                                                                                                                  |
| -------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Server `-ERR 'Authentication Timeout'` | control lane → `AuthorizationError` → `handleAuthError` → `connectError` → `connect()` rejects with the server's message; hold aborted; late authenticator result dropped |
| Server `-ERR 'Stale Connection'`       | control lane → `ProtocolError`, recorded as `lastError`, hold aborted; transport close then drives `disconnected(lastError)`                                              |
| Server closes the socket, no `-ERR`    | transport `closed()` → `disconnected()` → `dialLoop` → `prepare()` → `resetOutbound()` aborts the hold                                                                    |
| Authenticator rejects / throws         | `close(err)` → `connect()` rejects with that error (same as a throwing sync authenticator)                                                                                |
| `close()` while pending                | hold aborted; nothing written                                                                                                                                             |
| Reconnect while pending                | `resetOutbound()` aborts; the new attempt calls the authenticator again                                                                                                   |
| Authenticator returns `null`           | treated as `{}`                                                                                                                                                           |
| User publishes during the window       | buffered; `flushPending` is gated on `infoReceived && connected`, and `connected` flips on the first `PONG` (`:1144`, `:594`)                                             |

Known pre-existing limitation, unchanged: if the socket closes with no `-ERR`
and no `connectError`, `dial()` waits for `options.timeout` (default 20 s)
before rejecting. Not introduced or worsened here: reproduced with plain
synchronous `token` credentials against a server that hangs up after `CONNECT`
without replying, where the next attempt starts only after the dial timeout (~20
s). Tests that abandon an attempt this way set a short `timeout` option.

### 6.7 Backpressure and buffering

The read loop is not parked, so frames are consumed as they arrive. `held` is
bounded in practice: before `CONNECT` the server sends `INFO`/`PING` at
`ping_interval` and disconnects within the §4 deadline. A defensive cap (e.g.
1024 held events ⇒ abort with a `ProtocolError`) is proposed in Q3 but is
unnecessary for correctness.

### 6.8 Performance

- Sync users: one `connectHold.offer(e)` call per event, which returns after a
  single field read; no allocation, no promise, no microtask. Acceptance
  criterion: a `MSG`-throughput microbenchmark within ±2 % of base (the call is
  small and monomorphic, so the engine can inline it; measure rather than
  assume).
- Async users: one small `Hold` and array per connection attempt.
- Nothing on the message path is ever awaited (the point of §7).

---

## 7. Alternatives considered (all discounted)

| Alternative                                                                                        | Why discounted                                                                                                                                                                                                                                                                       |
| -------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Always-on actor:** every event enqueued, one long-lived consumer coroutine `await`s each handler | Every `MSG` pays an extra async hop unless a fast path is added, and the fast path _is_ this design (queue only while a hold is active). Also adds a permanently running coroutine to manage across reconnects. §11 Q5 describes when it would become worth reconsidering            |
| Separate `asyncAuthenticator` **option** (as in the reverted commit)                               | Creates a "both set" case (`Connect`'s ctor runs one, the other is merged after) and a second credential path beside the existing normalization                                                                                                                                      |
| Public `AuthenticatorFactory` re-declaring every builder plus an async one                         | The sync builders already return functions the resolver can merge as-is, so parallel factory methods add public surface without adding capability, and changing the builders' return types breaks callers. The _bridging_ half of the idea is adopted, internally, as §6.1a          |
| Widen the exported `Authenticator` return type to `Auth \| Promise<Auth>`                          | Breaks direct callers (`multiAuthenticator`, `authenticator_test.ts`) at compile time                                                                                                                                                                                                |
| Sniff for a returned promise instead of tagging                                                    | Changes behavior for anyone already passing an `async` function to `authenticator`, and makes the sync/async split invisible in types                                                                                                                                                |
| Widen `Dispatcher`/`Authenticator`/`parse` to async everywhere                                     | Async signature on `QueuedIteratorImpl` and every delivery call site; hundreds of `await`s per pipelined chunk                                                                                                                                                                       |
| Batch-then-drain in the parser (parser scans a chunk, then awaits handlers in order)               | Keeps a single ordered pipeline and needs no control lane, but changes `Parser`, adds a new handler interface, serializes `parse`, needs `Parser.cancel()` for reconnect, and cannot observe server `-ERR`/EOF on Deno during the window (§6.6). Larger diff for less error fidelity |
| Reverted fire-and-forget + drop                                                                    | Drops early `PING`s (fatal after `CONNECT`, §4 H) and `-ERR` frames                                                                                                                                                                                                                  |
| `node:events` / `EventTarget` as the queue                                                         | Dispatch is synchronous, so it does not defer anything by itself; `node:events` is unavailable in browsers, a target runtime here                                                                                                                                                    |

---

## 8. Test plan

**Hold queue unit tests (`core/tests/hold_queue_test.ts`, no server, socket or
timer; 15 tests):** pass-through with no hold; FIFO release; nothing held after
release; urgent event bypasses, aborts and drops the queue; default predicate
treats nothing as urgent; abort; a newer `open()` supersedes (and the old hold's
`release`/`abort` are inert); `abortFor` honours the owner and is a no-op when
nothing is active; events offered during the replay are delivered in order,
urgent or not; `abort()` during the replay stops it; a throwing `deliver` drops
the rest, closes the hold and propagates; `release` delivers once; the queue is
reusable.

**Unit / protocol (no server needed, fake transport):**

1. With no tagged async member, `processInfo` writes `CONNECT`+`PING`
   synchronously inside `push(INFO)` — identical byte sequence and call order to
   base (guard for G2).
2. Async authenticator: `push(INFO)`, `push(PING)` ⇒ no `PONG` written; after
   resolve ⇒ order on the wire is `CONNECT`, `PING`, `PONG`.
3. Two chunks worth of events inside the window replay in arrival order.
4. Authenticator resolves after the hold was aborted (reconnect / `close()` /
   `-ERR`) ⇒ nothing written, no unhandled rejection.
5. `-ERR` in the window is handled immediately (asserted via `dispatchStatus`)
   and aborts the hold.
6. Authenticator throws synchronously / rejects ⇒ `close(err)`. 6a. **Options
   with no tagged member are unchanged:** `parseOptions` yields the same
   `options.authenticator` behavior as base and **no** `AUTH_RESOLVER`;
   `properties_test.ts` passes unmodified (`Connect` ctor path). 6b.
   `asyncAuthenticator(fn)` called synchronously throws `InvalidArgumentError`;
   it passes the `typeof === "function"` validation and is accepted inside the
   `authenticator` array. 6c. **Merge order:**
   `{ token: "t", authenticator: asyncAuthenticator(async () => ({ auth_token: "a" })) }`
   resolves `auth_token: "t"` (`token` is merged after the authenticator,
   exactly as on the sync path); swapped array positions swap the winner; sync
   and async members interleaved in an array merge in array order. 6d. Two async
   members run concurrently (total latency ≈ max, not sum); if one rejects,
   `connect()` rejects with that error and the other's rejection is not reported
   as unhandled. 6e. A sync member throwing after an async member started ⇒
   `close(err)` and no unhandled rejection from the started member. 6f. An async
   member that returns a non-promise ⇒ treated as sync, no hold started,
   `CONNECT` written inline.

**Integration — `authenticator_test.ts`** (Deno + real `nats-server`):

7. `authenticator: asyncAuthenticator(fn)` with a delay connects and `flush()`
   works.
8. **Early-`PING` regression (the reason for the design).**
   `ping_interval: 400ms`, `ping_max: 2`, authenticator delay 1000 ms. Client
   stays connected for ≥ 1.5 s afterwards. **Timing constraint:** the window
   must span `ping_max` server pings (400 ms, 800 ms) yet end before the
   server's own deadline `ping_interval × (ping_max + 1)` (1200 ms). Windows
   shorter than `ping_max` intervals pass even if early pings are dropped
   (checked: 300–400 ms at a 200 ms interval did not discriminate), and a
   `ping_interval` much shorter than the delay (the first draft used 50 ms with
   500 ms) makes the server close the connection before `CONNECT`. With these
   parameters the test fails when early pings are dropped (row H) and passes
   with the hold queue (row H′).
9. **Error fidelity.** Server `authorization.timeout: 1`, authenticator delay 3
   s: `connect()` rejects with an `AuthorizationError` whose message includes
   the server text, on Deno **and** Node, well before the authenticator
   resolves.
10. Reconnect during a pending authenticator (server restart mid-delay): the new
    attempt succeeds; no `Authorization Violation` observed.
11. `close()` during the window: no `CONNECT` written, no unhandled rejection.
12. Row F: authenticator slower than the server timeout ⇒ fails promptly with
    the server message rather than at `options.timeout`.

**Regression:** `deno task test-core`, `test-jetstream`, `test-kv`; the
`transport-node` suite; `deno fmt --check`; `deno lint`. Commits with
`git commit -s`.

---

## 9. Delivery plan

| Commit | Content                                                                                                                                                        | Behavior change                                                                              |
| ------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| 1      | Test 8 written against the reverted approach to prove row H (optional, PR description evidence)                                                                | none                                                                                         |
| 2      | `HoldQueue` module + its unit tests; `dispatch` extraction, `connectHold` field, `push` → `offer`, `abortFor` in `resetOutbound`/`close`                       | **none** (no hold ever opens)                                                                |
| 3      | `asyncAuthenticator()` helper + `ASYNC_AUTH` tag, `buildAuthenticator` partition/resolver, `AUTH_RESOLVER` slot, `Connect` optional `creds` param; tests 6a–6f | none until a tagged member is used; helper is exported but nothing consumes the resolver yet |
| 4      | `sendConnect`, `beginAsyncConnect`, forked `processInfo`, exports (`mod.ts`/`internal_mod.ts`), TSDoc; tests 2, 3, 6, 7, 9–12                                  | new opt-in API goes live                                                                     |
| 5      | docs (deadline formula §4, README/`migration.md` note), optional `ASYNC-AUTHENTICATOR-SCOPE.md` update                                                         | docs                                                                                         |

Measured size of the implementation: `hold_queue.ts` +154 (new, mostly docs),
`protocol.ts` +128/−20, `authenticator.ts` +119 (mostly docs), `options.ts`
+35/−1, `mod.ts` and `internal_mod.ts` +1 each; tests +896 (hold queue unit
tests 247, async tests 649). `parser.ts` and `queued_iterator.ts`: 0.

---

## 10. Compatibility

- **Public API:** additive only — one exported function, `asyncAuthenticator`;
  no new option and no changed types. **This differs from the reverted commit**,
  which added `ConnectionOptions.asyncAuthenticator`; the browser DPoP flow in
  `nats-nkey-demo-priv` (returns `{ jwt, nkey, sig, auth_token }`) changes from
  `asyncAuthenticator: fn` to `authenticator: asyncAuthenticator(fn)`.
- **Internal API** (`@nats-io/nats-core/internal`): `Connect` gains one optional
  trailing constructor parameter; `ProtocolHandler.push` keeps its signature and
  meaning; `Parser` is not touched, so `core/tests/parser_test.ts` and
  `headers_test.ts` need no change.
- **Sync users:** identical observable behavior and timing (G2), enforced by
  test 1.

---

## 11. Open questions / decisions needed

- **Q1. Merge semantics — resolved by design.** Sync and async members merge
  with today's `multiAuthenticator` rule (member order, later wins; §6.1a).
  Remaining sub-question: keep the existing member order (`authenticator`, then
  `token`, then `user`/`pass`), which is what the proposal does.
- **Q2. Cancellation.** Pass `{ signal }` as a second argument to the wrapped
  function so an abandoned attempt (aborted hold) can cancel its I/O. Additive.
- **Q3. How the tag is expressed.** (a) proposed: `asyncAuthenticator(fn)`
  returns an `Authenticator`-typed function carrying a symbol, throwing when
  called synchronously; (b) return a branded `AsyncAuthenticator` type and widen
  `authenticator` to `Authenticator | AsyncAuthenticator | (…)[]` — honest
  typing, one more exported type, and `Connect`-style direct users of the option
  see a wider type. Also: exact helper name.
- **Q4. Failure during a _reconnect_.** `close()` is terminal, so a transient
  authenticator failure permanently closes the client — same as a throwing sync
  authenticator. Treating it as a failed dial attempt would suit I/O-bound
  authenticators better but diverges from sync semantics; propose as a later
  opt-in.
- **Q5. Generalising the hold.** `beginAsyncConnect` is the only user today. If
  a second async handshake step appears (e.g. async TLS-name lookup),
  `HoldQueue` is generic and can be reused as is (one hold at a time); if async
  handling of _steady-state_ events ever appears, that is the point at which the
  always-on actor (§7) is worth its hot-path cost.
- **Q6. Resolution concurrency.** Async members start concurrently (§6.1a).
  Alternative: sequential, which is simpler to reason about but sums the
  latencies against the §4 deadline.
- **Q7. Confirm the server default `auth_timeout`** (2 s per the earlier scope
  doc); the probes configured it explicitly.
- **Q8. Assumption check:** "every pre-`CONNECT` `-ERR` is terminal" (§4) was
  verified for the errors provokable with a raw socket, not from server source.
  Confirm against `nats-server`'s `client.go` if a maintainer knows of a
  counter-example; if one exists, the control lane should abort only on the
  terminal set.

---

## Appendix — reproducing §4

Configs (rows A–F / rows G, H, H′):

```
port: 14222                       port: 14223
authorization {                   authorization { token: "s3cret"  timeout: 10 }
  token: "s3cret"                 ping_interval: "200ms"
  timeout: 2                      ping_max: 2
}
ping_interval: "1s"
ping_max: 10
```

Each row is a raw `socket.create_connection`: read `INFO`, perform the listed
action, print what arrives for a fixed window. Rows B/C send `PONG\r\n` /
`PING\r\n`; row E sends
`CONNECT {"auth_token":"s3cret","protocol":1,…}\r\nPING\r\n` after 1.3 s then
`PONG\r\n`; row H waits 0.35 s, sends `CONNECT`+`PING`, and answers only `PING`s
that arrive afterwards; H′ additionally sends one `PONG` per early `PING`
immediately after `CONNECT`.

---

## 12. Implementation notes (what building it changed)

Implemented in `core/src/hold_queue.ts` (new), `authenticator.ts`, `options.ts`,
`protocol.ts`, `mod.ts`/`internal_mod.ts`; tests in
`core/tests/hold_queue_test.ts` and `core/tests/async_authenticator_test.ts`.

- **Merge-order example corrected** (§6.1a, test 6c): `token` wins over an
  `authenticator` on conflict, matching the existing sync behavior; the first
  draft had it backwards.
- **Test 8 parameters corrected** (see test 8): the draft's `ping_interval` 50
  ms / delay 500 ms could never connect; the first re-tuned attempt (200 ms
  interval, 300–400 ms delay) passed even against a build that drops early
  pings. Found by mutation testing the hold queue.
- **`Connect`'s `creds` parameter** distinguishes "not given" (`undefined`) from
  "given but empty": `sendConnect` passes `creds || {}`, so an authenticator
  that returns nothing never falls back to calling the parsed options' throwing
  `authenticator`.
- **Mutation checks run** (each fails the tests named): dropping held events
  fails the wire-order test (scripted server) and the real-server
  stays-connected test; answering held events immediately fails six tests;
  removing the control lane fails both `-ERR` tests.
- **Pre-existing failures on the untouched base**, unrelated to this change:
  `basics - resolve` (needs public DNS for `demo.nats.io`) and
  `jscluster_test: jsm - stream update properties` (needs a clustered server).
- **Not verified:** the npm/CJS build (`core` → `tsc`, no `node_modules` in this
  checkout) and the `transport-node` suite.
- **Hold queue extracted into its own module** after the first implementation
  kept the buffering inline in `ProtocolHandler` (a `gate` field, a branch in
  `push`, an `abortGate` method, a replay loop). Behavior is unchanged and the
  24 integration tests passed untouched. What changed:
  - The queueing policy is now testable without I/O (15 unit tests).
  - The attempt token is the `Hold` handle instead of a bare object compared by
    identity; `hold()` supersedes a previous hold instead of relying on callers
    to abort it first.
  - **Replay is now drain-until-empty.** The inline version cleared the gate and
    then iterated the array, so an event pushed during the replay would have
    gone straight through and overtaken the ones still waiting. Nothing can
    trigger that today (`dispatch` never feeds the parser synchronously), but
    the module no longer depends on it, and it has a test. It is a robustness
    fix, not a behavior change any existing flow can observe.
  - **Ordering of `tail()`:** the inline version cleared the gate, then ran the
    `update`/`ldm` status dispatch, then replayed. Now `tail()` runs while the
    hold is still active and `release()` follows. Equivalent, because `tail()`
    only dispatches status to listeners and never offers an event to the queue.
  - **What the module cannot check** is that the hold is started before
    `processInfo` returns (I2). That stays a wiring property, covered by the
    scripted-server wire-order test; a mutation that starts the hold a microtask
    late fails seven integration tests.
- **Naming.** The module was first called `HandshakeGate` with `open()` /
  `isOpen`. That was misleading twice over: the module is generic (nothing in it
  is about handshakes), and a gate that is "open" lets events through, whereas
  `open()` started blocking them. It is now `HoldQueue` with `hold()` /
  `isHolding`, and the field in `ProtocolHandler` is `connectHold`.
- **Mutation checks against the extracted design:** dropping queued events,
  never holding, ignoring the owner in `abortFor`, replaying in reverse, holding
  `-ERR` too, and opening the hold late were each caught (11, 15, 1, 5, 2 and 7
  failing tests respectively).
