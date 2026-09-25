# Fail a dial promptly when the socket closes before the handshake completes

**Status:** proposal · **Independent of** `ASYNC-AUTHENTICATOR-DESIGN.md` (it
works with or without it; §5 says how the two interact) · **Base:**
`3a7b736b175d9a387130210c88f851d71e1b014f`. Line numbers refer to the current
working tree (`core/src/protocol.ts`), which already contains the async
authenticator change; function names are the stable anchors.

Claims marked _measured_ were reproduced against the unmodified dial code with a
scripted TCP server (method in the appendix).

---

## 1. Summary

With the default `reconnect: true`, if the server closes the socket after `INFO`
but before answering our `CONNECT`, the client does not notice for
**`options.timeout` (default 20 s)**. `connect()` then rejects with a generic
`TimeoutError`, and a mid-life reconnect loop is stalled for the same time. The
socket-close event does fire; nothing that is waiting listens to it.

This change makes the pending dial fail as soon as **its own** transport closes,
with the error the client already computes for that situation, and also drops
any pending async-authenticator hold for that transport (§4.2).

1. **Reject the pending dial on transport close** — one guarded call in the
   existing close handler in `prepare()`.
2. **Abort the connect hold eagerly** — one guarded call in the same handler.

No new options, no public API, no transport changes, no protocol changes.

---

## 2. Problem, in code

`dial()` (`protocol.ts:593`) waits for the server's reply to `CONNECT`:

```ts
await Promise.race([this.raceTimer, pong]); // :613  raceTimer = options.timeout (20 s)
```

`pong` is settled only by (a) the server's `PONG` (`processPong`), or (b)
`connectError(err)` — `pong.reject` — which is called from `handleAuthError`,
from `close()`, and from nowhere else. When the socket dies, the handler
registered in `prepare()` runs:

```ts
this.transport.closed().then(async (_err?) => { // :531
  this.connected = false;
  if (!this.isClosed()) {
    await this.disconnected(this.transport.closeError || this.lastError); // :537
  }
});
```

`disconnected()` (`:560`) does one of two things:

| `reconnect`      | What `disconnected()` does                                                      | Effect on the pending dial                                                                                                                                                                                                                                   |
| ---------------- | ------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `false`          | `await this.close(err)`, and `close()` calls `connectError(err)` (`:1232-1234`) | pong rejected **immediately**                                                                                                                                                                                                                                |
| `true` (default) | `await this.dialLoop()`                                                         | **nothing**: `dialLoop()` is single-flight (`:658-659`, `connectPromise !== null`) and the running loop is the one parked inside `dial()`. `resetOutbound()`, which would reject old pongs, only runs when the _next_ `prepare()` runs, i.e. after the timer |

_Measured_ (server hangs up 100 ms after `INFO`+`PING`, never answering
`CONNECT`, sync `token` credentials):

```
reconnect:false  rejected after   108ms with ConnectionError "connection refused"
reconnect:true   rejected after 20003ms with TimeoutError    "timeout"
```

Mid-life, the same server behavior (a reconnect attempt that is hung up on)
delays the next attempt by the full timeout (_measured_: attempts arrived at 9
ms, 30 ms, **20032 ms**).

Why it matters more with an async authenticator: the pre-`CONNECT` window is now
as long as the authenticator, so a server that gives up during it (auth timeout,
stale connection) is a realistic case rather than a race. The server's `-ERR` is
reported promptly by the hold queue's control lane
(`ASYNC-AUTHENTICATOR-DESIGN.md` §6.3), but a hang-up _without_ a preceding
`-ERR` is not.

---

## 3. Goals and non-goals

**Goals**

- G1. A pending dial fails as soon as the transport it is using closes.
- G2. The error is the one the client already derives for the same event when
  `reconnect: false` (parity), or a more specific one already recorded (§4.3).
- G3. Only the attempt that owns the transport is affected; a stale or later
  attempt is never rejected by an earlier transport's close.
- G4. No effect on a connection that has completed its handshake.
- G5. After a transport closes, no hold is left holding events for it.

**Non-goals**

- Changing `options.timeout` semantics or default (it still bounds a server that
  stays connected but silent).
- Changing reconnect/backoff policy (`reconnectTimeWait`, jitter, attempts).
- Cancelling an in-flight async authenticator (the `AbortSignal` idea, Q2 of the
  authenticator design).
- Fixing the late-bound `this.transport` in the close handler (§4.4).

---

## 4. Design

### 4.1 Reject the pending dial on transport close

Give each attempt an identity, and let its own transport's close settle it:

```ts
private prepare(): Deferred<void> {
  ...
  const pong = deferred<void>();
  pong.catch(() => {});
  this.pongs.unshift(pong);

  const connectError = (err?: Error) => {          // was an inline arrow
    pong.reject(err);
  };
  this.connectError = connectError;

  const t = newTransport();                        // was: this.transport = newTransport();
  this.transport = t;
  t.closed().then(async (_err?) => {
    this.connected = false;
    // NEW: this attempt's dial is still waiting for CONNECT to be answered
    if (this.connectError === connectError) {
      connectError(t.closeError || this.lastError);
    }
    // NEW (§4.2): only a hold opened for this transport
    this.connectHold.abortFor(t);
    if (!this.isClosed()) {
      await this.disconnected(this.transport.closeError || this.lastError);   // unchanged
      return;
    }
  });
  return pong;
}
```

Why the identity test is sufficient (G3, G4):

- `this.connectError` is replaced by every `prepare()` and set to `undefined` by
  `dial()` on success (`:616`) and by `close()` (`:1234`). So
  `this.connectError === connectError` is true **only** while this attempt's
  dial is still waiting on its own `pong`.
- After a successful handshake the value is `undefined`, so a later close falls
  through to today's `disconnected()` path untouched.
- After a newer `prepare()`, the value belongs to the newer attempt, so an old
  transport's late close cannot reject it.
- If the pong already settled (server replied, or timeout fired) but `dial()`
  has not yet cleared `connectError`, `pong.reject` on a settled deferred is a
  no-op.

Order of effects is deliberate: reject first, then continue into
`disconnected()` exactly as before, so status events (`disconnect`), the
`dialLoop()` call and `close()` for `reconnect: false` are unchanged. With
`reconnect: false`, `close(err)` then calls `connectError` a second time: a
second `reject` on the same deferred is ignored.

`dial()`'s existing `catch` then runs: it cancels the timer, calls
`transport.close(err)` and rethrows, and `dodialLoop` proceeds to the next
address / backoff exactly as it does for any other failed dial.

### 4.2 Abort the connect hold eagerly

The buffering is its own module (`HoldQueue`, `core/src/hold_queue.ts`; see
`ASYNC-AUTHENTICATOR-DESIGN.md` §6.2), and the hold was opened for the attempt's
transport (`connectHold.hold(transport)`). The close handler calls
`this.connectHold.abortFor(t)`, which aborts the active hold only if it belongs
to `t`, so a stale transport closing cannot cancel a newer attempt's hold. This
is low-value but cheap, and it makes the invariant _"a hold implies a live
transport"_ true at all times instead of only after the next `prepare()`:

- Without it, between the close and the next attempt (which may be a
  `reconnectTimeWait` away) the hold and its few held events linger, and a
  late-settling authenticator is neutralised only by its own
  `transport.isClosed` check.
- With it, the continuation sees `hold.current === false` and returns; the held
  events are dropped.

It does not cancel the authenticator; its promise still runs to completion and
both `.then` branches remain attached (no unhandled rejection).

### 4.3 The error

The handler already computes `transport.closeError || this.lastError` and passes
it to `disconnected()`; for `reconnect: false` that value reaches the pending
dial through `close(err)`. §4.1 forwards **the same value** for
`reconnect: true`, so the two modes now fail the same way:

| Situation                                                                           | Value forwarded                                                    | Ends up as                                                                                                                     |
| ----------------------------------------------------------------------------------- | ------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------ |
| Server sent `-ERR 'Authorization Violation'`/`'Authentication Timeout'` then closed | already rejected by `handleAuthError` first; second reject ignored | `AuthorizationError` (unchanged)                                                                                               |
| Server sent another `-ERR` (e.g. `'Stale Connection'`) then closed                  | `lastError` = the `ProtocolError`                                  | that error — previously hidden behind a 20 s `TimeoutError`                                                                    |
| Transport reported an error (reset, TLS)                                            | `transport.closeError`                                             | that error                                                                                                                     |
| Plain hang-up, nothing recorded                                                     | `undefined`                                                        | `ConnectionError("connection refused")`, from `dodialLoop`'s fallback when it has no error — _measured_ for `reconnect: false` |

The last row is a wart (a hang-up is not a refusal) but is today's message for
`reconnect: false`; changing it would be a separate, visible change (Q1).

### 4.4 Deliberately not touched

The handler reads `this.transport.closeError` (late-bound) and sets
`this.connected = false` unconditionally. If a _stale_ transport's `closed()`
resolves after a newer `prepare()`, both refer to the newer transport. In
practice stale transports are silenced (Node's `discard()` removes listeners and
never resolves; Deno's non-internal `close(err)` does not notify), so this is
latent, not exercised. The new lines use the captured `t` and the `connectError`
identity and are therefore immune; the pre-existing lines are left as they are
to keep this change reviewable. Worth its own issue.

---

## 5. Interaction with the async authenticator change

- **Independent.** The sync path benefits on its own (the _measured_ repro uses
  `token`).
- **Hold.** §4.2 is a no-op unless a hold is active. With the authenticator
  change present, §4.1 turns "server hangs up while the authenticator is
  pending" from a 20 s stall into an immediate, correctly attributed failure.
- **Existing tests.** `core/tests/async_authenticator_test.ts` passes
  `timeout: 500` in the two reconnect tests solely to bound this stall; after
  this change that workaround can be removed and the tests should still pass
  (they then also prove promptness). `ASYNC-AUTHENTICATOR-DESIGN.md` §6.6's
  "known pre-existing limitation" paragraph should be replaced by a pointer
  here.

---

## 6. Behavior changes and compatibility

Public API and types: none. Observable changes, all in the failure path of a
dial whose socket closes before `CONNECT` is answered, with `reconnect: true`:

| Before                                                                             | After                                                                                                                                  |
| ---------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| `connect()` rejects after `options.timeout` (20 s) with `TimeoutError`             | rejects within one event-loop turn of the close, with `ConnectionError` / the recorded server error (same as `reconnect: false` today) |
| Reconnect loop stalls one full timeout per hung-up attempt                         | next attempt after the normal `reconnectTimeWait`                                                                                      |
| `maxReconnectAttempts` (default 10) spans ~10 × (20 s + wait) in this failure mode | spans ~10 × wait: the count is the same, the wall-clock time before giving up is not                                                   |
| Hidden `-ERR` text (non-auth)                                                      | surfaced as the error                                                                                                                  |

The last two are the point of the change but are user-visible: anything that
currently observes `TimeoutError` from `connect()` for a server that hangs up
mid-handshake, or tunes `timeout` to compensate, will see different behavior.
Servers that stay connected but silent are unaffected (the timer still fires).

Risk to check before merging: tests that assert `TimeoutError` (or a long
elapsed time) from a dial against a server that _closes_ the socket. The full
suites (§7) are the detector; none is known from a read of `core/tests`.

---

## 7. Transport semantics (what "closed" means to the handler)

The handler depends on each transport resolving `closed()` for a server-side
hang-up. Checked in source:

| Transport                     | Server hangs up                                                                                                         | Notification                                                                                                                          |
| ----------------------------- | ----------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| Node (`node_transport.ts`)    | socket `close` → `_closed(connError, false)` → resolves `closedNotification` (requires the transport to have connected) | yes                                                                                                                                   |
| Deno (`deno_transport.ts`)    | read loop ends → `_closed(reason)` (internal) → resolves                                                                | yes; client-initiated `close(err)` is _non-internal_ and does not resolve — irrelevant here, as the handler is for server-side closes |
| WebSocket (`ws_transport.ts`) | `onclose` → `_closed` + `_cleanup()` → resolves; `onerror` after connect likewise                                       | yes                                                                                                                                   |

The hold does not stop the read loop (authenticator design I5), so the Deno
transport observes the hang-up during the window.

---

## 8. Alternatives considered (all discounted)

| Alternative                                                              | Why discounted                                                                                                                                                                                                                                                       |
| ------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Add `t.closed()` as a third promise in `dial()`'s race                   | Equivalent effect, but needs a no-op `.catch` to avoid an unhandled rejection after the race ends, and adds a promise per dial. The identity-guarded `connectError` reuses the mechanism `close()` and `handleAuthError` already use                                 |
| Make `dialLoop()` restart when the transport dies                        | It would abandon a `dial()` that is still awaiting; the promise and its cleanup (`transport.close`, timer cancel) would need separate handling. Rejecting the awaited promise lets the existing loop and its bookkeeping (reconnect counts, server pool) do the work |
| Lower the default `timeout`                                              | Fixes the symptom for one scenario, breaks slow-network users, and does nothing for the error attribution                                                                                                                                                            |
| Client-side deadline for the authenticator                               | Different problem (a slow authenticator on a live socket); the server's own deadlines already bound it (`ASYNC-AUTHENTICATOR-DESIGN.md` §4)                                                                                                                          |
| Reject with a new descriptive `ConnectionError` when nothing is recorded | Changes `reconnect: false` vs `true` parity and an existing message; kept as Q1                                                                                                                                                                                      |

---

## 9. Test plan

New file `core/tests/dial_close_test.ts`, using a scripted `node:net` server
(the one in `async_authenticator_test.ts`; extract it to a shared test helper in
the same change). Each asserts elapsed time with generous margins.

1. **Initial connect, `reconnect: true`, hang-up before `CONNECT` is answered**
   → `connect()` rejects in < 2 s (was 20 s), with `ConnectionError`. Variants:
   sync `token`; async authenticator (needs the async change).
2. **Parity:** the same scenario with `reconnect: false` rejects with the same
   error class and message.
3. **Mid-life:** connect, drop the socket, hang up on the second attempt before
   it is answered → the third attempt starts within `reconnectTimeWait` + slack
   (was ≥ `timeout`). No `timeout` override.
4. **`-ERR` then close:** server sends `-ERR 'Stale Connection'` then hangs up →
   `connect()` rejects with a `ProtocolError` containing the server text; with
   `'Authorization Violation'` → `AuthorizationError` (unchanged).
5. **No effect after a successful handshake:** connect, server hangs up → the
   normal `disconnect`/`reconnect` status sequence, no unhandled rejection, no
   double reconnect. (Existing reconnect tests cover the breadth; this pins the
   specific guard.)
6. **Stale transport:** an attempt is superseded, then the old socket closes →
   the new attempt's dial is not rejected (drive with two scripted connections).
7. **Hold:** with the async authenticator pending, hang up →
   `connectHold.isHolding` is `false` immediately (test-only cast to reach the
   private `connectHold` field), the authenticator resolving later writes
   nothing, no unhandled rejection.
8. **Silent server:** accepts, never speaks or closes → still rejected by
   `options.timeout` (set to 300 ms in the test), i.e. the timer is intact.

**Mutation checks** (run, expect the named tests to fail): remove the
`connectError` line → tests 1–4; remove the identity guard so any close rejects
→ test 5 or 6; remove the `connectHold.abortFor(t)` line → test 7.

**Regression:** `deno task test-core`, `test-jetstream`, `test-kv`, `test-obj`,
`test-services`, `test-transport-deno`; `transport-node` suite (WS and Node
transports exercise §7); `deno fmt --check`, `deno lint`. Baseline failures
already known and unrelated: `basics - resolve` (public DNS),
`jscluster_test: jsm - stream update properties` (needs a cluster).

---

## 10. Delivery plan

| Commit | Content                                                                                                           | Behavior change                |
| ------ | ----------------------------------------------------------------------------------------------------------------- | ------------------------------ |
| 1      | Tests 1–3 and 8, expected to **fail** on the base (documents the bug; can be `ignore`d or squashed into commit 2) | none                           |
| 2      | `prepare()` change (§4.1, §4.2), tests 4–7, extract the scripted server helper                                    | the failure-path changes in §6 |
| 3      | Remove the `timeout: 500` workaround in the async authenticator tests; update the two doc references (§5)         | none                           |

Size: `protocol.ts` ≈ +12/−3; tests ≈ +200.

---

## 11. Open questions

- **Q1. Error for a bare hang-up.** Keep
  `ConnectionError("connection
  refused")` for parity (proposed), or introduce
  a distinct message such as "connection closed during handshake" for both
  modes.
- **Q2. Release note.** §6 changes wall-clock behavior of the reconnect budget
  in one failure mode; call it out in the changelog.
- **Q3. Should `connectError` also be invoked by `transport.disconnect()`
  paths** that do not resolve `closed()`? None known; confirm against WS in a
  browser-like runtime.
- **Q4. The late-bound `this.transport` in the handler (§4.4)** deserves its own
  issue.

---

## Appendix — reproducing the measurements

Scripted server (Deno, `node:net`): on each connection write
`INFO {"server_id":"S","version":"2.10.0","headers":true,...}\r\nPING\r\n`, then
`socket.destroy()` 100 ms later, never answering `CONNECT`. Client:
`connect({ port, token: "x", reconnect })`, timing the rejection. For the
mid-life case: a server that answers the first connection normally, then
destroys the first socket, and hangs up on the second connection without
replying; record connection arrival times.
