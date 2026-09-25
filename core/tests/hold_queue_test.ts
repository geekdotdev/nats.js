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

import { assertEquals, assertThrows } from "@std/assert";
import { HoldQueue } from "../src/hold_queue.ts";

// events are strings; "!" prefixed ones are urgent
const urgent = (e: string) => e.startsWith("!");

function collect(): { out: string[]; deliver: (e: string) => void } {
  const out: string[] = [];
  return { out, deliver: (e) => out.push(e) };
}

Deno.test("hold queue - with no hold, offer passes everything through", () => {
  const g = new HoldQueue<string>(urgent);
  assertEquals(g.isHolding, false);
  assertEquals(g.offer("a"), false);
  assertEquals(g.offer("!e"), false);
  assertEquals(g.isHolding, false);
});

Deno.test("hold queue - holds events and releases them in order", () => {
  const g = new HoldQueue<string>(urgent);
  const h = g.hold("t1");
  assertEquals(g.isHolding, true);
  assertEquals(h.current, true);

  assertEquals(g.offer("ping1"), true);
  assertEquals(g.offer("ping2"), true);
  assertEquals(g.offer("info"), true);

  const { out, deliver } = collect();
  h.release(deliver);
  assertEquals(out, ["ping1", "ping2", "info"]);
  assertEquals(h.current, false);
  assertEquals(g.isHolding, false);
});

Deno.test("hold queue - events offered after release pass through", () => {
  const g = new HoldQueue<string>(urgent);
  const h = g.hold("t1");
  g.offer("a");
  h.release(() => {});
  assertEquals(g.offer("b"), false);
});

Deno.test("hold queue - an urgent event is not held, aborts the hold and drops what was queued", () => {
  const g = new HoldQueue<string>(urgent);
  const h = g.hold("t1");
  g.offer("ping");
  assertEquals(g.offer("!err"), false); // caller handles it now
  assertEquals(h.current, false);
  assertEquals(g.isHolding, false);

  const { out, deliver } = collect();
  h.release(deliver); // aborted: nothing to replay
  assertEquals(out, []);
  // and the queue is back to pass-through
  assertEquals(g.offer("later"), false);
});

Deno.test("hold queue - the default predicate treats nothing as urgent", () => {
  const g = new HoldQueue<string>();
  const h = g.hold("t1");
  assertEquals(g.offer("!e"), true);
  const { out, deliver } = collect();
  h.release(deliver);
  assertEquals(out, ["!e"]);
});

Deno.test("hold queue - abort drops held events and closes the hold", () => {
  const g = new HoldQueue<string>(urgent);
  const h = g.hold("t1");
  g.offer("a");
  h.abort();
  assertEquals(h.current, false);
  assertEquals(g.isHolding, false);
  assertEquals(g.offer("b"), false);
  const { out, deliver } = collect();
  h.release(deliver);
  assertEquals(out, []);
  h.abort(); // idempotent
});

Deno.test("hold queue - opening a hold supersedes the previous one", () => {
  const g = new HoldQueue<string>(urgent);
  const old = g.hold("t1");
  g.offer("old-1");
  const cur = g.hold("t2");
  assertEquals(old.current, false);
  assertEquals(cur.current, true);

  g.offer("new-1");
  // the superseded hold can no longer deliver, and its events are gone
  const stale = collect();
  old.release(stale.deliver);
  assertEquals(stale.out, []);
  old.abort(); // must not close the newer hold
  assertEquals(cur.current, true);
  assertEquals(g.isHolding, true);

  const { out, deliver } = collect();
  cur.release(deliver);
  assertEquals(out, ["new-1"]);
});

Deno.test("hold queue - abortFor only aborts a hold owned by that owner", () => {
  const g = new HoldQueue<string>(urgent);
  const t1 = { name: "t1" };
  const t2 = { name: "t2" };
  const h = g.hold(t2);
  g.offer("a");

  g.abortFor(t1); // someone else's transport closing: leave it
  assertEquals(h.current, true);
  assertEquals(g.isHolding, true);

  g.abortFor(t2);
  assertEquals(h.current, false);
  assertEquals(g.isHolding, false);
});

Deno.test("hold queue - abortFor with no owner aborts any hold; no-op when none", () => {
  const g = new HoldQueue<string>(urgent);
  g.abortFor(); // nothing open: no throw
  const h = g.hold("t1");
  g.abortFor();
  assertEquals(h.current, false);
  assertEquals(g.isHolding, false);
});

Deno.test("hold queue - events offered during release are delivered after the ones still waiting", () => {
  const g = new HoldQueue<string>(urgent);
  const h = g.hold("t1");
  g.offer("a");
  g.offer("b");

  const out: string[] = [];
  h.release((e) => {
    out.push(e);
    if (e === "a") {
      // a delivery that feeds the queue again must not overtake "b"
      assertEquals(g.offer("c"), true);
    }
  });
  assertEquals(out, ["a", "b", "c"]);
  assertEquals(g.isHolding, false);
});

Deno.test("hold queue - an urgent event during release is queued in order, not bypassed", () => {
  const g = new HoldQueue<string>(urgent);
  const h = g.hold("t1");
  g.offer("a");
  g.offer("b");

  const out: string[] = [];
  h.release((e) => {
    out.push(e);
    if (e === "a") {
      assertEquals(g.offer("!late"), true);
    }
  });
  assertEquals(out, ["a", "b", "!late"]);
});

Deno.test("hold queue - aborting during release stops the replay", () => {
  const g = new HoldQueue<string>(urgent);
  const h = g.hold("t1");
  g.offer("a");
  g.offer("b");
  g.offer("c");

  const out: string[] = [];
  h.release((e) => {
    out.push(e);
    if (e === "a") {
      h.abort();
    }
  });
  assertEquals(out, ["a"]);
  assertEquals(g.isHolding, false);
});

Deno.test("hold queue - a throwing deliver drops the rest, closes the hold and propagates", () => {
  const g = new HoldQueue<string>(urgent);
  const h = g.hold("t1");
  g.offer("a");
  g.offer("b");
  g.offer("c");

  const out: string[] = [];
  assertThrows(
    () =>
      h.release((e) => {
        out.push(e);
        if (e === "b") {
          throw new Error("boom");
        }
      }),
    Error,
    "boom",
  );
  assertEquals(out, ["a", "b"]);
  assertEquals(g.isHolding, false);
  assertEquals(g.offer("d"), false);
});

Deno.test("hold queue - release delivers only once", () => {
  const g = new HoldQueue<string>(urgent);
  const h = g.hold("t1");
  g.offer("a");
  const { out, deliver } = collect();
  h.release(deliver);
  h.release(deliver);
  assertEquals(out, ["a"]);
});

Deno.test("hold queue - the queue is reusable after a release and after an abort", () => {
  const g = new HoldQueue<string>(urgent);

  const h1 = g.hold("t1");
  g.offer("a");
  h1.release(() => {});

  const h2 = g.hold("t2");
  g.offer("b");
  h2.abort();

  const h3 = g.hold("t3");
  g.offer("c");
  const { out, deliver } = collect();
  h3.release(deliver);
  assertEquals(out, ["c"]);
});
