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

/**
 * A handle on one active hold of a {@link HoldQueue}. While it is
 * {@link Hold.current} the queue holds the events it is offered; the owner
 * of the hold then either {@link Hold.release}s them, in order, or
 * {@link Hold.abort}s and drops them.
 */
export interface Hold<T> {
  /** True until the hold is released, aborted, or superseded by a newer one. */
  readonly current: boolean;
  /**
   * Delivers every held event to `deliver`, in the order they were offered,
   * synchronously, then closes the hold. Events offered to the queue while
   * this runs are appended and delivered too, so nothing can overtake an
   * event that is still waiting. Does nothing if the hold is not current.
   * If `deliver` throws, the events not yet delivered are dropped and the
   * error propagates.
   */
  release(deliver: (e: T) => void): void;
  /** Drops the held events and closes the hold. No-op if not current. */
  abort(): void;
}

type State = "holding" | "releasing" | "done";

/**
 * Holds events back while something asynchronous completes, then replays
 * them in order. Knows nothing about what the events are: whether an event
 * may bypass the queue is decided by the `isUrgent` predicate given at
 * construction.
 *
 * At most one hold is active at a time. With no hold active, {@link offer} is a
 * single field read, so a queue that is never used costs almost nothing.
 */
export class HoldQueue<T> {
  private active?: HoldImpl<T>;
  private readonly isUrgent: (e: T) => boolean;

  /**
   * @param isUrgent - events for which this returns true are never held: the
   * hold is aborted and {@link offer} returns false, so the caller handles
   * the event immediately.
   */
  constructor(isUrgent: (e: T) => boolean = () => false) {
    this.isUrgent = isUrgent;
  }

  /** True while a hold exists (holding, or replaying its events). */
  get isHolding(): boolean {
    return this.active !== undefined;
  }

  /**
   * Starts holding events on behalf of `owner`. A hold that is already active
   * is superseded: it is aborted and its events dropped.
   */
  hold(owner: unknown): Hold<T> {
    this.active?.abort();
    const h: HoldImpl<T> = new HoldImpl<T>(owner, () => {
      if (this.active === h) {
        this.active = undefined;
      }
    });
    this.active = h;
    return h;
  }

  /**
   * Offers an event to the queue. Returns true if it was queued: the caller
   * must not handle it. Returns false if the caller must handle it now,
   * because no hold is active or because the event is urgent (in which case the
   * active hold has been aborted and its events dropped).
   */
  offer(e: T): boolean {
    const h = this.active;
    if (h === undefined) {
      return false;
    }
    if (h.state === "holding" && this.isUrgent(e)) {
      h.abort();
      return false;
    }
    // "releasing": the hold is being replayed; queue behind what is left so
    // order is preserved, urgent or not
    h.held.push(e);
    return true;
  }

  /**
   * Aborts the active hold. With `owner`, only if the hold belongs to it, so a
   * newer owner's hold is left alone. No-op if no hold is active.
   */
  abortFor(owner?: unknown): void {
    const h = this.active;
    if (h !== undefined && (owner === undefined || h.owner === owner)) {
      h.abort();
    }
  }
}

class HoldImpl<T> implements Hold<T> {
  readonly held: T[] = [];
  state: State = "holding";

  constructor(
    readonly owner: unknown,
    private readonly onDone: () => void,
  ) {}

  get current(): boolean {
    return this.state === "holding";
  }

  release(deliver: (e: T) => void): void {
    if (this.state !== "holding") {
      return;
    }
    this.state = "releasing";
    try {
      // index loop: events offered by deliver() land at the end and are seen
      for (let i = 0; i < this.held.length; i++) {
        deliver(this.held[i]);
      }
    } finally {
      this.held.length = 0;
      this.state = "done";
      this.onDone();
    }
  }

  abort(): void {
    if (this.state === "done") {
      return;
    }
    // aborting while releasing stops the replay: the loop sees an empty queue
    this.held.length = 0;
    this.state = "done";
    this.onDone();
  }
}
