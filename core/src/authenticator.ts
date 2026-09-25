/*
 * Copyright 2020-2023 The NATS Authors
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
import { nkeys } from "./nkeys.ts";
import { TD, TE } from "./encoders.ts";
import type {
  Auth,
  Authenticator,
  JwtAuth,
  NKeyAuth,
  NoAuth,
  TokenAuth,
  UserPass,
} from "./core.ts";

import { InvalidArgumentError } from "./errors.ts";

/**
 * Marks a function created by {@link asyncAuthenticator}. The value stored
 * under this key is the wrapped asynchronous credential source.
 */
export const ASYNC_AUTH = Symbol("nats.asyncAuth");

/**
 * Key under which the parsed connection options carry the credential
 * resolver, when at least one authenticator is asynchronous. Absent otherwise.
 */
export const AUTH_RESOLVER = Symbol("nats.authResolver");

/**
 * Resolves credentials for one connection attempt. Returns a promise only
 * when at least one member is asynchronous.
 */
export type AuthResolver = (nonce?: string) => Auth | Promise<Auth>;

type AsyncMember = Authenticator & {
  [ASYNC_AUTH]: (nonce?: string) => Promise<Auth>;
};

export function isAsyncMember(a: unknown): a is AsyncMember {
  return typeof a === "function" &&
    typeof (a as AsyncMember)[ASYNC_AUTH] === "function";
}

export function isThenable<T>(v: unknown): v is PromiseLike<T> {
  return v !== null && typeof v === "object" &&
    typeof (v as PromiseLike<T>).then === "function";
}

function asyncCalledSync(): InvalidArgumentError {
  return new InvalidArgumentError(
    "an asyncAuthenticator cannot be called synchronously - " +
      "pass it as the 'authenticator' option to connect()",
  );
}

/**
 * Wraps an asynchronous credential source (for example one that signs the
 * server nonce with a non-extractable WebCrypto key, or fetches a token) so
 * it can be used anywhere an {@link Authenticator} can: on its own, as an
 * element of the `authenticator` array, or alongside `token`, `user` and
 * `pass`. Credentials from all sources are merged in order; later sources
 * win on conflicting fields.
 *
 * The function is invoked once per connection attempt (including every
 * reconnect), with that attempt's nonce. It must settle before the server
 * gives up on the connection: the server closes a connection that has not
 * sent `CONNECT` within its authorization timeout, or after `ping_interval
 * * (ping_max + 1)`, whichever comes first. A `null` or `undefined` result is
 * treated as no credentials.
 *
 * The returned function must not be called directly: doing so throws.
 *
 * @param fn - returns the credentials for the given nonce
 */
export function asyncAuthenticator(
  fn: (nonce?: string) => Promise<Auth>,
): Authenticator {
  if (typeof fn !== "function") {
    throw InvalidArgumentError.format("fn", "must be a function");
  }
  const f = (): Auth => {
    throw asyncCalledSync();
  };
  (f as unknown as AsyncMember)[ASYNC_AUTH] = fn;
  return f;
}

function mergeInOrder(parts: Auth[]): Auth {
  let auth: Partial<NoAuth & TokenAuth & UserPass & NKeyAuth & JwtAuth> = {};
  for (const p of parts) {
    auth = Object.assign(auth, p || {});
  }
  return auth as Auth;
}

/**
 * Builds a resolver over the given members, at least one of which is
 * asynchronous. Sync members run inline, in order; async members are started
 * concurrently. Merge order is member order, later wins - the same rule as
 * {@link multiAuthenticator}.
 */
export function asyncResolver(members: Authenticator[]): AuthResolver {
  return (nonce?: string) => {
    const parts: Array<Auth | Promise<Auth>> = [];
    try {
      for (const m of members) {
        parts.push(isAsyncMember(m) ? m[ASYNC_AUTH](nonce) : m(nonce));
      }
    } catch (err) {
      // a member threw after an async one started: don't leak its rejection
      parts.forEach((x) => {
        if (isThenable(x)) {
          Promise.resolve(x).catch(() => {});
        }
      });
      throw err;
    }
    return parts.some((x) => isThenable(x))
      ? Promise.all(parts).then(mergeInOrder)
      : mergeInOrder(parts as Auth[]);
  };
}

/**
 * The `authenticator` installed on parsed options when a resolver is
 * present: keeps the option a function, but fails loudly if used directly.
 */
export function asyncOnlyAuthenticator(): Authenticator {
  return (): Auth => {
    throw asyncCalledSync();
  };
}

export function multiAuthenticator(authenticators: Authenticator[]) {
  return (nonce?: string): Auth => {
    let auth: Partial<NoAuth & TokenAuth & UserPass & NKeyAuth & JwtAuth> = {};
    authenticators.forEach((a) => {
      const args = a(nonce) || {};
      auth = Object.assign(auth, args);
    });
    return auth as Auth;
  };
}

export function noAuthFn(): Authenticator {
  return (): NoAuth => {
    return;
  };
}

/**
 * Returns a user/pass authenticator for the specified user and optional password
 * @param { string | () => string } user
 * @param {string | () => string } pass
 * @return {UserPass}
 */
export function usernamePasswordAuthenticator(
  user: string | (() => string),
  pass?: string | (() => string),
): Authenticator {
  return (): UserPass => {
    const u = typeof user === "function" ? user() : user;
    const p = typeof pass === "function" ? pass() : pass;
    return { user: u, pass: p };
  };
}

/**
 * Returns a token authenticator for the specified token
 * @param { string | () => string } token
 * @return {TokenAuth}
 */
export function tokenAuthenticator(
  token: string | (() => string),
): Authenticator {
  return (): TokenAuth => {
    const auth_token = typeof token === "function" ? token() : token;
    return { auth_token };
  };
}

/**
 * Returns an Authenticator that returns a NKeyAuth based that uses the
 * specified seed or function returning a seed.
 * @param {Uint8Array | (() => Uint8Array)} seed - the nkey seed
 * @return {NKeyAuth}
 */
export function nkeyAuthenticator(
  seed?: Uint8Array | (() => Uint8Array),
): Authenticator {
  return (nonce?: string): NKeyAuth => {
    const s = typeof seed === "function" ? seed() : seed;
    const kp = s ? nkeys.fromSeed(s) : undefined;
    const nkey = kp ? kp.getPublicKey() : "";
    const challenge = TE.encode(nonce || "");
    const sigBytes = kp !== undefined && nonce ? kp.sign(challenge) : undefined;
    const sig = sigBytes ? nkeys.encode(sigBytes) : "";
    return { nkey, sig };
  };
}

/**
 * Returns an Authenticator function that returns a JwtAuth.
 * If a seed is provided, the public key, and signature are
 * calculated.
 *
 * @param {string | ()=>string} ajwt - the jwt
 * @param {Uint8Array | ()=> Uint8Array } seed - the optional nkey seed
 * @return {Authenticator}
 */
export function jwtAuthenticator(
  ajwt: string | (() => string),
  seed?: Uint8Array | (() => Uint8Array),
): Authenticator {
  return (
    nonce?: string,
  ): JwtAuth => {
    const jwt = typeof ajwt === "function" ? ajwt() : ajwt;
    const fn = nkeyAuthenticator(seed);
    const { nkey, sig } = fn(nonce) as NKeyAuth;
    return { jwt, nkey, sig };
  };
}

/**
 * Returns an Authenticator function that returns a JwtAuth.
 * This is a convenience Authenticator that parses the
 * specified creds and delegates to the jwtAuthenticator.
 * @param {Uint8Array | () => Uint8Array } creds - the contents of a creds file or a function that returns the creds
 * @returns {JwtAuth}
 */
export function credsAuthenticator(
  creds: Uint8Array | (() => Uint8Array),
): Authenticator {
  const fn = typeof creds !== "function" ? () => creds : creds;
  const parse = () => {
    const CREDS =
      /\s*(?:(?:[-]{3,}[^\n]*[-]{3,}\n)(.+)(?:\n\s*[-]{3,}[^\n]*[-]{3,}\n))/ig;
    const s = TD.decode(fn());
    // get the JWT
    let m = CREDS.exec(s);
    if (!m) {
      throw new Error("unable to parse credentials");
    }
    const jwt = m[1].trim();
    // get the nkey
    m = CREDS.exec(s);
    if (!m) {
      throw new Error("unable to parse credentials");
    }
    const seed = TE.encode(m[1].trim());

    return { jwt, seed };
  };

  const jwtFn = () => {
    const { jwt } = parse();
    return jwt;
  };
  const nkeyFn = () => {
    const { seed } = parse();
    return seed;
  };

  return jwtAuthenticator(jwtFn, nkeyFn);
}
