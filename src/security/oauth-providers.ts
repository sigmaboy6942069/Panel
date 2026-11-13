/**
 * OAuth 2.0 / OIDC provider registry for third-party sign-in.
 *
 * One implementation serves every provider so Google, Discord, GitHub and a
 * self-hosted OIDC issuer cannot drift apart in their security behaviour.
 * Everything here is pure: no DB access, no Express, no session. The caller
 * supplies stored config and handles the user-record side.
 *
 * Security rules encoded here:
 *  - `state` is 32 random bytes, compared in constant time.
 *  - PKCE (S256) is used whenever the provider supports it.
 *  - The profile is only trusted after the token endpoint returned 2xx.
 *  - Email is only trusted when the provider marks it verified.
 */

import crypto from 'crypto';

export type OAuthProviderId = 'google' | 'discord' | 'github';

export interface OAuthProviderDefinition {
  id: OAuthProviderId;
  label: string;
  /** Where the user is sent to approve the request. */
  authorizeUrl: string;
  /** Where we exchange the code for a token. */
  tokenUrl: string;
  scopes: string[];
  /** Providers that require PKCE (Google does, Discord/GitHub tolerate it). */
  usesPkce: boolean;
  /** Google needs these on the token exchange to satisfy OIDC. */
  extraAuthorizeParams?: Record<string, string>;
}

export const OAUTH_PROVIDERS: Record<OAuthProviderId, OAuthProviderDefinition> = {
  google: {
    id: 'google',
    label: 'Google',
    authorizeUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
    tokenUrl: 'https://oauth2.googleapis.com/token',
    scopes: ['openid', 'email', 'profile'],
    usesPkce: true,
    extraAuthorizeParams: { access_type: 'online', prompt: 'select_account' },
  },
  discord: {
    id: 'discord',
    label: 'Discord',
    authorizeUrl: 'https://discord.com/api/oauth2/authorize',
    tokenUrl: 'https://discord.com/api/oauth2/token',
    scopes: ['identify', 'email'],
    usesPkce: true,
  },
  github: {
    id: 'github',
    label: 'GitHub',
    authorizeUrl: 'https://github.com/login/oauth/authorize',
    tokenUrl: 'https://github.com/login/oauth/access_token',
    scopes: ['read:user', 'user:email'],
    usesPkce: false,
  },
};

export interface OAuthConfig {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
}

export interface NormalizedProfile {
  provider: OAuthProviderId;
  /** Stable provider-side id. Never the email, which can change. */
  subject: string;
  username: string;
  email: string | null;
  /** True only when the provider itself asserts the address is verified. */
  emailVerified: boolean;
  avatarUrl: string | null;
}

export function isOAuthProviderId(v: unknown): v is OAuthProviderId {
  return typeof v === 'string' && Object.prototype.hasOwnProperty.call(OAUTH_PROVIDERS, v);
}

/** PKCE verifier: 43-128 chars of unreserved characters per RFC 7636. */
export function createPkcePair(): { verifier: string; challenge: string } {
  const verifier = crypto.randomBytes(32).toString('base64url');
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
  return { verifier, challenge };
}

export function createOAuthState(): string {
  return crypto.randomBytes(32).toString('base64url');
}

/** Constant-time state comparison; a plain !== leaks timing. */
export function oauthStateMatches(expected: string | undefined, actual: unknown): boolean {
  if (!expected || typeof actual !== 'string') return false;
  const a = Buffer.from(expected);
  const b = Buffer.from(actual);
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

export function buildAuthorizeUrl(params: {
  provider: OAuthProviderId;
  config: OAuthConfig;
  state: string;
  codeChallenge?: string;
}): string {
  const def = OAUTH_PROVIDERS[params.provider];
  const url = new URL(def.authorizeUrl);
  url.searchParams.set('client_id', params.config.clientId);
  url.searchParams.set('redirect_uri', params.config.redirectUri);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('scope', def.scopes.join(' '));
  url.searchParams.set('state', params.state);
  if (def.usesPkce && params.codeChallenge) {
    url.searchParams.set('code_challenge', params.codeChallenge);
    url.searchParams.set('code_challenge_method', 'S256');
  }
  for (const [k, v] of Object.entries(def.extraAuthorizeParams || {})) {
    url.searchParams.set(k, v);
  }
  return url.toString();
}

/** Exchange an authorization code. Throws on any non-2xx response. */
export async function exchangeCodeForToken(params: {
  provider: OAuthProviderId;
  config: OAuthConfig;
  code: string;
  codeVerifier?: string;
  fetchImpl?: typeof fetch;
}): Promise<{ accessToken: string; tokenType: string; scope: string | null }> {
  const def = OAUTH_PROVIDERS[params.provider];
  const doFetch = params.fetchImpl || fetch;
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code: params.code,
    client_id: params.config.clientId,
    client_secret: params.config.clientSecret,
    redirect_uri: params.config.redirectUri,
  });
  if (params.codeVerifier) body.set('code_verifier', params.codeVerifier);

  const res = await doFetch(def.tokenUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Accept: 'application/json',
    },
    body: body.toString(),
  });

  const text = await res.text();
  if (!res.ok) {
    throw new Error(`Token exchange failed (${res.status}): ${text.slice(0, 200)}`);
  }

  // GitHub answers form-encoded unless asked for JSON; Accept header handles it,
  // but stay tolerant in case a proxy strips the header.
  let payload: any;
  try {
    payload = JSON.parse(text);
  } catch {
    payload = Object.fromEntries(new URLSearchParams(text));
  }
  if (payload.error) {
    throw new Error(`Token exchange rejected: ${payload.error_description || payload.error}`);
  }
  const accessToken = payload.access_token;
  if (!accessToken) throw new Error('Token exchange returned no access_token');
  return {
    accessToken: String(accessToken),
    tokenType: String(payload.token_type || 'Bearer'),
    scope: payload.scope ? String(payload.scope) : null,
  };
}

async function getJson(url: string, accessToken: string, fetchImpl: typeof fetch) {
  const res = await fetchImpl(url, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      Accept: 'application/json',
      'User-Agent': 'TGVPANEL',
    },
  });
  if (!res.ok) {
    throw new Error(`Profile fetch failed (${res.status}) from ${url}`);
  }
  return (await res.json()) as any;
}

/**
 * Fetch and normalise the user profile. The provider decides the shape, so
 * each branch is explicit rather than clever.
 */
export async function fetchNormalizedProfile(params: {
  provider: OAuthProviderId;
  accessToken: string;
  fetchImpl?: typeof fetch;
}): Promise<NormalizedProfile> {
  const doFetch = params.fetchImpl || fetch;
  const token = params.accessToken;

  if (params.provider === 'google') {
    const me = await getJson('https://openidconnect.googleapis.com/v1/userinfo', token, doFetch);
    return {
      provider: 'google',
      subject: String(me.sub),
      username: String(me.name || me.email || me.sub),
      email: me.email ? String(me.email) : null,
      emailVerified: me.email_verified === true || me.email_verified === 'true',
      avatarUrl: me.picture ? String(me.picture) : null,
    };
  }

  if (params.provider === 'discord') {
    const me = await getJson('https://discord.com/api/users/@me', token, doFetch);
    const avatar = me.avatar
      ? `https://cdn.discordapp.com/avatars/${me.id}/${me.avatar}.png?size=256`
      : null;
    return {
      provider: 'discord',
      subject: String(me.id),
      username: String(me.global_name || me.username || me.id),
      email: me.email ? String(me.email) : null,
      // Discord only returns an email for verified accounts.
      emailVerified: Boolean(me.verified) && Boolean(me.email),
      avatarUrl: avatar,
    };
  }

  // github
  const me = await getJson('https://api.github.com/user', token, doFetch);
  let email: string | null = me.email ? String(me.email) : null;
  let emailVerified = false;
  // GitHub hides the primary address unless we ask the emails endpoint.
  if (!email) {
    try {
      const emails = (await getJson('https://api.github.com/user/emails', token, doFetch)) as any[];
      const primary = Array.isArray(emails)
        ? emails.find((e) => e.primary && e.verified) || emails.find((e) => e.verified)
        : null;
      if (primary) {
        email = String(primary.email);
        emailVerified = true;
      }
    } catch {
      // Not fatal: account linking falls back to manual confirmation.
    }
  } else if (me.email) {
    // A public profile email is not necessarily verified; confirm it.
    try {
      const emails = (await getJson('https://api.github.com/user/emails', token, doFetch)) as any[];
      if (Array.isArray(emails)) {
        emailVerified = emails.some((e) => String(e.email) === email && e.verified);
      }
    } catch {
      emailVerified = false;
    }
  }
  return {
    provider: 'github',
    subject: String(me.id),
    username: String(me.login || me.id),
    email,
    emailVerified,
    avatarUrl: me.avatar_url ? String(me.avatar_url) : null,
  };
}

/**
 * Decide what to do with a profile: sign in an existing link, link to a
 * matching account, or create a new one. Pure so it can be unit tested.
 *
 * `link` is only auto-trusted when the provider vouches for the address.
 * An unverified email could belong to someone else, so it must not be used
 * to take over an existing account.
 */
export type LinkDecision =
  | { action: 'login'; userId: number }
  | { action: 'link'; userId: number; requiresProof: boolean }
  | { action: 'create' }
  | { action: 'refuse'; reason: string };

export function decideAccountLink(input: {
  linkedUserId: number | null;
  matchingEmailUserId: number | null;
  emailVerified: boolean;
  email: string | null;
  autoCreateUsers: boolean;
}): LinkDecision {
  if (input.linkedUserId !== null) {
    return { action: 'login', userId: input.linkedUserId };
  }
  if (input.matchingEmailUserId !== null) {
    // Signing straight in on an unverified address is account takeover.
    if (input.emailVerified) {
      return { action: 'link', userId: input.matchingEmailUserId, requiresProof: false };
    }
    return { action: 'link', userId: input.matchingEmailUserId, requiresProof: true };
  }
  if (!input.autoCreateUsers) {
    return { action: 'refuse', reason: 'No account exists for this address and automatic sign-up is disabled.' };
  }
  if (!input.email) {
    return { action: 'refuse', reason: 'The provider did not share an email address, which is required to create an account.' };
  }
  return { action: 'create' };
}
