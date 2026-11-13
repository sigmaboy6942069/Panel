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
export declare const OAUTH_PROVIDERS: Record<OAuthProviderId, OAuthProviderDefinition>;
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
export declare function isOAuthProviderId(v: unknown): v is OAuthProviderId;
/** PKCE verifier: 43-128 chars of unreserved characters per RFC 7636. */
export declare function createPkcePair(): {
    verifier: string;
    challenge: string;
};
export declare function createOAuthState(): string;
/** Constant-time state comparison; a plain !== leaks timing. */
export declare function oauthStateMatches(expected: string | undefined, actual: unknown): boolean;
export declare function buildAuthorizeUrl(params: {
    provider: OAuthProviderId;
    config: OAuthConfig;
    state: string;
    codeChallenge?: string;
}): string;
/** Exchange an authorization code. Throws on any non-2xx response. */
export declare function exchangeCodeForToken(params: {
    provider: OAuthProviderId;
    config: OAuthConfig;
    code: string;
    codeVerifier?: string;
    fetchImpl?: typeof fetch;
}): Promise<{
    accessToken: string;
    tokenType: string;
    scope: string | null;
}>;
/**
 * Fetch and normalise the user profile. The provider decides the shape, so
 * each branch is explicit rather than clever.
 */
export declare function fetchNormalizedProfile(params: {
    provider: OAuthProviderId;
    accessToken: string;
    fetchImpl?: typeof fetch;
}): Promise<NormalizedProfile>;
/**
 * Decide what to do with a profile: sign in an existing link, link to a
 * matching account, or create a new one. Pure so it can be unit tested.
 *
 * `link` is only auto-trusted when the provider vouches for the address.
 * An unverified email could belong to someone else, so it must not be used
 * to take over an existing account.
 */
export type LinkDecision = {
    action: 'login';
    userId: number;
} | {
    action: 'link';
    userId: number;
    requiresProof: boolean;
} | {
    action: 'create';
} | {
    action: 'refuse';
    reason: string;
};
export declare function decideAccountLink(input: {
    linkedUserId: number | null;
    matchingEmailUserId: number | null;
    emailVerified: boolean;
    email: string | null;
    autoCreateUsers: boolean;
}): LinkDecision;
