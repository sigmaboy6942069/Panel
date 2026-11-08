import { IncomingMessage } from 'http';
import { Request, Response, NextFunction } from 'express';
export declare function sanitizeAgentEnvValue(raw: string | undefined | null): string;
export interface AgentCredentialConfig {
    nodeId: string;
    rawApiKey?: string;
    apiKeyHash: string;
    hmacSecret: string;
    envBootstrapHash?: string;
    requireMtls: boolean;
    allowedControllerIps?: string[];
    credentialsFilePath?: string;
    loadPersistedCredentials?: boolean;
}
/**
 * Replay-protection nonce cache + HMAC/API-Key/mTLS authenticator for the TGVPANEL Node Agent.
 */
export declare class NodeAgentAuthenticator {
    private config;
    private activeRawApiKey?;
    private seenNonces;
    private cleanupTimer;
    private readonly maxSkewSec;
    constructor(config: AgentCredentialConfig);
    getOutboundSigningCredentials(): {
        nodeId: string;
        apiKey: string;
        hmacSecret: string;
    } | null;
    rotateCredentials(newRawApiKey: string, newHmacSecret: string): void;
    private candidateCanonicalPaths;
    verifyRawHeaders(params: {
        method: string;
        pathWithQuery: string;
        signedPathHint?: string;
        rawBody: string;
        apiKeyHeader?: string;
        timestampHeader?: string;
        nonceHeader?: string;
        signatureHeader?: string;
        remoteAddress?: string;
        tlsAuthorized?: boolean;
    }): {
        ok: boolean;
        status: number;
        reason?: string;
    };
    expressMiddleware(): (req: Request, res: Response, next: NextFunction) => void | Response<any, Record<string, any>>;
    verifyWebSocketUpgrade(req: IncomingMessage): {
        ok: boolean;
        reason?: string;
    };
}
