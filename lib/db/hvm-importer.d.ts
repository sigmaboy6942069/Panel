import { UnifiedDatabase } from './database';
export interface HvmImportReport {
    backupPath: string;
    usersMappedExisting: number;
    usersCreated: number;
    nodesImported: number;
    vpsImported: number;
    portsImported: number;
    snapshotsImported: number;
    backupsImported: number;
    notificationsImported: number;
    apiKeysImported: number;
    warnings: string[];
}
/**
 * Verifies legacy Werkzeug hashes (pbkdf2:sha256 / scrypt) or bcrypt hashes
 * so imported HVM accounts can authenticate safely and upgrade to HKVM bcrypt.
 */
export declare function verifyPasswordWithLegacySupport(plaintext: string, storedHash: string): {
    valid: boolean;
    needsRehash: boolean;
};
export declare function importHvmDatabase(hkvmDb: UnifiedDatabase, hvmDbFilePath: string): Promise<HvmImportReport>;
