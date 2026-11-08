import { UnifiedDatabase } from './database';
export interface MigrationDefinition {
    version: number;
    name: string;
    up: (db: UnifiedDatabase) => Promise<void>;
}
export declare const BUILTIN_LXC_OS_CATALOG: ({
    key: string;
    label: string;
    alias: string;
    fallback: string;
    family: string;
    category: string;
    version: string;
    icon: string;
    minDiskGb: number;
    minRamMb: number;
    description: string;
} | {
    key: string;
    label: string;
    alias: string;
    fallback: null;
    family: string;
    category: string;
    version: string;
    icon: string;
    minDiskGb: number;
    minRamMb: number;
    description: string;
})[];
export declare const MIGRATIONS: MigrationDefinition[];
export declare function runMigrations(db: UnifiedDatabase): Promise<{
    applied: string[];
    backupPath?: string;
}>;
