"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const path_1 = __importDefault(require("path"));
const sqlite3_1 = __importDefault(require("sqlite3"));
const database_1 = require("./database");
const migrations_1 = require("./migrations");
async function main() {
    const dbDir = process.env.TGVPANEL_DATA_DIR ||
        process.env.HKVM_DATA_DIR ||
        path_1.default.resolve(process.cwd(), 'data');
    const dbPath = (0, database_1.resolveAndMigrateDatabasePath)(dbDir, process.env.TGVPANEL_DB_PATH || process.env.HKVM_DB_PATH);
    const raw = new sqlite3_1.default.Database(dbPath);
    const db = new database_1.UnifiedDatabase(raw, dbPath);
    try {
        const res = await (0, migrations_1.runMigrations)(db);
        console.log(JSON.stringify({
            success: true,
            dbPath,
            appliedMigrations: res.applied,
            backupPath: res.backupPath || null,
        }, null, 2));
    }
    finally {
        raw.close();
    }
}
main().catch((err) => {
    console.error('[TGVPANEL Migrate Error]', err);
    process.exit(1);
});
