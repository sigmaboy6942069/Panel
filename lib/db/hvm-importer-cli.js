"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const path_1 = __importDefault(require("path"));
const sqlite3_1 = __importDefault(require("sqlite3"));
const database_1 = require("./database");
const migrations_1 = require("./migrations");
const hvm_importer_1 = require("./hvm-importer");
async function main() {
    const sourcePath = process.argv[2];
    if (!sourcePath) {
        console.error('Usage: npm run import:hvm -- <path-to-hvm.db>');
        process.exit(1);
    }
    const dbDir = process.env.TGVPANEL_DATA_DIR ||
        process.env.HKVM_DATA_DIR ||
        path_1.default.resolve(process.cwd(), 'data');
    const dbPath = (0, database_1.resolveAndMigrateDatabasePath)(dbDir, process.env.TGVPANEL_DB_PATH || process.env.HKVM_DB_PATH);
    const raw = new sqlite3_1.default.Database(dbPath);
    const db = new database_1.UnifiedDatabase(raw, dbPath);
    try {
        await (0, migrations_1.runMigrations)(db);
        const report = await (0, hvm_importer_1.importHvmDatabase)(db, path_1.default.resolve(sourcePath));
        console.log(JSON.stringify({ success: true, report }, null, 2));
    }
    finally {
        raw.close();
    }
}
main().catch((err) => {
    console.error('[TGVPANEL HVM-Import Error]', err);
    process.exit(1);
});
