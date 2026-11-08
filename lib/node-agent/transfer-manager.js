"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.LxcTransferManager = void 0;
const fs_1 = __importDefault(require("fs"));
const path_1 = __importDefault(require("path"));
const middleware_1 = require("../security/middleware");
/**
 * Implements the node-side operations for HKVM Offline Verified VPS Migration:
 * 1. Stop container cleanly on source node
 * 2. Export verified `.tar.gz` archive with SHA-256 digest
 * 3. Stream archive to target node & verify SHA-256 before extraction
 * 4. Apply target node network config & verify container starts cleanly
 * 5. Rollback cleanly on either source or target if verification fails
 */
class LxcTransferManager {
    containerManager;
    snapshotManager;
    stagingDir;
    constructor(containerManager, snapshotManager, stagingDir = path_1.default.join(process.env.TGVPANEL_DATA_DIR ||
        process.env.HKVM_DATA_DIR ||
        path_1.default.resolve(process.cwd(), 'data'), 'migration-staging')) {
        this.containerManager = containerManager;
        this.snapshotManager = snapshotManager;
        this.stagingDir = stagingDir;
        fs_1.default.mkdirSync(this.stagingDir, { recursive: true });
    }
    async prepareOfflineExport(containerName) {
        const safeName = middleware_1.SafeValidators.containerName(containerName);
        const runtimeInfo = await this.containerManager.inspectContainer(safeName);
        const wasRunning = runtimeInfo.state === 'running' || runtimeInfo.state === 'frozen';
        if (wasRunning) {
            await this.containerManager.stopContainer(safeName, false);
        }
        const artifact = await this.snapshotManager.createTarBackup(safeName, `mig_${Date.now()}`);
        return {
            containerName: safeName,
            wasRunning,
            archivePath: artifact.filePath,
            sizeBytes: artifact.sizeBytes,
            checksumSha256: artifact.checksumSha256,
        };
    }
    async importAndVerifyBundle(params) {
        const safeName = middleware_1.SafeValidators.containerName(params.containerName);
        const existing = await this.containerManager.inspectContainer(safeName);
        if (existing.state !== 'missing') {
            throw new Error(`Target node already has a container named "${safeName}" (${existing.state}). Refusing to overwrite.`);
        }
        let archivePath;
        let tempStagedFile = false;
        if (Buffer.isBuffer(params.archiveBufferOrPath)) {
            archivePath = path_1.default.join(this.stagingDir, `${safeName}_import_${Date.now()}.tar.gz`);
            fs_1.default.writeFileSync(archivePath, params.archiveBufferOrPath);
            tempStagedFile = true;
        }
        else {
            archivePath = path_1.default.resolve(params.archiveBufferOrPath);
        }
        try {
            await this.snapshotManager.restoreTarBackup(archivePath, params.expectedChecksumSha256);
            if (params.targetBridge || params.targetIpv4) {
                await this.containerManager.writeManagedConfigSection(safeName, {
                    bridge: params.targetBridge || 'lxcbr0',
                    ipv4Address: params.targetIpv4 || null,
                    ipv4Gateway: params.targetGateway || null,
                });
            }
            if (params.startAfterImport) {
                await this.containerManager.startContainer(safeName);
            }
            const postCheck = await this.containerManager.inspectContainer(safeName);
            if (params.startAfterImport && postCheck.state !== 'running') {
                throw new Error(`Migrated container "${safeName}" failed post-import startup verification (state=${postCheck.state}).`);
            }
            return {
                verified: true,
                state: postCheck.state,
                archivePath,
            };
        }
        catch (err) {
            // Automatic target cleanup on failed verification so rollback leaves no orphan
            await this.containerManager.destroyContainer(safeName).catch(() => undefined);
            throw err;
        }
        finally {
            if (tempStagedFile && fs_1.default.existsSync(archivePath)) {
                try {
                    fs_1.default.unlinkSync(archivePath);
                }
                catch {
                    // ignore
                }
            }
        }
    }
    async rollbackSourceAfterFailure(containerName, wasRunning, archivePath) {
        const safeName = middleware_1.SafeValidators.containerName(containerName);
        if (archivePath && fs_1.default.existsSync(archivePath)) {
            fs_1.default.unlinkSync(archivePath);
        }
        if (wasRunning) {
            await this.containerManager.startContainer(safeName);
        }
    }
    async finalizeSourceCleanup(containerName, archivePath) {
        const safeName = middleware_1.SafeValidators.containerName(containerName);
        if (archivePath && fs_1.default.existsSync(archivePath)) {
            fs_1.default.unlinkSync(archivePath);
        }
        await this.containerManager.destroyContainer(safeName);
    }
}
exports.LxcTransferManager = LxcTransferManager;
