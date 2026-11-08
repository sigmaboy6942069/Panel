import fs from 'fs';
import path from 'path';
import { LxcContainerManager } from './container-manager';
import { LxcSnapshotAndBackupManager } from './snapshot-manager';
import { SafeValidators } from '../security/middleware';

export interface MigrationExportBundle {
  containerName: string;
  wasRunning: boolean;
  archivePath: string;
  sizeBytes: number;
  checksumSha256: string;
}

/**
 * Implements the node-side operations for HKVM Offline Verified VPS Migration:
 * 1. Stop container cleanly on source node
 * 2. Export verified `.tar.gz` archive with SHA-256 digest
 * 3. Stream archive to target node & verify SHA-256 before extraction
 * 4. Apply target node network config & verify container starts cleanly
 * 5. Rollback cleanly on either source or target if verification fails
 */
export class LxcTransferManager {
  private containerManager: LxcContainerManager;
  private snapshotManager: LxcSnapshotAndBackupManager;
  private stagingDir: string;

  constructor(
    containerManager: LxcContainerManager,
    snapshotManager: LxcSnapshotAndBackupManager,
    stagingDir = path.join(
      process.env.TGVPANEL_DATA_DIR ||
        process.env.HKVM_DATA_DIR ||
        path.resolve(process.cwd(), 'data'),
      'migration-staging'
    )
  ) {
    this.containerManager = containerManager;
    this.snapshotManager = snapshotManager;
    this.stagingDir = stagingDir;
    fs.mkdirSync(this.stagingDir, { recursive: true });
  }

  public async prepareOfflineExport(containerName: string): Promise<MigrationExportBundle> {
    const safeName = SafeValidators.containerName(containerName);
    const runtimeInfo = await this.containerManager.inspectContainer(safeName);
    const wasRunning = runtimeInfo.state === 'running' || runtimeInfo.state === 'frozen';

    if (wasRunning) {
      await this.containerManager.stopContainer(safeName, false);
    }

    const artifact = await this.snapshotManager.createTarBackup(
      safeName,
      `mig_${Date.now()}`
    );

    return {
      containerName: safeName,
      wasRunning,
      archivePath: artifact.filePath,
      sizeBytes: artifact.sizeBytes,
      checksumSha256: artifact.checksumSha256,
    };
  }

  public async importAndVerifyBundle(params: {
    containerName: string;
    archiveBufferOrPath: Buffer | string;
    expectedChecksumSha256: string;
    targetBridge?: string;
    targetIpv4?: string | null;
    targetGateway?: string | null;
    startAfterImport?: boolean;
  }): Promise<{ verified: boolean; state: string; archivePath: string }> {
    const safeName = SafeValidators.containerName(params.containerName);
    const existing = await this.containerManager.inspectContainer(safeName);
    if (existing.state !== 'missing') {
      throw new Error(
        `Target node already has a container named "${safeName}" (${existing.state}). Refusing to overwrite.`
      );
    }

    let archivePath: string;
    let tempStagedFile = false;
    if (Buffer.isBuffer(params.archiveBufferOrPath)) {
      archivePath = path.join(this.stagingDir, `${safeName}_import_${Date.now()}.tar.gz`);
      fs.writeFileSync(archivePath, params.archiveBufferOrPath);
      tempStagedFile = true;
    } else {
      archivePath = path.resolve(params.archiveBufferOrPath);
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
        throw new Error(
          `Migrated container "${safeName}" failed post-import startup verification (state=${postCheck.state}).`
        );
      }

      return {
        verified: true,
        state: postCheck.state,
        archivePath,
      };
    } catch (err) {
      // Automatic target cleanup on failed verification so rollback leaves no orphan
      await this.containerManager.destroyContainer(safeName).catch(() => undefined);
      throw err;
    } finally {
      if (tempStagedFile && fs.existsSync(archivePath)) {
        try {
          fs.unlinkSync(archivePath);
        } catch {
          // ignore
        }
      }
    }
  }

  public async rollbackSourceAfterFailure(
    containerName: string,
    wasRunning: boolean,
    archivePath?: string
  ): Promise<void> {
    const safeName = SafeValidators.containerName(containerName);
    if (archivePath && fs.existsSync(archivePath)) {
      fs.unlinkSync(archivePath);
    }
    if (wasRunning) {
      await this.containerManager.startContainer(safeName);
    }
  }

  public async finalizeSourceCleanup(
    containerName: string,
    archivePath?: string
  ): Promise<void> {
    const safeName = SafeValidators.containerName(containerName);
    if (archivePath && fs.existsSync(archivePath)) {
      fs.unlinkSync(archivePath);
    }
    await this.containerManager.destroyContainer(safeName);
  }
}
