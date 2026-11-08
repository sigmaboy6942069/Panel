import { Router } from 'express';
import { HkvmRuntimeContext } from '../context';
export declare function createUnifiedWebRouter(ctx: HkvmRuntimeContext, getLicenseSummary?: () => Record<string, unknown>): Router;
