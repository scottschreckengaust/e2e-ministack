import * as fs from 'node:fs';
import * as path from 'node:path';
import {
  repoRoot,
  cdkBin,
  tsNodeBin,
  appCommand,
  bootstrapArgs,
  deployArgs,
  cdkEnv,
  cdkExecOpts,
  CDK_MAX_BUFFER,
} from '../../../services/_harness/cdk';
import { MINISTACK_DEFAULT_ENDPOINT } from '../../../services/_harness/aws-env';
import { MINISTACK_ENV } from '../../../lib/env';

// Unit test for the shared CDK provisioning helpers (#147). The repoRoot
// assertion below is the structural guard that makes the original off-by-one
// (repoRoot resolving to the wrong directory) impossible: it fails unless
// repoRoot actually contains the repo's cdk.json + package.json.
describe('_harness/cdk — shared CDK provisioning helpers', () => {
  describe('repoRoot', () => {
    it('points at the actual repo root (contains cdk.json)', () => {
      expect(fs.existsSync(path.join(repoRoot, 'cdk.json'))).toBe(true);
    });

    it('points at the actual repo root (contains package.json)', () => {
      expect(fs.existsSync(path.join(repoRoot, 'package.json'))).toBe(true);
    });
  });

  describe('bin resolution', () => {
    it('resolves cdk from the repo node_modules/.bin, absolutely', () => {
      expect(path.isAbsolute(cdkBin)).toBe(true);
      expect(cdkBin.endsWith(path.join('node_modules', '.bin', 'cdk'))).toBe(
        true,
      );
    });

    it('resolves ts-node from the repo node_modules/.bin, absolutely', () => {
      expect(path.isAbsolute(tsNodeBin)).toBe(true);
      expect(
        tsNodeBin.endsWith(path.join('node_modules', '.bin', 'ts-node')),
      ).toBe(true);
    });
  });

  describe('appCommand', () => {
    it('runs the entry through ts-node --prefer-ts-exts', () => {
      const cmd = appCommand('/x/app.ts');
      expect(cmd).toContain(tsNodeBin);
      expect(cmd).toContain('--prefer-ts-exts');
      expect(cmd).toContain('/x/app.ts');
    });
  });

  describe('bootstrapArgs', () => {
    it('is the cdk bootstrap argv for the MiniStack env', () => {
      expect(bootstrapArgs('CMD')).toEqual([
        'bootstrap',
        'aws://000000000000/us-east-1',
        '--app',
        'CMD',
      ]);
    });

    it('derives the target from MINISTACK_ENV (not a hardcoded literal)', () => {
      expect(bootstrapArgs('CMD')).toEqual([
        'bootstrap',
        `aws://${MINISTACK_ENV.account}/${MINISTACK_ENV.region}`,
        '--app',
        'CMD',
      ]);
    });
  });

  describe('deployArgs', () => {
    it('is the cdk deploy argv for the given stack', () => {
      expect(deployArgs('CompatLambdaStack', 'CMD')).toEqual([
        'deploy',
        'CompatLambdaStack',
        '--require-approval',
        'never',
        '--app',
        'CMD',
      ]);
    });
  });

  describe('cdkEnv', () => {
    it('keeps an explicit AWS_ENDPOINT_URL_S3', () => {
      expect(
        cdkEnv({ AWS_ENDPOINT_URL_S3: 'http://s3' }).AWS_ENDPOINT_URL_S3,
      ).toBe('http://s3');
    });

    it('backfills S3 to the generic endpoint when only AWS_ENDPOINT_URL is set', () => {
      expect(
        cdkEnv({ AWS_ENDPOINT_URL: 'http://gen' }).AWS_ENDPOINT_URL_S3,
      ).toBe('http://gen');
    });

    it('backfills S3 to the MiniStack default when neither is set', () => {
      expect(cdkEnv({}).AWS_ENDPOINT_URL_S3).toBe(MINISTACK_DEFAULT_ENDPOINT);
    });
  });

  describe('cdkExecOpts', () => {
    it('pins cwd=repoRoot, the enlarged maxBuffer, and the S3-backfilled env', () => {
      const opts = cdkExecOpts({});
      expect(opts.cwd).toBe(repoRoot);
      expect(opts.maxBuffer).toBe(64 * 1024 * 1024);
      expect(opts.maxBuffer).toBe(CDK_MAX_BUFFER);
      expect(opts.env.AWS_ENDPOINT_URL_S3).toBe(MINISTACK_DEFAULT_ENDPOINT);
    });
  });
});
