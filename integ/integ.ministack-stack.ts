/**
 * CDK integration test for MiniStackStack — exercised by @aws-cdk/integ-runner.
 *
 * Snapshot baseline: integ/integ.ministack-stack.snapshot/ (committed).
 * Regenerate after intentional template changes:
 *   npm run test:integ-snapshot:update
 *
 * See CONTRIBUTING.md and docs/TESTING.md.
 */
import * as cdk from 'aws-cdk-lib';
import { RequireApproval } from 'aws-cdk-lib/cloud-assembly-schema';
import { IntegTest } from '@aws-cdk/integ-tests-alpha';
import { MiniStackStack } from '../lib/ministack-stack.js';
import { MINISTACK_ENV } from '../lib/env.js';

const app = new cdk.App();

const stack = new MiniStackStack(app, 'MiniStackTestStack', {
  env: MINISTACK_ENV,
});

new IntegTest(app, 'MiniStackSnapshot', {
  testCases: [stack],
  // Mask volatile Lambda asset hashes (same motivation as #42).
  diffAssets: true,
  cdkCommandOptions: {
    deploy: {
      args: {
        requireApproval: RequireApproval.NEVER,
      },
    },
    destroy: {
      args: {
        force: true,
      },
    },
  },
});
