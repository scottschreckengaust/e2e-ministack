#!/usr/bin/env node
import * as cdk from 'aws-cdk-lib';
import { MiniStackStack } from '../lib/ministack-stack';

const app = new cdk.App();

new MiniStackStack(app, 'MiniStackTestStack', {
  // Pin a deterministic account/region so the same bootstrap environment
  // (aws://000000000000/us-east-1) is used locally and in CI against MiniStack.
  env: {
    account: process.env.CDK_DEFAULT_ACCOUNT ?? '000000000000',
    region: process.env.CDK_DEFAULT_REGION ?? 'us-east-1',
  },
});
