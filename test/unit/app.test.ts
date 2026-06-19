import * as cdk from 'aws-cdk-lib';
import { buildApp } from '../../bin/app';
import { MINISTACK_ENV } from '../../lib/env';

// Regression guard for issue #2: bin/app.ts must NOT resolve the deploy target
// from ambient credentials. The CDK CLI injects CDK_DEFAULT_ACCOUNT from the
// full credential chain (AWS_PROFILE / SSO / IMDS) before running the app, so a
// `?? '000000000000'` fallback only fires when there are *no* credentials at
// all. In any normal dev shell it leaks the contributor's real account into
// synth (empirically observed: account 677276119483). Pin it unconditionally.
describe('bin/app.ts deploy environment', () => {
  const POLLUTED_ACCOUNT = '677276119483'; // a real-looking AWS account id
  const POLLUTED_REGION = 'eu-west-1';

  let savedAccount: string | undefined;
  let savedRegion: string | undefined;

  beforeEach(() => {
    savedAccount = process.env.CDK_DEFAULT_ACCOUNT;
    savedRegion = process.env.CDK_DEFAULT_REGION;
  });

  afterEach(() => {
    // Restore so we never leak the pollution into other tests.
    if (savedAccount === undefined) delete process.env.CDK_DEFAULT_ACCOUNT;
    else process.env.CDK_DEFAULT_ACCOUNT = savedAccount;
    if (savedRegion === undefined) delete process.env.CDK_DEFAULT_REGION;
    else process.env.CDK_DEFAULT_REGION = savedRegion;
  });

  it('pins the MiniStack account/region even when ambient AWS credentials point elsewhere', () => {
    process.env.CDK_DEFAULT_ACCOUNT = POLLUTED_ACCOUNT;
    process.env.CDK_DEFAULT_REGION = POLLUTED_REGION;

    const app = buildApp();
    const stack = app.node.findChild('MiniStackTestStack') as cdk.Stack;

    expect(stack.account).toBe('000000000000');
    expect(stack.region).toBe('us-east-1');
  });

  it('uses the shared MINISTACK_ENV constant as the single source of truth', () => {
    const app = buildApp();
    const stack = app.node.findChild('MiniStackTestStack') as cdk.Stack;

    expect(stack.account).toBe(MINISTACK_ENV.account);
    expect(stack.region).toBe(MINISTACK_ENV.region);
  });
});
