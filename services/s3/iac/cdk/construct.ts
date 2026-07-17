import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as s3 from 'aws-cdk-lib/aws-s3';

/** Props for {@link HardenedBucket}. */
export interface HardenedBucketProps {
  /**
   * Physical name of the data bucket. Defaults to `cdk-demo-bucket` (mirroring
   * the demo bucket's name for standalone/verbatim reuse), but the compat stack
   * ({@link CompatS3Stack} in iac/cdk/stack.ts) OVERRIDES it to
   * `compat-s3-bucket` on purpose: MiniStack shares one global namespace, so
   * leaving the default would collide with the demo `cdk-demo-bucket` whenever
   * both are deployed (as in CI). Pass a distinct `compat-*` name in any stack
   * that provisions this construct alongside the demo stack.
   */
  readonly bucketName?: string;
}

/**
 * Standalone, reusable hardened S3 data bucket — the construct fragment the
 * MiniStack compat harness exposes for the S3/CDK vertical (epic #117, #139).
 *
 * It is a faithful mirror of the `cdk-demo-bucket` / `cdk-demo-log-bucket` pair
 * defined inline in `lib/ministack-stack.ts`: a data bucket that ships its S3
 * server access logs to a DEDICATED log bucket which logs to ITSELF (so the
 * access-logging rules are satisfied without an infinite chain of log buckets).
 * Both buckets apply the same hardening — TLS enforced, SSE, block-all-public,
 * versioning, and bounded lifecycle rules — so the construct passes cdk-nag
 * (AwsSolutions-S1/S2/S10) and checkov (CKV_AWS_18/21/300) identically.
 *
 * This construct is the reusable building block the vertical PROVISIONS: it is
 * instantiated by {@link CompatS3Stack} (iac/cdk/stack.ts), which the CDK
 * {@link DeployAdapter} (iac/cdk/deploy.ts) verify-or-provisions against a live
 * MiniStack (#147). It is deliberately NOT added to the demo stack
 * `lib/ministack-stack.ts` — that stays the decoupled "sample", while each
 * compat vertical owns and deploys its own `Compat*Stack` (the sample-vs-proof
 * split). It is exercised in full by the pure-synth unit test
 * `test/unit/services/s3-construct.test.ts`, which holds it under the repo's
 * 100% coverage gate.
 *
 * WARNING — do NOT deploy unchanged to a real AWS account: S3 bucket names are
 * GLOBALLY unique, so the fixed names below would collide (issue #35). They are
 * deliberate here only because MiniStack isolates the global namespace.
 */
export class HardenedBucket extends Construct {
  /** The underlying data bucket, exposed so callers can grant/wire it. */
  public readonly bucket: s3.Bucket;

  constructor(scope: Construct, id: string, props: HardenedBucketProps = {}) {
    super(scope, id);

    const bucketName = props.bucketName ?? 'cdk-demo-bucket';

    // Dedicated bucket to receive the data bucket's server access logs
    // (AwsSolutions-S1 / CKV_AWS_18). It logs to itself to avoid an infinite
    // chain of log buckets.
    const logBucket = new s3.Bucket(this, 'LogBucket', {
      bucketName: `${bucketName}-logs`,
      enforceSSL: true, // AwsSolutions-S10
      encryption: s3.BucketEncryption.S3_MANAGED,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL, // AwsSolutions-S2
      versioned: true, // CKV_AWS_21
      serverAccessLogsPrefix: 'self/', // CKV_AWS_18 (logs to itself)
      // Bound noncurrent-version / multipart-upload / self-log accumulation
      // (issue #6 / CKV_AWS_300), same rationale as the demo log bucket.
      lifecycleRules: [
        {
          id: 'expire-noncurrent-versions',
          noncurrentVersionExpiration: cdk.Duration.days(30),
          noncurrentVersionsToRetain: 1,
          abortIncompleteMultipartUploadAfter: cdk.Duration.days(7),
        },
        {
          id: 'expire-access-logs',
          prefix: 'self/',
          expiration: cdk.Duration.days(90),
        },
      ],
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    // Data bucket: no autoDeleteObjects custom resource, which doesn't complete
    // cleanly against the emulator. Clean up with `cdk destroy` +
    // POST /_ministack/reset instead.
    this.bucket = new s3.Bucket(this, 'DataBucket', {
      bucketName,
      enforceSSL: true, // AwsSolutions-S10
      encryption: s3.BucketEncryption.S3_MANAGED,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL, // AwsSolutions-S2
      versioned: true, // CKV_AWS_21
      serverAccessLogsBucket: logBucket, // AwsSolutions-S1 / CKV_AWS_18
      serverAccessLogsPrefix: 'data-bucket/',
      lifecycleRules: [
        {
          id: 'expire-noncurrent-versions',
          noncurrentVersionExpiration: cdk.Duration.days(30),
          noncurrentVersionsToRetain: 1,
          abortIncompleteMultipartUploadAfter: cdk.Duration.days(7),
        },
      ],
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });
  }
}
