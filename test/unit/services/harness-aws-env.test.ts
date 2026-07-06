import {
  MINISTACK_DEFAULT_ENDPOINT,
  endpoint,
  region,
  ministackEnv,
} from '../../../services/_harness/aws-env';

// Unit test for the shared MiniStack AWS-env defaults (#147). Pure functions
// over an explicit env param — no process.env reads — so every `??` branch is
// exercised deterministically to hold the module at the repo's 100% gate.
describe('_harness/aws-env — MiniStack toolchain defaults', () => {
  describe('endpoint', () => {
    it('falls back to the MiniStack default when AWS_ENDPOINT_URL is unset', () => {
      expect(endpoint({})).toBe(MINISTACK_DEFAULT_ENDPOINT);
    });

    it('returns AWS_ENDPOINT_URL when present', () => {
      expect(endpoint({ AWS_ENDPOINT_URL: 'http://custom:9999' })).toBe(
        'http://custom:9999',
      );
    });
  });

  describe('region', () => {
    it('falls back to us-east-1 when AWS_DEFAULT_REGION is unset', () => {
      expect(region({})).toBe('us-east-1');
    });

    it('returns AWS_DEFAULT_REGION when present', () => {
      expect(region({ AWS_DEFAULT_REGION: 'eu-west-2' })).toBe('eu-west-2');
    });
  });

  describe('ministackEnv', () => {
    it('backfills all five MiniStack defaults on an empty env', () => {
      const out = ministackEnv({});
      expect(out.AWS_ENDPOINT_URL).toBe(MINISTACK_DEFAULT_ENDPOINT);
      expect(out.AWS_REGION).toBe('us-east-1');
      expect(out.AWS_DEFAULT_REGION).toBe('us-east-1');
      expect(out.AWS_ACCESS_KEY_ID).toBe('test');
      expect(out.AWS_SECRET_ACCESS_KEY).toBe('test');
    });

    it('preserves all five values when the env is fully populated', () => {
      const full: NodeJS.ProcessEnv = {
        AWS_ENDPOINT_URL: 'http://gen:1',
        AWS_REGION: 'ap-south-1',
        AWS_DEFAULT_REGION: 'ap-south-1',
        AWS_ACCESS_KEY_ID: 'AKIAREAL',
        AWS_SECRET_ACCESS_KEY: 'realsecret',
      };
      const out = ministackEnv(full);
      expect(out.AWS_ENDPOINT_URL).toBe('http://gen:1');
      expect(out.AWS_REGION).toBe('ap-south-1');
      expect(out.AWS_DEFAULT_REGION).toBe('ap-south-1');
      expect(out.AWS_ACCESS_KEY_ID).toBe('AKIAREAL');
      expect(out.AWS_SECRET_ACCESS_KEY).toBe('realsecret');
    });

    it('spreads unrelated keys through unchanged', () => {
      const out = ministackEnv({ PATH: '/usr/bin', SOME_OTHER: 'keep-me' });
      expect(out.PATH).toBe('/usr/bin');
      expect(out.SOME_OTHER).toBe('keep-me');
    });
  });
});
