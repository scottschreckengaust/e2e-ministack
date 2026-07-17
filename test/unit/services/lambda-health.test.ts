import {
  State,
  LastUpdateStatus,
  type FunctionConfiguration,
} from '@aws-sdk/client-lambda';
import {
  isFunctionConfigHealthy,
  hasProvenanceMarker,
} from '../../../services/lambda/health';

// Unit test for the Lambda-vertical health predicate (#147). Table-drives every
// branch of the State/LastUpdateStatus classifier so the module is held at the
// repo's 100% gate: both explicit-bad-state branches, the OR short-circuits, and
// the absent/unknown-field tolerance.
describe('isFunctionConfigHealthy', () => {
  const cases: Array<[string, FunctionConfiguration | undefined, boolean]> = [
    ['undefined config → healthy (tolerated)', undefined, true],
    [
      'Active + Successful → healthy',
      { State: State.Active, LastUpdateStatus: LastUpdateStatus.Successful },
      true,
    ],
    [
      'Pending + InProgress (transient) → healthy',
      { State: State.Pending, LastUpdateStatus: LastUpdateStatus.InProgress },
      true,
    ],
    [
      'Active + InProgress → healthy',
      { State: State.Active, LastUpdateStatus: LastUpdateStatus.InProgress },
      true,
    ],
    [
      'Failed state → unhealthy',
      { State: State.Failed, LastUpdateStatus: LastUpdateStatus.Successful },
      false,
    ],
    [
      'Inactive state → unhealthy',
      { State: State.Inactive, LastUpdateStatus: LastUpdateStatus.Successful },
      false,
    ],
    [
      'Active + LastUpdateStatus Failed → unhealthy',
      { State: State.Active, LastUpdateStatus: LastUpdateStatus.Failed },
      false,
    ],
    ['no fields → healthy (tolerated)', {}, true],
  ];

  it.each(cases)('%s', (_label, cfg, expected) => {
    expect(isFunctionConfigHealthy(cfg)).toBe(expected);
  });
});

// Unit test for the provenance-marker predicate (#175). This is the pure core
// of the integration adapter's read-back assertion: after `deploy()` the CDK
// adapter reads the live function via GetFunction and, on BOTH the verify
// fast-path and a fresh provision, requires the exact Description marker that
// only DoublerFunction/CompatLambdaStack stamps. A stale or foreign function of
// the same name lacks it, so the adapter fails loudly instead of letting the
// oracle green against a resource this stack never provisioned. Table-drives
// every branch so the classifier stays at the repo's 100% gate.
describe('hasProvenanceMarker', () => {
  const marker = 'the-expected-marker';
  const cases: Array<[string, FunctionConfiguration | undefined, boolean]> = [
    ['undefined config → absent', undefined, false],
    ['no Description field → absent', {}, false],
    ['empty Description → absent', { Description: '' }, false],
    ['foreign Description → absent', { Description: 'something else' }, false],
    ['exact marker → present', { Description: marker }, true],
  ];

  it.each(cases)('%s', (_label, cfg, expected) => {
    expect(hasProvenanceMarker(cfg, marker)).toBe(expected);
  });
});
