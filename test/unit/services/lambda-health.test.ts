import {
  State,
  LastUpdateStatus,
  type FunctionConfiguration,
} from '@aws-sdk/client-lambda';
import { isFunctionConfigHealthy } from '../../../services/lambda/health';

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
