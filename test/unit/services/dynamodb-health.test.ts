import { TableStatus, type TableDescription } from '@aws-sdk/client-dynamodb';
import {
  isTableHealthy,
  hasProvenanceMarker,
} from '../../../services/dynamodb/health';

// Unit test for the DynamoDB-vertical health + provenance predicates (#140).
// Table-drives every branch so both modules are held at the repo's 100% gate.

describe('isTableHealthy', () => {
  const cases: Array<[string, TableDescription | undefined, boolean]> = [
    ['undefined description → healthy (tolerated)', undefined, true],
    // No TableStatus at all: exercises the `desc?.` short-circuit branch.
    ['absent TableStatus → healthy (tolerated)', {}, true],
    ['ACTIVE → healthy', { TableStatus: TableStatus.ACTIVE }, true],
    [
      'CREATING (transient) → healthy',
      { TableStatus: TableStatus.CREATING },
      true,
    ],
    [
      'UPDATING (transient) → healthy',
      { TableStatus: TableStatus.UPDATING },
      true,
    ],
    ['ARCHIVED → unhealthy', { TableStatus: TableStatus.ARCHIVED }, false],
    ['ARCHIVING → unhealthy', { TableStatus: TableStatus.ARCHIVING }, false],
    ['DELETING → unhealthy', { TableStatus: TableStatus.DELETING }, false],
    [
      'INACCESSIBLE_ENCRYPTION_CREDENTIALS → unhealthy',
      { TableStatus: TableStatus.INACCESSIBLE_ENCRYPTION_CREDENTIALS },
      false,
    ],
    [
      'REPLICATION_NOT_AUTHORIZED → unhealthy',
      { TableStatus: TableStatus.REPLICATION_NOT_AUTHORIZED },
      false,
    ],
  ];

  it.each(cases)('%s', (_label, desc, expected) => {
    expect(isTableHealthy(desc)).toBe(expected);
  });
});

// Unit test for the provenance-marker predicate (#140, mirrors #175). This is
// the pure core of the integration adapter's read-back assertion: after
// `deploy()` the CDK adapter reads the live table via DescribeTable and, on BOTH
// the verify fast-path and a fresh provision, requires the exact partition-key
// marker that only HardenedTable/CompatDynamoStack sets. A stale or foreign
// table of the same name lacks it, so the adapter fails loudly instead of
// letting the oracle green against a resource this stack never provisioned.
// Table-drives every branch so the classifier stays at the repo's 100% gate.
describe('hasProvenanceMarker', () => {
  const marker = 'the-expected-pk';
  const withHashKey = (name: string): TableDescription =>
    ({
      KeySchema: [{ AttributeName: name, KeyType: 'HASH' }],
    }) as TableDescription;

  const cases: Array<[string, TableDescription | undefined, boolean]> = [
    ['undefined description → absent', undefined, false],
    ['no KeySchema field → absent', {}, false],
    ['empty KeySchema → absent', { KeySchema: [] }, false],
    [
      'only a RANGE key (no HASH) → absent',
      {
        KeySchema: [{ AttributeName: marker, KeyType: 'RANGE' }],
      } as TableDescription,
      false,
    ],
    ['foreign HASH key → absent', withHashKey('something-else'), false],
    ['exact marker HASH key → present', withHashKey(marker), true],
  ];

  it.each(cases)('%s', (_label, desc, expected) => {
    expect(hasProvenanceMarker(desc, marker)).toBe(expected);
  });
});
