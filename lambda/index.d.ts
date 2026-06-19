// Hand-written type contract for the plain-JS Lambda handler (index.js).
// Committed on purpose (see .gitignore) so the unit tests can import it with
// types without enabling allowJs (which would clash with the JS source).

// The handler accepts arbitrary input (it validates at runtime), so the event
// is intentionally loose — fuzz/property tests pass non-numeric/garbage values.
export interface DoublerEvent {
  n?: unknown;
}

export interface DoublerResult {
  statusCode: number;
  /** Present on success (statusCode 200); always a finite number. */
  doubled?: number;
  /** Present on failure (statusCode 400). */
  error?: string;
  nodeVersion: string;
}

export function handler(event?: DoublerEvent | null): Promise<DoublerResult>;
