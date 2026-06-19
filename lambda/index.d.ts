// Hand-written type contract for the plain-JS Lambda handler (index.js).
// Committed on purpose (see .gitignore) so the unit tests can import it with
// types without enabling allowJs (which would clash with the JS source).

export interface DoublerEvent {
  n?: number;
}

export interface DoublerResult {
  statusCode: number;
  doubled: number;
  nodeVersion: string;
}

export function handler(event: DoublerEvent): Promise<DoublerResult>;
