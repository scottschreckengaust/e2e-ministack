// Trivial handler exercised by the integration test: doubles event.n and
// reports the Node version it ran under (so the test can assert nodejs24.x).
exports.handler = async (event) => ({
  statusCode: 200,
  doubled: (event.n || 0) * 2,
  nodeVersion: process.version,
});
