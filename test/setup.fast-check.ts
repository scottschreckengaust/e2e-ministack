// Make the fast-check property tests DETERMINISTIC.
//
// Without a pinned seed, @fast-check/jest seeds each run with
// `Date.now() ^ (Math.random() * 2**32)`, so the same commit explores
// different inputs on every run. That made the property gate flaky: a
// non-coercible input like {toString:0} (which the old handler threw on) only
// surfaced on *some* runs, so identical code passed on the PR-triggered CI run
// and failed on the push-triggered one — and slipped past local checks too.
//
// Pinning the seed trades "discover new counterexamples in CI" for "every run
// is reproducible". That trade is right here because:
//   - the known bug classes are locked by explicit it.each cases, not luck, and
//   - unbounded random exploration still happens in the scheduled jazzer.js
//     fuzz job (fuzz/handler.fuzz.js), which is the proper place for it.
// numRuns is bumped so each (deterministic) run still covers a broad sample.
//
// NOTE: this file is .ts on purpose — .gitignore ignores test/**/*.js as
// transient compiled output, which would silently drop a .js setup file.
import { fc } from '@fast-check/jest';

fc.configureGlobal({ seed: 0x5eed, numRuns: 1000 });
