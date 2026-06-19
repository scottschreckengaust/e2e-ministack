<!-- Thanks for contributing! Fill in the sections below. -->

## Linked issue

<!-- Use a closing keyword so the issue auto-closes on merge, e.g. "Closes #123". -->

Closes #

## What changed

<!-- Summarize the change and the motivation. -->

## Testing

<!-- Tick the tiers you ran. See CLAUDE.md for the test pyramid. -->

- [ ] `npm run build`
- [ ] `npm run lint`
- [ ] `npm run test:unit` (Lambda logic + CDK assertions/snapshot)
- [ ] `npm run test:integration` (against deployed MiniStack resources)
- [ ] `npm run test:mutation` (Stryker, if Lambda logic changed)
- [ ] `npm run fuzz` (jazzer.js; needs GLIBC >= 2.38)
- [ ] Not applicable (docs/config only) — explain below

## Checklist

- [ ] CDK snapshot regenerated (`npm run test:unit -- -u`) if the synthesized template changed
- [ ] Security gates still pass (cdk-nag synth, checkov/cfn-lint, ESLint) where relevant
- [ ] Anything pinned (Actions SHA, Node version, MiniStack digest, scanner versions) stays pinned
- [ ] No out-of-scope or unrelated changes

## Notes

<!-- Anything reviewers should know: trade-offs, follow-ups, environment caveats. -->
