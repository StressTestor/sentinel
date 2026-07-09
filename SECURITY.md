# security policy

sentinel is a security tool, so bugs here are worse than usual. if you can bypass a BLOCK rule, escape the policy engine, or make the hook fail open, i want to know.

## supported versions

| version | supported |
|---------|-----------|
| latest release on crates.io | yes |
| anything older | no, upgrade first |

## reporting a vulnerability

use [github private vulnerability reporting](https://github.com/StressTestor/sentinel/security/advisories/new). don't open a public issue for exploitable stuff.

what helps:

- a working repro. the exact tool call or command that gets past the policy, and what you expected sentinel to do with it.
- your policy.toml if it's not the default.
- `sentinel doctor` output.

what to expect:

- acknowledgment within 72 hours.
- known bypass classes are documented in the README under ["supply-chain hardening (and what it can't do)"](README.md#supply-chain-hardening-and-what-it-cant-do). check there first, it might be a known and accepted limit rather than a new hole.
- if it's real, you get credit in the changelog and the fix ships as fast as the test suite allows.

## scope notes

- sentinel is deny-list runtime defense, not a sandbox. things it explicitly does not claim to stop are documented, and reports about those are appreciated but may be closed as known limits.
- version disclosure or missing-header style reports don't apply here. demonstrated policy bypass with impact is the bar.
