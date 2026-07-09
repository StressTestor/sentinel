# contributing

thanks for looking at this. sentinel is small on purpose, so the bar for merging is quality, not volume.

## ground rules

- zero false positives on BLOCK rules. always. a rule that fires on legitimate dev work is a bug even if it also catches attacks. dual-use commands go to warn, not block.
- local and offline. no network calls, no telemetry, no cloud. CI enforces this (the AD-5 lint).
- honest docs. if a protection has a known bypass, we say so instead of overselling.

## workflow

1. fork, branch from `main` (`fix/short-desc` or `feat/short-desc`).
2. make the change. new rules and matcher changes need tests, including a negative test proving no false positive on the closest legitimate command.
3. run the gates locally before pushing:

```bash
cargo test
cargo clippy -- -D warnings
cargo run --quiet -- verify   # attack regression gate
bash scripts/ad5-network-lint.sh
```

4. conventional commit messages: `type(scope): description` in imperative mood. e.g. `fix(policy): match spaced credential paths`.
5. open a PR against `main`. describe the why, not just the what.

## reporting security issues

not in public issues. see [SECURITY.md](SECURITY.md).

## adding policy rules

deny rules live in the default policy. before proposing one, ask:

- can this fire on legitimate work? if yes, it's a warn, not a block.
- is there a test that proves the attack is caught AND a test that proves the nearest legit command passes?
- does it survive the de-obfuscation pass (quote stripping, interpolation)?

rules that fail any of these get bounced in review, so cheaper to check first.
