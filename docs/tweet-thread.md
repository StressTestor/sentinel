# sentinel launch tweet thread

6 posts. attach `docs/live-demo.gif` to tweet 3.

---

**1/6**

spent the weekend building a runtime defense layer for CLI AI agents.

reason: you can own a claude code agent with filesystem access using a single poisoned README.

not theoretically. i built the demo and filmed it.

---

**2/6**

20 prompt injections on one html page. html comments, zero-width unicode, white-on-white text, display:none divs, tiny-font spans, fake "agent instructions" blockquotes.

sentinel blocked every single one at the hook layer. no tool ever ran.

---

**3/6** *(attach `docs/live-demo.gif`)*

each entry in the gif is one thing the agent tried to run after parsing the page.

cat ~/.aws/credentials. read ~/.ssh/id_rsa. exfil /etc/passwd. pipe attacker.sh to bash. rm -rf your home.

twenty attempts. twenty BLOCKED.

---

**4/6**

how it works: sentinel hooks into claude code's PreToolUse system. intercepts every tool call. evaluates against a TOML policy in <1ms. returns deny before the tool runs.

tier 1 is deterministic rules. no LLM, no training, no magic.

---

**5/6**

install is two commands:

```
cargo install sentinel-guard
sentinel install
```

defaults to audit mode so you see what'd be blocked before enforcing. flip to enforce when you trust it. MIT/Apache, macos + linux.

---

**6/6**

test it yourself: point any CLI agent at stresstestor.github.io/sentinel/target.html with no defense running and watch what it tries to do.

then install sentinel and try it again.

repo: github.com/StressTestor/sentinel
