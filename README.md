# Portfolio

Three security tools, all of them built with coding agents. That is the thing they have in
common, and it is also the thing each one is designed to survive.

An agent will write a plausible detection query, a confident CVE verdict and a convincing
phishing lure without being able to tell you which of them is wrong. So the same pattern runs
through all three, deliberately:

- **The deterministic core works with no model at all.** Otter Shell's hunt library, ATT&CK
  coverage map, Sigma round-trip and KEV scan; PatchGuard's inventory, CPE matching and patch
  path; Decoy's detections, funnel and audit chain. AI is additive, and where it isn't configured
  the feature says so instead of falling back to something weaker.
- **Model output is re-validated, never returned on trust.** Decoy generates behind a
  server-pinned training-only prompt and *rejects* a lure containing a live URL rather than
  defanging it; PatchGuard's API key never enters the binary, and requests go through a proxy
  that pins the model and refuses `system` / `tools` overrides.
- **The tool never marks its own work validated.** Otter Shell's validation ladder is a level the
  *user* sets; PatchGuard renders **NOT SCANNED** and **KEV unavailable** rather than a green
  zero; Decoy's authorization gate wants a named approver, not a checkbox.

The agents wrote most of the implementation, the test suites, and the security-audit passes over
their own output. What I decided is the list above — which invariants hold, which failure
direction each tool is allowed to have, and what each write-up is *not* allowed to claim. Every
write-up ends with what has not been exercised, because a portfolio about tools that don't
overstate themselves cannot overstate itself either.

| Project | What it is |
|---|---|
| **[Otter Shell](otter-shell/)**<br/><sub>[source](https://github.com/LittleJeter/otter-shell)</sub> | A threat-hunt authoring and tracking console — drafts the hunt query for seven SIEM/EDR platforms at once, then tracks it through a lifecycle until someone has actually run it. Built so the tool cannot overstate itself: every query is labelled a starting point, validation is a level the user sets rather than the tool claims, and coverage is always reported alongside its gaps. |
| **[Decoy](decoy/)** | Security-awareness tooling for phishing simulations — writes the training lure, explains what gives it away, and turns it into deployable detections. Built so that misusing it takes deliberate effort: it cannot send, cannot receive a credential, and cannot emit a live URL. |
| **[PatchGuard Pro](patchguard/)**<br/><sub>source private</sub> | A desktop vulnerability scanner aimed at people who don't know what a CVE is — inventories installed software, checks it against NIST NVD and CISA's actively-exploited catalog, explains the risk in plain English and patches it through winget or Homebrew. A prototype, built around one rule — because a consumer tool has no expert user to catch its mistakes: an absence of data is never rendered as an assurance. |

Source availability, per project: **Otter Shell**'s repository is public and linked above.
**PatchGuard Pro**'s and **Decoy**'s are private — I'm happy to walk through either.
