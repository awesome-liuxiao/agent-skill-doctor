# Public-preview launch kit

## One-sentence pitch

Agent Skill Doctor finds broken and risky Codex or Claude Code skills locally, links every finding
to evidence, and never silently executes or rewrites the skill.

## Show HN draft

**Title:** Show HN: Agent Skill Doctor – local static analysis for Codex and Claude skills

I built Agent Skill Doctor after repeatedly seeing agent-skill failures where the symptom was
obvious but the cause was not. A skill may have a broken reference, an unsafe command, a trigger
mismatch, or no relationship to the failure at all.

The development preview snapshots a local skill, runs deterministic checks without executing skill
content, and produces terminal, JSON, HTML, SARIF, and JUnit reports. Every finding keeps evidence,
confidence, severity, and completed coverage separate. Dynamic reproduction exists, but it is a
separate two-step flow that fails closed without an approved plan and attested sandbox.

The fastest demo uses the deliberately broken example in the repository. I am especially looking
for feedback from people maintaining real Codex or Claude Code skills. This is an alpha—not a claim
of stable safety—and the README lists the external evidence still missing.

## Short social post

Agent skills can fail because of broken references, unsafe commands, trigger mismatches, or causes
outside the skill entirely. Agent Skill Doctor checks them locally, links findings to evidence, and
does not silently execute or rewrite anything. Public static-analysis alpha:
https://github.com/awesome-liuxiao/agent-skill-doctor

## Community post

I am looking for maintainers of Codex and Claude Code skills to test a local-first diagnostic tool.
The current alpha focuses on deterministic static checks and produces evidence-linked reports. It
does not require uploading skills, prompts, or traces. If you can try it against a skill you are
authorized to inspect, I would value feedback on false positives, missing checks, and installation
friction. Please use the repository Discussion rather than sharing private skill content.

## Technical article

The repository includes a complete, publishable article:
[Why agent skills fail in surprising ways](WHY_AGENT_SKILLS_FAIL.md). When adapting it for another
platform, keep the alpha limitations and benchmark caveats intact and link back to the tagged
preview rather than copying only the positive results.

## Launch checklist

- Confirm the public CI badge is green.
- Confirm the demo and one-command install from a clean environment.
- Link the custom social-preview image.
- Publish the GitHub prerelease and release notes.
- Open the design-partner Discussion.
- Submit tailored posts; do not coordinate votes or duplicate identical copy across communities.
- Stay available for questions and fixes during the first 48 hours.
- Track release downloads, successful design-partner reports, and external contributors—not stars
  alone.
