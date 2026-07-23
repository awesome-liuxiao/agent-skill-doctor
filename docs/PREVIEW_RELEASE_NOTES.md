# Agent Skill Doctor 0.1.0a1

This is the first public static-analysis alpha. It is intended for evaluation and design-partner
feedback, not production safety certification.

## Try it

```console
uv tool install git+https://github.com/awesome-liuxiao/agent-skill-doctor.git@v0.1.0a1
skill-doctor check path/to/skill
```

Or install the attached wheel in an isolated Python 3.12 environment after verifying its GitHub
artifact attestation.

## Included

- bounded local snapshots and deterministic static checks;
- Codex and Claude Code skill discovery;
- evidence-linked terminal, JSON, HTML, SARIF, and JUnit reports;
- advisory-only remediations and explicit limitations;
- reusable GitHub Action and deliberately broken demo skill.

## Not claimed

This alpha does not satisfy the independent three-platform, rotating held-out, private
design-partner, remediation-period, public-preview, or protected release-evidence gates required
for stable v1. Signed standalone executables remain reserved for the stable gated workflow.

See [Roadmap status](https://github.com/awesome-liuxiao/agent-skill-doctor/blob/v0.1.0a1/docs/ROADMAP_STATUS.md)
for the complete limitations.
