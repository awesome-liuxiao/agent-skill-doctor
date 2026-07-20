# Design-partner preview

Agent Skill Doctor is recruiting maintainers who author or operate real Codex or Claude Code skills
and can evaluate the local static-analysis path.

## What participation involves

1. Install the development preview on a supported Python 3.12 host.
2. Run static checks against skills you are authorized to inspect.
3. Review each highlighted finding against the cited evidence.
4. Report aggregate outcomes and sanitized reproductions through GitHub Discussions or issues.
5. Allow confirmed defects to be remediated before any public case study is proposed.

Dynamic reproduction is not required. It remains a separate two-step, approval-bound capability
and must not be enabled merely to participate in the preview.

## What not to share

Do not submit raw prompts, session transcripts, credentials, proprietary skill content, customer
names, private repository URLs, usernames, home directories, or identifying absolute paths. A
useful report normally needs only:

- host platform and Python version;
- skill platform (`codex` or `claude`);
- finding rule ID and result classification;
- whether the finding was correct, incorrect, or unclear;
- a synthetic minimal reproduction; and
- the completed and missing coverage shown in the report.

## Aggregate evidence

The protected release workflow accepts only aggregate partner counts, tested platform/runtime
combinations, issue references, remediation status, and sign-off. It does not accept raw partner
data as a release artifact. Participation does not guarantee public attribution.

To volunteer, open the **Design partner** Discussion form or use the general
[Discussions page](https://github.com/awesome-liuxiao/agent-skill-doctor/discussions).
