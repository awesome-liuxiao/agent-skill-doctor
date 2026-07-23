# Verified installation and updates

## Python source preview

The public alpha can be installed into an isolated Python 3.12 environment directly from an exact
Git tag:

```console
uv tool install git+https://github.com/awesome-liuxiao/agent-skill-doctor.git@v0.1.0a1
```

```console
pipx install git+https://github.com/awesome-liuxiao/agent-skill-doctor.git@v0.1.0a1
```

For evaluation before the first preview tag exists, replace the tag with `main`. A branch install is
mutable and must not be treated as a reproducible deployment. The Python preview is distinct from
the signed standalone bundles below: it does not claim the protected stable-release evidence or
standalone artifact identity.

## Wrapper skills from GitHub

The thin wrappers are repository-native Agent Skills and require explicit invocation:

- Codex: `wrappers/codex/skill-doctor`
- Claude Code: `wrappers/claude/skill-doctor`

Install that directory through the platform's GitHub skill-install flow. The wrapper never
downloads or executes a backend by itself.

## Standalone backend without Python

Tagged releases contain one-file Windows amd64, macOS arm64, and Linux amd64 executables. The
repository installers require GitHub CLI because `gh attestation verify` establishes the exact
release workflow and tag identity for both the checksum manifest and executable before the
executable is copied or run:

```powershell
./install.ps1 -Repository OWNER/agent-skill-doctor -Version vX.Y.Z
```

```console
./install.sh OWNER/agent-skill-doctor vX.Y.Z
```

The verifier rejects other signer workflows, other source refs, and self-hosted-runner
attestations. If the verifier, either attestation, platform bundle, or checksum is unavailable,
installation stops.
The script then runs `skill-doctor readiness --deep`; Python is not required on the user host.

## First-use sandbox bootstrap

Native/container runner assets use a separate signed bootstrap manifest and exact host target.
The first invocation only verifies and previews the manifest, asset URLs, total bytes, checksums,
key ID, and approval token:

```console
skill-doctor bootstrap signed-bootstrap.json --json
skill-doctor bootstrap signed-bootstrap.json --approve PLAN_TOKEN --json
```

The installer downloads credential-free HTTPS assets, verifies the signed manifest plus every
declared size and SHA-256 digest, and writes a receipt. Readiness reverifies installed bytes.
Unverified assets are never executed through this path.

## Signed declarative rule packs

The embedded offline baseline is always available when no external pack is active. Inspect and
install a pack with a two-step verified plan:

```console
skill-doctor rules plan signed-rules.json --json
skill-doctor rules install signed-rules.json --approve PLAN_TOKEN --json
skill-doctor rules status --json
skill-doctor rules pin RULESET_VERSION
skill-doctor rules rollback
```

Automatic updates are off until a credential-free HTTPS feed receives endpoint-bound approval:

```console
skill-doctor rules configure-auto https://updates.example/rules.json --json
skill-doctor rules configure-auto https://updates.example/rules.json --approve PLAN_TOKEN --json
skill-doctor rules disable-auto
```

Approved feeds are checked no more than once per 24 hours. Only a valid, unexpired Ed25519
envelope can activate. A pin blocks a different version; the latest ten verified states are kept
for rollback.
