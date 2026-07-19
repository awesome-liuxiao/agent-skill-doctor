# Reproducible release builds

Release inputs are declared in `release-toolchain.json`. Builds use Python 3.12, the exact
transitive tool environment in `requirements-release.lock`, `PYTHONHASHSEED=0`, and a mandatory
`SOURCE_DATE_EPOCH`. The same source revision is built independently on GitHub-hosted Windows,
macOS, and Linux runners because native one-file executables are platform-specific.

To reproduce one host artifact:

1. Check out the exact signed release tag in a clean environment.
2. Install `requirements-dev.lock`, then install `requirements-release.lock` with `--no-deps`
   and run `pip check`. This prevents an unpinned transitive release tool from being resolved.
3. Set `SOURCE_DATE_EPOCH` to the release workflow value and `PYTHONHASHSEED=0`.
4. Run `python scripts/build_standalone.py --output dist/PLATFORM --name
   agent-skill-doctor-PLATFORM`.
5. Generate the SBOM and run `scripts/release_manifest.py` exactly as the workflow does.
6. Compare the executable and manifest SHA-256 values. Native loader metadata may vary when a
   platform signing service adds its signature; verify the published provenance and unsigned
   payload digest in that case.

The release workflow runs formatting, linting, strict typing, tests, and dependency checks before
building. It publishes the standalone executable, SHA-256 manifest, CycloneDX SBOM, Sigstore
signature/certificate, and GitHub artifact provenance. Release publication is gated on all three
host builds.
