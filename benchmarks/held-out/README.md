# Rotating held-out corpus

No held-out case is stored in this repository. Stable release evaluation uses a protected
GitHub environment and the `protected-held-out-evaluation` workflow.

The environment secret `HELD_OUT_CORPUS_TAR_GZ_B64` contains a base64-encoded gzip tar
archive. Its root contains `manifest.json` plus case and license files. The manifest uses
`schemas/benchmark.schema.json`, its `corpus_version` begins with `held-out-`, and its case
IDs must not overlap the public manifest. Archives are limited to 100 MB and 10,000 regular
files/directories; absolute paths, traversal, links, devices, and special files are rejected.
GitHub’s individual secret limit also applies, so larger corpora should be split or supplied
by an equivalently protected artifact-fetch step after security review.

For every stable candidate:

1. Rotate at least part of the benign and defect cases and assign a new rotation ID.
2. Review origin, redistribution license, mutation history, expected rules, and expected
   coverage without exposing the cases to the implementation authors.
3. Run the held-out workflow against the exact proposed release ref and release version.
4. Preserve the successful run ID for the stable-release workflow.
5. Let the stable workflow verify the result’s GitHub attestation, signer workflow, and
   source commit. Never set the attestation flag based on an unverified JSON file.

The published result contains aggregate ratios, count, rotation metadata, and a SHA-256
commitment to sorted private case IDs. It contains no prompts, skill bodies, paths, findings,
or generated tests.
