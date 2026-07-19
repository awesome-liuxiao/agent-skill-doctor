#!/bin/sh
set -eu
repository=${1:?usage: install.sh OWNER/REPOSITORY VERSION}
version=${2:?usage: install.sh OWNER/REPOSITORY VERSION}
printf '%s\n' "$repository" | grep -Eq '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$' || {
  echo "Repository must have the form OWNER/REPOSITORY." >&2
  exit 1
}
printf '%s\n' "$version" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9.-]+)?$' || {
  echo "Version must be an exact version tag." >&2
  exit 1
}
command -v gh >/dev/null 2>&1 || {
  echo "GitHub CLI is required to verify GitHub artifact attestations; nothing was installed." >&2
  exit 1
}
case "$(uname -s)-$(uname -m)" in
  Linux-x86_64) artifact=agent-skill-doctor-linux-amd64 ;;
  Darwin-arm64) artifact=agent-skill-doctor-macos-arm64 ;;
  *) echo "No signed standalone bundle is published for this host." >&2; exit 1 ;;
esac
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
gh release download "$version" --repo "$repository" --pattern "$artifact" --dir "$work"
gh release download "$version" --repo "$repository" --pattern "manifest-${artifact#agent-skill-doctor-}.json" --dir "$work"
binary="$work/$artifact"
manifest="$work/manifest-${artifact#agent-skill-doctor-}.json"
gh attestation verify "$manifest" --repo "$repository" \
  --signer-workflow "$repository/.github/workflows/release.yml" \
  --source-ref "refs/tags/$version" --deny-self-hosted-runners
expected=$(sed -n "/\"name\": \"$artifact\"/{n;s/.*\"sha256\": \"\([0-9a-f]*\)\".*/\1/p;}" "$manifest")
case "$expected" in *[!0-9a-f]*|'') echo "Release checksum manifest is invalid." >&2; exit 1;; esac
case "$(uname -s)" in Darwin) actual=$(shasum -a 256 "$binary" | awk '{print $1}') ;; *) actual=$(sha256sum "$binary" | awk '{print $1}') ;; esac
[ "$actual" = "$expected" ] || { echo "Release checksum verification failed." >&2; exit 1; }
gh attestation verify "$binary" --repo "$repository" \
  --signer-workflow "$repository/.github/workflows/release.yml" \
  --source-ref "refs/tags/$version" --deny-self-hosted-runners
target="${XDG_BIN_HOME:-$HOME/.local/bin}"
install -d -m 700 "$target"
install -m 700 "$binary" "$target/skill-doctor"
"$target/skill-doctor" readiness --deep
