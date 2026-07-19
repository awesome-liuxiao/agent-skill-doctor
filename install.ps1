param(
  [Parameter(Mandatory=$true)][string]$Repository,
  [Parameter(Mandatory=$true)][string]$Version
)
$ErrorActionPreference = "Stop"
if ($Repository -notmatch '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$') {
  throw "Repository must have the form OWNER/REPOSITORY."
}
if ($Version -notmatch '^v[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9.-]+)?$') {
  throw "Version must be an exact version tag."
}
if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
  throw "GitHub CLI is required to verify GitHub artifact attestations; nothing was installed."
}
$work = Join-Path ([System.IO.Path]::GetTempPath()) ("skill-doctor-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $work | Out-Null
try {
  gh release download $Version --repo $Repository --pattern "agent-skill-doctor-windows-amd64.exe" --dir $work
  gh release download $Version --repo $Repository --pattern "manifest-windows-amd64.json" --dir $work
  $binary = Join-Path $work "agent-skill-doctor-windows-amd64.exe"
  $manifestPath = Join-Path $work "manifest-windows-amd64.json"
  gh attestation verify $manifestPath --repo $Repository `
    --signer-workflow "$Repository/.github/workflows/release.yml" `
    --source-ref "refs/tags/$Version" --deny-self-hosted-runners
  $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
  $entry = $manifest.artifacts | Where-Object { $_.name -eq "agent-skill-doctor-windows-amd64.exe" }
  if ($null -eq $entry -or $entry.sha256 -ne (Get-FileHash -Algorithm SHA256 -LiteralPath $binary).Hash.ToLowerInvariant()) {
    throw "Release checksum verification failed; nothing was installed."
  }
  gh attestation verify $binary --repo $Repository `
    --signer-workflow "$Repository/.github/workflows/release.yml" `
    --source-ref "refs/tags/$Version" --deny-self-hosted-runners
  $target = Join-Path $env:LOCALAPPDATA "AgentSkillDoctor\bin"
  New-Item -ItemType Directory -Force -Path $target | Out-Null
  Copy-Item -LiteralPath $binary -Destination (Join-Path $target "skill-doctor.exe")
  & (Join-Path $target "skill-doctor.exe") readiness --deep
} finally {
  Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}
