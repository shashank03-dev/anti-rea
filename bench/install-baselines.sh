#!/usr/bin/env bash
# Installs the three baseline scanners used by the benchmark into bench/.tools/
# (gitignored; nothing is installed system-wide). Review before running.
#
#   gitleaks 8.30.1     official GitHub release, SHA-256 verified against the publisher's checksums file
#   trufflehog 3.99.8   official GitHub release, SHA-256 verified against the publisher's checksums file
#   detect-secrets 1.5.0  PyPI, into a private virtualenv
#
# Requires: gh (authenticated), python3, shasum. macOS arm64 asset names; adjust for other platforms.
set -euo pipefail
cd "$(dirname "$0")"
T=.tools
mkdir -p "$T/bin" "$T/dl-gitleaks" "$T/dl-trufflehog"

gh release download v8.30.1 -R gitleaks/gitleaks \
  -p 'gitleaks_8.30.1_darwin_arm64.tar.gz' -p 'gitleaks_8.30.1_checksums.txt' -D "$T/dl-gitleaks" --clobber
gh release download v3.99.8 -R trufflesecurity/trufflehog \
  -p 'trufflehog_3.99.8_darwin_arm64.tar.gz' -p 'trufflehog_3.99.8_checksums.txt' -D "$T/dl-trufflehog" --clobber

(cd "$T/dl-gitleaks" && grep ' gitleaks_8.30.1_darwin_arm64.tar.gz$' gitleaks_8.30.1_checksums.txt | shasum -a 256 -c -)
(cd "$T/dl-trufflehog" && grep ' trufflehog_3.99.8_darwin_arm64.tar.gz$' trufflehog_3.99.8_checksums.txt | shasum -a 256 -c -)

tar -xzf "$T/dl-gitleaks/gitleaks_8.30.1_darwin_arm64.tar.gz" -C "$T/bin" gitleaks
tar -xzf "$T/dl-trufflehog/trufflehog_3.99.8_darwin_arm64.tar.gz" -C "$T/bin" trufflehog

python3 -m venv "$T/venv"
"$T/venv/bin/pip" install --disable-pip-version-check -q 'detect-secrets==1.5.0'

"$T/bin/gitleaks" version
"$T/bin/trufflehog" --version
"$T/venv/bin/detect-secrets" --version
echo "baselines installed under bench/$T"
