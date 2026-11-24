#!/bin/bash
# Prints the Gradle flags that point this build at an mls-kmp checkout, or nothing.
#
# The same as quartz-args.sh, for mls-kmp: while the mls-kmp release this library pins (mlsKmp in
# gradle/libs.versions.toml) is not out yet (on Maven Central up to 1.3.0, on Nostr + Blossom from
# 1.3.1, where its GitHub tag marks it), a build uses the checkout at
# $MLS_KMP_DIR, else ../mls-kmp beside this repo, else (in CI, when $MLS_KMP_CLONE_TO is set) a
# fresh clone of vitorpamplona/mls-kmp at $MLS_KMP_REF (default main). Once the release is
# published this prints nothing and the build uses the artifact, with no edit needed here.
# A tag is a quick sign for builds; the release gate (create-release.yml) does not trust it and
# runs `./gradlew verifyDependenciesPublished`, which resolves the pinned version through Magpie.
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
version="$(sed -n 's/^mlsKmp = "\(.*\)"/\1/p' "$root/gradle/libs.versions.toml")"
pom="https://repo1.maven.org/maven2/com/vitorpamplona/mls/mls/$version/mls-$version.pom"

release="https://github.com/vitorpamplona/mls-kmp/releases/tag/v$version"
if curl -fsI "$pom" >/dev/null 2>&1 || curl -fsIL "$release" >/dev/null 2>&1; then
  exit 0
fi

dir="${MLS_KMP_DIR:-$root/../mls-kmp}"
if [ ! -f "$dir/settings.gradle.kts" ] && [ -n "${MLS_KMP_CLONE_TO:-}" ]; then
  dir="$MLS_KMP_CLONE_TO"
  git clone --quiet --depth 1 --branch "${MLS_KMP_REF:-main}" https://github.com/vitorpamplona/mls-kmp.git "$dir" >&2
fi

if [ ! -f "$dir/settings.gradle.kts" ]; then
  echo "mls-kmp $version is not released and there is no checkout at $dir." >&2
  echo "Clone vitorpamplona/mls-kmp beside this repo, or set MLS_KMP_DIR." >&2
  exit 1
fi

echo "mls-kmp $version is not released yet; building against $dir" >&2
echo "-PmlsKmpDir=$(cd "$dir" && pwd)"
