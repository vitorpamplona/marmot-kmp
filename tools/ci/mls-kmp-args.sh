#!/bin/bash
# Prints the Gradle flags that point this build at an mls-kmp checkout, or nothing.
#
# The same as quartz-args.sh, for mls-kmp: while the mls-kmp release this library pins (mlsKmp in
# gradle/libs.versions.toml) is not on Maven Central yet, a build uses the checkout at
# $MLS_KMP_DIR, else ../mls-kmp beside this repo, else (in CI, when $MLS_KMP_CLONE_TO is set) a
# fresh clone of vitorpamplona/mls-kmp at $MLS_KMP_REF (default main). Once the release is
# published this prints nothing and the build uses the artifact, with no edit needed here.
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
version="$(sed -n 's/^mlsKmp = "\(.*\)"/\1/p' "$root/gradle/libs.versions.toml")"
pom="https://repo1.maven.org/maven2/com/vitorpamplona/mls/mls/$version/mls-$version.pom"

if curl -fsI "$pom" >/dev/null 2>&1; then
  exit 0
fi

dir="${MLS_KMP_DIR:-$root/../mls-kmp}"
if [ ! -f "$dir/settings.gradle.kts" ] && [ -n "${MLS_KMP_CLONE_TO:-}" ]; then
  dir="$MLS_KMP_CLONE_TO"
  git clone --quiet --depth 1 --branch "${MLS_KMP_REF:-main}" https://github.com/vitorpamplona/mls-kmp.git "$dir" >&2
fi

if [ ! -f "$dir/settings.gradle.kts" ]; then
  echo "mls-kmp $version is not on Maven Central and there is no checkout at $dir." >&2
  echo "Clone vitorpamplona/mls-kmp beside this repo, or set MLS_KMP_DIR." >&2
  exit 1
fi

echo "mls-kmp $version is not on Maven Central yet; building against $dir" >&2
echo "-PmlsKmpDir=$(cd "$dir" && pwd)"
