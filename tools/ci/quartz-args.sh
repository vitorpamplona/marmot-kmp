#!/bin/bash
# Prints the Gradle flags that point this build at a Quartz checkout, or nothing.
#
# This library pins a Quartz release (quartzKmp in gradle/libs.versions.toml). Since 2.19.0 Quartz
# releases on Nostr + Blossom through Magpie, and a release this build already resolved is pinned in
# gradle/magpie.lock; older releases are on Maven Central. While the pinned release is in neither,
# a build has to use a checkout instead: the one at
# $QUARTZ_DIR, else ../quartz beside this repo, else (in CI, when $QUARTZ_CLONE_TO is set) a
# fresh clone of vitorpamplona/quartz at $QUARTZ_REF (default main). Once the release is
# published (and, for a Magpie release, locked) this prints nothing and the build uses the artifact.
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
version="$(sed -n 's/^quartzKmp = "\(.*\)"/\1/p' "$root/gradle/libs.versions.toml")"
pom="https://repo1.maven.org/maven2/com/vitorpamplona/quartz/quartz/$version/quartz-$version.pom"

if grep -q "^release com.vitorpamplona.quartz:quartz:$version " "$root/gradle/magpie.lock" 2>/dev/null; then
  exit 0
fi

if curl -fsI "$pom" >/dev/null 2>&1; then
  exit 0
fi

dir="${QUARTZ_DIR:-$root/../quartz}"
if [ ! -f "$dir/settings.gradle.kts" ] && [ -n "${QUARTZ_CLONE_TO:-}" ]; then
  dir="$QUARTZ_CLONE_TO"
  git clone --quiet --depth 1 --branch "${QUARTZ_REF:-main}" https://github.com/vitorpamplona/quartz.git "$dir" >&2
fi

if [ ! -f "$dir/settings.gradle.kts" ]; then
  echo "Quartz $version is neither in gradle/magpie.lock nor on Maven Central, and there is no checkout at $dir." >&2
  echo "Clone vitorpamplona/quartz beside this repo, or set QUARTZ_DIR." >&2
  exit 1
fi

echo "Quartz $version is not in gradle/magpie.lock or on Maven Central yet; building against $dir" >&2
echo "-PquartzDir=$(cd "$dir" && pwd)"
