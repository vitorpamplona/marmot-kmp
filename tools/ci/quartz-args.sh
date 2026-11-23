#!/bin/bash
# Prints the Gradle flags that point this build at a Quartz checkout, or nothing.
#
# This library pins a Quartz release (quartzKmp in gradle/libs.versions.toml): on Maven Central up
# to 2.18.0, on Nostr + Blossom through Magpie from 2.19.0 (its GitHub release marks it; Quartz's
# release workflow publishes to Nostr from that tag). While that release is not out yet, a build
# has to use a checkout instead: the one at
# $QUARTZ_DIR, else ../quartz beside this repo, else (in CI, when $QUARTZ_CLONE_TO is set) a
# fresh clone of vitorpamplona/quartz at $QUARTZ_REF (default main). Once the release is
# published this prints nothing and the build uses the artifact, with no edit needed here.
# A tag is a quick sign for builds; the release gate (create-release.yml) does not trust it and
# runs `./gradlew verifyDependenciesPublished`, which resolves the pinned version through Magpie.
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
version="$(sed -n 's/^quartzKmp = "\(.*\)"/\1/p' "$root/gradle/libs.versions.toml")"
pom="https://repo1.maven.org/maven2/com/vitorpamplona/quartz/quartz/$version/quartz-$version.pom"

release="https://github.com/vitorpamplona/quartz/releases/tag/v$version"
if curl -fsI "$pom" >/dev/null 2>&1 || curl -fsIL "$release" >/dev/null 2>&1; then
  exit 0
fi

dir="${QUARTZ_DIR:-$root/../quartz}"
if [ ! -f "$dir/settings.gradle.kts" ] && [ -n "${QUARTZ_CLONE_TO:-}" ]; then
  dir="$QUARTZ_CLONE_TO"
  git clone --quiet --depth 1 --branch "${QUARTZ_REF:-main}" https://github.com/vitorpamplona/quartz.git "$dir" >&2
fi

if [ ! -f "$dir/settings.gradle.kts" ]; then
  echo "Quartz $version is not released and there is no checkout at $dir." >&2
  echo "Clone vitorpamplona/quartz beside this repo, or set QUARTZ_DIR." >&2
  exit 1
fi

echo "Quartz $version is not released yet; building against $dir" >&2
echo "-PquartzDir=$(cd "$dir" && pwd)"
