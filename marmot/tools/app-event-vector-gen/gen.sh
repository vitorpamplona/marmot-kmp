#!/usr/bin/env bash
#
# Regenerates marmot/src/commonTest/resources/marmot/app-events/*.json: the app events
# (the unsigned rumors inside a group) White Noise sends, and the ones marmot-kmp's
# builders send, each with what MDK made of it. See README.md next to this script.
#
#   WN_BIN_DIR=…/mdk-bin   # wn + wnd release binaries (MDK version in MDK_VERSION)
#   AMY=…/amethyst/cli/build/install/amy/bin/amy
#   BLOSSOM_PY=…/amethyst/cli/tests/marmot/blossom-server.py
#   ./gradlew :marmot:jvmJar && marmot/tools/app-event-vector-gen/gen.sh
#
# Everything runs on loopback: one relay (`amy serve`), one Blossom, one wnd.
set -uo pipefail
GEN_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd -- "$GEN_DIR/../../.." && pwd)"
OUT_DIR=${OUT_DIR:-$REPO/marmot/src/commonTest/resources/marmot/app-events}
MDK_VERSION=${MDK_VERSION:-0.19.0}
MARMOT_JAR=${MARMOT_JAR:-$REPO/marmot/build/libs/marmot-jvm.jar}
# shellcheck source=env.sh
source "$GEN_DIR/env.sh"
set -e
AMY_LIB=${AMY_LIB:-$(cd -- "$(dirname -- "$AMY")/../lib" && pwd)}
trap stop_all EXIT
: >"$LOG"
log "work dir $WORK"

[[ -f "$MARMOT_JAR" ]] || die "no $MARMOT_JAR; run ./gradlew :marmot:jvmJar first"

# --- the injector: Inject.kt against amy's classpath, this checkout's marmot first ---
KOTLINC_JARS=${KOTLINC_JARS:-}
if [[ -z "$KOTLINC_JARS" ]]; then
  G=$HOME/.gradle/caches/modules-2/files-2.1/org.jetbrains.kotlin
  KV=$(basename "$(ls "$AMY_LIB"/kotlin-stdlib-2*.jar | head -n1)" .jar); KV=${KV#kotlin-stdlib-}
  for a in kotlin-compiler-embeddable kotlin-daemon-embeddable kotlin-script-runtime; do
    j=$(ls "$G/$a/$KV"/*/"$a-$KV.jar" 2>/dev/null | head -n1)
    [[ -n "$j" ]] || die "no $a $KV in the Gradle cache; set KOTLINC_JARS"
    KOTLINC_JARS+="$j:"
  done
  KOTLINC_JARS+=$(ls "$AMY_LIB"/kotlin-stdlib-2*.jar "$AMY_LIB"/kotlin-reflect-*.jar "$AMY_LIB"/kotlinx-coroutines-core-jvm-*.jar "$AMY_LIB"/annotations-*.jar | tr '\n' ':')
fi
RUN_CP="$MARMOT_JAR:$(ls "$AMY_LIB"/*.jar | grep -v '/marmot-jvm' | tr '\n' ':')"
mkdir -p "$WORK/inject"
java -cp "$KOTLINC_JARS" org.jetbrains.kotlin.cli.jvm.K2JVMCompiler -no-stdlib -no-reflect -jvm-target 21 \
  -cp "$RUN_CP" "$GEN_DIR/Inject.kt" -d "$WORK/inject" >>"$LOG" 2>&1 || die "Inject.kt did not compile (see $LOG)"
inject() { HOME="$A_HOME" java -cp "$WORK/inject:$RUN_CP" InjectKt "$@" 2>>"$LOG"; }

STEPS="$WORK/steps.jsonl"
: >"$STEPS"
# theirs NAME CMD… : run a wn verb as B, record the inner event id it reports.
theirs() {
  local name="$1"; shift
  local out id
  out=$(wn_b "$@") || die "wn $* failed: $out"
  id=$(printf '%s' "$out" | jq -r '.result.message_ids[0] // .result.sent.message_ids[0] // empty')
  [[ -n "$id" ]] || die "wn $* reported no message id: $out"
  jq -nc --arg n "$name" --arg id "$id" --arg cmd "wn $*" '{side:"theirs",name:$n,id:$id,command:$cmd}' >>"$STEPS"
  log "theirs $name -> $id"
  printf '%s' "$id"
}
# ours NAME SPEC_JSON : build with marmot-kmp, send as A, record the rumor.
ours() {
  local name="$1" spec="$2" rumor
  rumor=$(inject send "$GID" "$spec") || die "inject $name failed (see $LOG)"
  jq -nc --arg n "$name" --argjson spec "$spec" --argjson r "$rumor" '{side:"ours",name:$n,id:$r.id,spec:$spec,rumor:$r}' >>"$STEPS"
  log "ours $name -> $(printf '%s' "$rumor" | jq -r .id)"
  printf '%s' "$rumor"
}
# ours_cli NAME CMD… : an amy verb whose rumor marmot-kmp builds inside amy (media).
ours_cli() {
  local name="$1"; shift
  local out id
  out=$(amy_a "$@") || die "amy $* failed: $out"
  id=$(printf '%s' "$out" | jq -r '.inner_event_id // empty')
  [[ -n "$id" ]] || die "amy $* reported no inner event id: $out"
  jq -nc --arg n "$name" --arg id "$id" --arg cmd "amy $*" '{side:"ours",name:$n,id:$id,command:$cmd}' >>"$STEPS"
  log "ours $name -> $id"
  printf '%s' "$id"
}
rumor_of() { jq -c --arg id "$1" 'select(.id == $id)' "$WORK/a-dump.jsonl" | head -n1; }
# png FILE W H BLUE : a small RGB PNG, different bytes per call so media hashes differ.
png() {
  python3 -I -c 'import struct,zlib,sys
w,h,b=int(sys.argv[1]),int(sys.argv[2]),int(sys.argv[3])
raw=b"".join(b"\x00"+b"".join(bytes([x*16%256,y*32%256,b]) for x in range(w)) for y in range(h))
def ch(t,d): return struct.pack(">I",len(d))+t+d+struct.pack(">I",zlib.crc32(t+d)&0xffffffff)
sys.stdout.buffer.write(b"\x89PNG\r\n\x1a\n"+ch(b"IHDR",struct.pack(">IIBBBBB",w,h,8,2,0,0,0))+ch(b"IDAT",zlib.compress(raw))+ch(b"IEND",b""))' "$2" "$3" "$4" >"$1"
}
b_sync() { wn_b sync >/dev/null || true; sleep 1; }
a_sync() { amy_a marmot message list "$GID" --limit 1 >/dev/null || true; }

# --- network, identities, group ---------------------------------------------
start_relay
start_blossom
start_wnd
out=$(wn_b create-identity) || die "wn create-identity"
B_NPUB=$(printf '%s' "$out" | jq -r .result.npub); B_HEX=$(printf '%s' "$out" | jq -r .result.account_id)
out=$(amy_a init) || die "amy init"
A_NPUB=$(printf '%s' "$out" | jq -r .npub); A_HEX=$(printf '%s' "$out" | jq -r .hex)
amy_a relay add "$RELAY_URL" >/dev/null || die "amy relay add"
amy_a relay publish-lists >/dev/null || die "amy publish-lists"
amy_a marmot key-package publish >/dev/null || die "amy key-package"
sleep 1
out=$(wn_b groups create "App event vectors" "$A_NPUB") || die "wn groups create: $out"
MG=$(printf '%s' "$out" | jq -r .result.group_id)
out=$(amy_a marmot await group --timeout 90) || die "A never joined: $out"
GID=$(printf '%s' "$out" | jq -r .group_id)
log "group mls=$MG nostr=$GID A=$A_HEX B=$B_HEX"
wn_b groups promote "$MG" "$A_NPUB" >/dev/null || die "promote A"
a_sync
# Media goes to the loopback Blossom only: replace the group's default (public) endpoints.
amy_a marmot media set-policy "$GID" "$BLOSSOM_URL/" >/dev/null || die "media set-policy"
b_sync

# --- THEIRS: what White Noise sends -------------------------------------------
T_TEXT=$(theirs text messages send "$MG" "plain text from White Noise")
T_MENTION=$(theirs mention-nostr-uri messages send "$MG" "hello nostr:$A_NPUB, welcome")
T_MENTION_BARE=$(theirs mention-bare-npub messages send "$MG" "ping @$A_NPUB")
T_REPLY=$(theirs reply messages send --group "$MG" --reply-to "$T_TEXT" "a reply from White Noise")
theirs react-plus messages react "$MG" "$T_TEXT" >/dev/null
theirs react-minus messages react "$MG" "$T_MENTION" "-" >/dev/null
T_REACT_EMOJI=$(theirs react-emoji messages react "$MG" "$T_REPLY" "🎉")
theirs edit messages edit "$MG" "$T_TEXT" "plain text from White Noise, edited" >/dev/null
theirs unreact messages unreact "$MG" "$T_REPLY" >/dev/null
T_REMOVE=$(theirs remove-target messages send "$MG" "Amethyst (an admin) will remove this")
T_DOOMED=$(theirs delete-target messages send "$MG" "White Noise will delete this (as an admin)")
theirs delete-own-as-admin messages delete "$MG" "$T_DOOMED" >/dev/null
png "$WORK/pic-wn.png" 16 8 128
T_MEDIA=$(theirs media media upload "$MG" "$WORK/pic-wn.png" --send --message "a picture from White Noise")

# --- OURS: what marmot-kmp's builders send ------------------------------------
inject dump "$GID" >"$WORK/a-dump.jsonl" || die "inject dump"
for id in "$T_TEXT" "$T_MENTION" "$T_REPLY" "$T_MEDIA"; do [[ -n "$(rumor_of "$id")" ]] || die "A never received $id"; done
TEXT_R=$(rumor_of "$T_TEXT"); MENTION_R=$(rumor_of "$T_MENTION"); REPLY_R=$(rumor_of "$T_REPLY")
O_TEXT=$(ours text '{"op":"text","text":"plain text from Amethyst"}')
O_TEXT_ID=$(printf '%s' "$O_TEXT" | jq -r .id)
O_MENTION=$(ours mention "$(jq -nc --arg t "hi nostr:$B_NPUB" --arg p "$B_HEX" '{op:"text",text:$t,mentions:[$p]}')")
ours mention-content-only "$(jq -nc --arg t "hi nostr:$B_NPUB, no p tag" '{op:"raw",kind:9,tags:[],content:$t}')" >/dev/null
ours reply "$(jq -nc --argjson t "$TEXT_R" '{op:"reply",text:"a reply from Amethyst",target:$t}')" >/dev/null
ours reply-e-only "$(jq -nc --arg e "$T_TEXT" '{op:"raw",kind:9,tags:[["e",$e]],content:"reply naming its parent with e only"}')" >/dev/null
ours reply-q-only "$(jq -nc --arg q "$T_TEXT" '{op:"raw",kind:9,tags:[["q",$q]],content:"reply naming its parent with q only"}')" >/dev/null
ours reply-q-and-e-differ "$(jq -nc --arg q "$T_TEXT" --arg e "$T_MENTION" '{op:"raw",kind:9,tags:[["e",$e],["q",$q]],content:"e names one message, q another"}')" >/dev/null
ours reply-q-address "$(jq -nc --arg a "30023:$B_HEX:an-article" '{op:"raw",kind:9,tags:[["q",$a]],content:"quotes an addressable event"}')" >/dev/null
ours react-plus "$(jq -nc --argjson t "$TEXT_R" '{op:"react",target:$t,reaction:"+"}')" >/dev/null
ours react-minus "$(jq -nc --argjson t "$MENTION_R" '{op:"react",target:$t,reaction:"-"}')" >/dev/null
O_REACT_EMOJI=$(ours react-emoji "$(jq -nc --argjson t "$REPLY_R" '{op:"react",target:$t,reaction:"🔥"}')")
ours react-custom-emoji "$(jq -nc --argjson t "$REPLY_R" --arg u "$BLOSSOM_URL/party.png" '{op:"react",target:$t,reaction:(":party:" + $u)}')" >/dev/null
ours edit "$(jq -nc --arg id "$O_TEXT_ID" '{op:"edit",target_id:$id,text:"plain text from Amethyst, edited"}')" >/dev/null
ours edit-foreign "$(jq -nc --arg id "$T_REPLY" '{op:"edit",target_id:$id,text:"Amethyst rewrites White Noise"}')" >/dev/null
ours delete-own "$(jq -nc --argjson t "$O_MENTION" '{op:"delete",targets:[$t]}')" >/dev/null
ours unreact "$(jq -nc --argjson t "$O_REACT_EMOJI" '{op:"delete",targets:[$t]}')" >/dev/null
ours delete-foreign-kind5 "$(jq -nc --arg e "$T_MENTION_BARE" '{op:"raw",kind:5,tags:[["e",$e]],content:""}')" >/dev/null
ours remove-as-admin "$(jq -nc --arg id "$T_REMOVE" '{op:"remove",target_id:$id}')" >/dev/null
ENDS=$(( $(date +%s) + 86400 ))
P_SINGLE=$(ours poll-single "$(jq -nc --argjson e "$ENDS" '{op:"poll",question:"Lunch?",options:["Pizza","Sushi","Tacos"],multiple:false,ends_at:$e}')")
P_MULTI=$(ours poll-multiple '{"op":"poll","question":"Which days work?","options":["Mon","Tue","Wed","Thu"],"multiple":true}')
ours vote-single "$(jq -nc --argjson p "$P_SINGLE" '{op:"vote",poll:$p,option_ids:["1"]}')" >/dev/null
ours vote-multiple "$(jq -nc --argjson p "$P_MULTI" '{op:"vote",poll:$p,option_ids:["0","2"]}')" >/dev/null
ours vote-unknown-option "$(jq -nc --argjson p "$P_SINGLE" '{op:"vote",poll:$p,option_ids:["7"],raw:true}')" >/dev/null
ours vote-two-on-single "$(jq -nc --argjson p "$P_SINGLE" '{op:"vote",poll:$p,option_ids:["0","2"],raw:true}')" >/dev/null
png "$WORK/pic-amy.png" 12 6 32
O_MEDIA=$(ours_cli media marmot media send "$GID" "$WORK/pic-amy.png" --caption "a picture from Amethyst" --mime image/png)
inject dump "$GID" >"$WORK/a-dump.jsonl" || die "inject dump"
# The same attachment with a blurhash field, which encrypted-media-v2 does not define.
O_MEDIA_R=$(rumor_of "$O_MEDIA")
ours media-with-blurhash "$(printf '%s' "$O_MEDIA_R" | jq -c '{op:"raw",kind:9,content:"the same picture, its imeta adds a blurhash",tags:[.tags[] | select(.[0]=="imeta") | . + ["blurhash LEHV6nWB2yk8pyo0adR*.7kCMdnj"]]}')" >/dev/null

# --- White Noise without admin rights deletes its own message with a kind 5 ----
b_sync
wn_b groups self-demote "$MG" >/dev/null || die "self-demote"
a_sync
T_DOOMED2=$(theirs delete-target-2 messages send "$MG" "White Noise will delete this (not an admin)")
theirs delete-own messages delete "$MG" "$T_DOOMED2" >/dev/null

# --- capture what each side holds ----------------------------------------------
sleep 2; b_sync
inject dump "$GID" >"$WORK/a-dump.jsonl" || die "inject dump"
wn_b messages list "$MG" --limit 500 >"$WORK/wn-messages.json" || die "wn messages list"
wn_b messages timeline list "$MG" --limit 500 >"$WORK/wn-timeline.json" || die "wn timeline list"
wn_b media list "$MG" >"$WORK/wn-media.json" || die "wn media list"
# Can each side open the other's attachment? wn by plaintext hash, amy by event id.
: >"$WORK/downloads.jsonl"
for h in $(jq -r '.result.media[]?.plaintext_sha256 // empty' "$WORK/wn-media.json" | sort -u); do
  if wn_b media download "$MG" "$h" --output "$WORK/dl-$h" >/dev/null; then ok=true; else ok=false; fi
  jq -nc --arg h "$h" --argjson ok "$ok" '{by:"wn",plaintext_sha256:$h,ok:$ok}' >>"$WORK/downloads.jsonl"
done
if amy_a marmot media get "$GID" "$T_MEDIA" --out "$WORK/dl-amy" >/dev/null; then ok=true; else ok=false; fi
jq -nc --arg id "$T_MEDIA" --argjson ok "$ok" '{by:"amy",event_id:$id,ok:$ok}' >>"$WORK/downloads.jsonl"
AMETHYST_SHA=${AMETHYST_SHA:-$(git -C "$(dirname "$AMY")" rev-parse --short HEAD 2>/dev/null || echo unknown)}
jq -n --arg a "$A_HEX" --arg b "$B_HEX" --arg mdk "$MDK_VERSION" --arg amy "$AMETHYST_SHA" \
  --arg marmot "$(grep '^VERSION_NAME=' "$REPO/gradle.properties" | cut -d= -f2) ($(git -C "$REPO" rev-parse --short HEAD 2>/dev/null || echo unknown))" \
  '{amethyst:$a,white_noise:$b,mdk:$mdk,amy:$amy,marmot_kmp:$marmot}' >"$WORK/meta.json"
python3 -I "$GEN_DIR/build_vectors.py" "$WORK" "$OUT_DIR" || die "build_vectors.py"
log "wrote vectors to $OUT_DIR"
