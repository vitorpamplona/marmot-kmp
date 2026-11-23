#!/usr/bin/env python3
"""Turns one gen.sh capture into the app-event vector files.

    build_vectors.py WORK_DIR OUT_DIR

Reads, from WORK_DIR:
  steps.jsonl      one line per step: side (theirs/ours), name, id, and the wn command or the
                   marmot-kmp builder spec that produced it
  a-dump.jsonl     every rumor amy (account A, marmot-kmp) holds for the group, as received
  wn-timeline.json `wn messages timeline list`: MDK's materialized timeline (B's view)
  wn-media.json    `wn media list`: the attachments MDK accepted
  downloads.jsonl  whether each side decrypted the other's attachment
  meta.json        both members' pubkeys and the tool versions

Writes mdk-<version>-sent.json (White Noise sent, marmot-kmp reads) and
ours-read-by-mdk-<version>.json (marmot-kmp built, White Noise read). The format is in
README.md. `expect` is MDK's decision, taken from what wn showed wherever wn shows it
("basis": "observed") and from MDK's source where its CLI does not ("basis": "source").
"""
import json
import re
import sys
from pathlib import Path

WORK = Path(sys.argv[1])
OUT = Path(sys.argv[2])

meta = json.loads((WORK / "meta.json").read_text())
MDK = meta["mdk"]
steps = [json.loads(line) for line in (WORK / "steps.jsonl").read_text().splitlines() if line.strip()]
dump = [json.loads(line) for line in (WORK / "a-dump.jsonl").read_text().splitlines() if line.strip()]
timeline = json.loads((WORK / "wn-timeline.json").read_text())["result"]["messages"]
wn_media = json.loads((WORK / "wn-media.json").read_text())["result"]["media"]
downloads = [json.loads(line) for line in (WORK / "downloads.jsonl").read_text().splitlines() if line.strip()]

# The conversation: every app event both clients exchanged, minus what the clients make
# themselves (push-token gossip 447, system rows 1210 each client derives on its own).
LOCAL_KINDS = {447, 448, 449, 1210}
conversation = []
by_id = {}
for raw in dump:
    if raw["kind"] in LOCAL_KINDS:
        continue
    rumor = {k: raw[k] for k in ("id", "pubkey", "created_at", "kind", "tags", "content")}
    conversation.append(rumor)
    by_id[rumor["id"]] = rumor
rows = {m["message_id"]: m for m in timeline}
reactions_present = {r["reaction_message_id_hex"] for m in timeline for r in m["reactions"]["user_reactions"]}

# ---- MDK's mention rule (marmot-app notifications.rs message_text_mentions_account): a p tag,
# or an inline `nostr:npub1…` / `nostr:nprofile1…` / `@npub1…` in a chat message's text.
CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def bech32_data(s):
    hrp, _, data = s.rpartition("1")
    values = [CHARSET.index(c) for c in data[:-6]]
    acc, bits, out = 0, 0, []
    for v in values:
        acc = (acc << 5) | v
        bits += 5
        while bits >= 8:
            bits -= 8
            out.append((acc >> bits) & 0xFF)
    return hrp, bytes(out)


def inline_pubkey(entity):
    hrp, data = bech32_data(entity)
    if hrp == "npub":
        return data.hex()
    if hrp == "nprofile":
        i = 0
        while i + 2 <= len(data):
            t, n = data[i], data[i + 1]
            if t == 0 and n == 32:
                return data[i + 2:i + 34].hex()
            i += 2 + n
    return None


INLINE = re.compile(r"(?:nostr:|@)((?:npub|nprofile)1[" + CHARSET + r"]+)")
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def mentions(rumor):
    if rumor["kind"] != 9:
        return []
    found = {t[1] for t in rumor["tags"] if len(t) > 1 and t[0] == "p" and HEX64.match(t[1])}
    for m in INLINE.finditer(rumor["content"]):
        pk = inline_pubkey(m.group(1))
        if pk:
            found.add(pk)
    return sorted(found)


def first(tags, name):
    return next((t[1] for t in tags if len(t) > 1 and t[0] == name), None)


def row_view(row):
    """The part of an MDK timeline row a vector records."""
    return {
        "reply_to_message_id": row["reply_to_message_id"],
        "plaintext": row["plaintext"],
        "edit": row["edit"]["latest_edit_message_id_hex"] if row["edit"] else None,
        "deleted": row["deleted"],
        "deletion_source": row["deletion_source"],
        "deleted_by_message_id": row["deleted_by_message_id"],
        "reactions": row["reactions"]["by_emoji"],
    }


def media_of(message_id):
    out = []
    for m in wn_media:
        if m["message_id"] != message_id:
            continue
        out.append({
            "url": m["locators"][0]["value"] if m["locators"] else None,
            "mime": m["media_type"],
            "filename": m["file_name"],
            "dim": m["dim"],
            "thumbhash": m["thumbhash"],
            "plaintext_sha256": m["plaintext_sha256"],
            "ciphertext_sha256": m["ciphertext_sha256"],
            "nonce": m["nonce_hex"],
        })
    return out


# ---- MDK's poll rules (cgka-traits polls.rs parse_poll / parse_poll_response /
# validate_poll_response, storage-sqlite timeline.rs effective_poll_votes): a voter's newest
# valid response is their vote; an invalid one counts for nothing and leaves it standing.
def parse_poll(r):
    options = [{"id": t[1], "label": t[2]} for t in r["tags"] if t[0] == "option" and len(t) == 3]
    ptype = first(r["tags"], "polltype") or "singlechoice"
    ends = first(r["tags"], "endsAt")
    return {"question": r["content"], "type": ptype, "options": options, "ends_at": int(ends) if ends else None}


def vote_valid(v):
    poll_id = first(v["tags"], "e")
    sel = [t[1] for t in v["tags"] if t[0] == "response" and len(t) == 2]
    poll = by_id.get(poll_id)
    if poll is None or poll["kind"] != 1068 or not sel or len(set(sel)) != len(sel):
        return False
    p = parse_poll(poll)
    ids = {o["id"] for o in p["options"]}
    if v["created_at"] < poll["created_at"] or (p["ends_at"] is not None and v["created_at"] > p["ends_at"]):
        return False
    if len(sel) > len(ids) or (p["type"] == "singlechoice" and len(sel) != 1):
        return False
    return all(s in ids for s in sel)


def effective_votes():
    best = {}
    for v in conversation:
        if v["kind"] != 1018 or not vote_valid(v):
            continue
        key = (first(v["tags"], "e"), v["pubkey"])
        if key not in best or (v["created_at"], v["id"]) > (best[key]["created_at"], best[key]["id"]):
            best[key] = v
    return {v["id"] for v in best.values()}


EFFECTIVE = effective_votes()


def interpret(rumor):
    """Returns (mdk, expect) for one rumor."""
    kind, rid = rumor["kind"], rumor["id"]
    if kind in (9, 1068):
        row = rows.get(rid)
        mdk = {"basis": "observed", "row": row is not None}
        expect = {"row": row is not None}
        if row is not None:
            mdk.update(row_view(row))
            expect["reply_to"] = row["reply_to_message_id"]
        if kind == 9:
            mdk["media"] = media_of(rid)
            expect["mentions"] = mentions(rumor)
            expect["media"] = mdk["media"]
            mdk["mentions_basis"] = "source: marmot-app notifications.rs message_text_mentions_account"
        else:
            expect["poll"] = parse_poll(rumor)
            mdk["poll_basis"] = "source: cgka-traits polls.rs parse_poll (wn 0.19 prints no poll projection)"
        return mdk, expect
    target = first(rumor["tags"], "e")
    target_row = rows.get(target)
    mdk = {"basis": "observed", "row": rid in rows, "target_row": row_view(target_row) if target_row else None}
    expect = {"row": rid in rows}
    if kind == 7:
        emoji_tag = next((t for t in rumor["tags"] if t[0] == "emoji" and len(t) > 2), None)
        expect["reaction"] = {"target": target, "emoji": rumor["content"], "custom_emoji_url": emoji_tag[2] if emoji_tag else None}
        expect["counted"] = rid in reactions_present
    elif kind == 1009:
        expect["edit"] = {"target": target, "content": rumor["content"]}
        expect["applied"] = bool(target_row and target_row["edit"] and target_row["edit"]["latest_edit_message_id_hex"] == rid)
    elif kind == 5:
        targets = [t[1] for t in rumor["tags"] if t[0] == "e" and len(t) > 1]
        applied = []
        for t in targets:
            target_event = by_id.get(t)
            if t in rows:
                if rows[t]["deleted_by_message_id"] == rid:
                    applied.append(t)
            elif target_event is not None and target_event["kind"] == 7 and t not in reactions_present:
                applied.append(t)
        expect["deletes"] = targets
        expect["applied"] = applied
    elif kind == 4891:
        expect["removes"] = target
        expect["applied"] = bool(target_row and target_row["deleted_by_message_id"] == rid)
    elif kind == 1018:
        mdk = {"basis": "source: storage-sqlite timeline.rs effective_poll_votes (wn 0.19 prints no tallies)", "row": rid in rows}
        expect["vote"] = {
            "poll": target,
            "options": [t[1] for t in rumor["tags"] if t[0] == "response" and len(t) == 2],
            "valid": vote_valid(rumor),
            "counted": rid in EFFECTIVE,
        }
    return mdk, expect


def referenced(rumor):
    return [t[1] for t in rumor["tags"] if len(t) > 1 and t[0] in ("e", "q") and t[1] in by_id]


def build(side):
    cases = []
    for step in steps:
        if step["side"] != side:
            continue
        rumor = by_id.get(step["id"])
        if rumor is None:
            sys.exit(f"amy never received {step['name']} ({step['id']})")
        if "rumor" in step and step["rumor"]["id"] != rumor["id"]:
            sys.exit(f"{step['name']}: amy stored a different rumor than the injector sent")
        mdk, expect = interpret(rumor)
        case = {"name": step["name"]}
        if side == "theirs":
            case["source"] = f"MDK {MDK} via `{' '.join(step['command'].split(' ')[0:3])}`"
        elif "spec" in step:
            op = step["spec"]["op"]
            case["source"] = "hand-shaped (no builder makes it), sent by amy" if op == "raw" or step["spec"].get("raw") else f"marmot-kmp builder ({op}), sent by amy"
            case["builder"] = step["spec"]
        else:
            case["source"] = f"marmot-kmp via `{' '.join(step['command'].split(' ')[0:4])}`"
        if rumor["kind"] == 9 and any(t[0] == "imeta" for t in rumor["tags"]):
            reader = "amy" if side == "theirs" else "wn"
            hashes = {m["plaintext_sha256"] for m in mdk["media"]}
            got = [d["ok"] for d in downloads if d["by"] == reader and (d.get("event_id") == rumor["id"] or d.get("plaintext_sha256") in hashes)]
            mdk["decrypted_by_reader"] = got[0] if got else None
        case.update({"rumor": rumor, "context": referenced(rumor), "mdk": mdk, "expect": expect})
        cases.append(case)
    return cases


common = {
    "generator": "marmot/tools/app-event-vector-gen (gen.sh, build_vectors.py)",
    "reference": f"MDK {MDK}, wn/wnd release binaries",
    "amy": meta["amy"],
    "marmot_kmp": meta["marmot_kmp"],
    "members": {"amethyst": meta["amethyst"], "white_noise": meta["white_noise"]},
    # Both were admins whenever a kind 4891 in these files was sent; White Noise stepped down
    # before its last kind-5 deletion so that one goes out as a plain author retraction.
    "admins": sorted([meta["amethyst"], meta["white_noise"]]),
    "conversation": conversation,
}
OUT.mkdir(parents=True, exist_ok=True)
files = {
    f"mdk-{MDK}-sent.json": ("White Noise sent these; marmot-kmp must read them as MDK does.", "theirs"),
    f"ours-read-by-mdk-{MDK}.json": ("marmot-kmp built these (or amy sent a hand-shaped one); this is what White Noise made of them.", "ours"),
}
for name, (description, side) in files.items():
    doc = {"description": description, **common, "cases": build(side)}
    (OUT / name).write_text(json.dumps(doc, indent=1, ensure_ascii=False) + "\n")
    print(f"{name}: {len(doc['cases'])} cases")
