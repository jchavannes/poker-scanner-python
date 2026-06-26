#!/usr/bin/env python3
"""Analyze a bsvp.db produced by bsvp_scan.py: how much BSV-Poker on-chain activity,
how many distinct participants/games, and how much is yours vs. other wallets.

Usage: python analyze.py [--db bsvp.db]
"""
import argparse, sqlite3
from collections import defaultdict

import bsv

# The scanner stores the FULL raw tx for every marked tx (txs.raw), so any field-level
# analysis parses straight from the DB — no network. Below: parse the typed PUSHDATA
# output (mirrors TxTemplates.Parse / OnChainIdentity) to read identity claims.
OP_DROP, OP_CHECKSIG, OP_PUSHDATA1, OP_PUSHDATA2 = 0x75, 0xac, 0x4c, 0x4d

def _read_push(s, p):
    if p >= len(s): return None, p
    op = s[p]; p += 1
    if op == 0x00: return b"", p
    if op == 0x4f: return b"\x81", p
    if 0x51 <= op <= 0x60: return bytes([op - 0x50]), p
    if op < OP_PUSHDATA1: ln = op
    elif op == OP_PUSHDATA1:
        if p >= len(s): return None, p
        ln = s[p]; p += 1
    elif op == OP_PUSHDATA2:
        if p + 2 > len(s): return None, p
        ln = s[p] | s[p + 1] << 8; p += 2
    else: return None, p
    if p + ln > len(s): return None, p
    return s[p:p + ln], p + ln

def parse_typed_output(script):
    """Return (tag, fields, ownerPub) or None for a typed BSV-Poker output script."""
    marker, p = _read_push(script, 0)
    if marker is None or p >= len(script) or script[p] != OP_DROP: return None
    p += 1; fields = []
    while True:
        data, p2 = _read_push(script, p)
        if data is None: return None
        if p2 < len(script) and script[p2] == OP_DROP:
            fields.append(data); p = p2 + 1; continue
        if len(data) == 33 and p2 < len(script) and script[p2] == OP_CHECKSIG and p2 + 1 == len(script):
            return marker.decode("ascii", "replace"), fields, data
        return None

def identity_saves(con):
    """Every BSVP:ID:1 save, parsed from the stored raw tx. Returns rows
    (height, txid, mine, idpub, attpub, pseudonym, email), or None if no raw txs are stored
    (DB scanned before raw capture — run: bsvp_scan.py --backfill-raw)."""
    if "raw" not in {r[1] for r in con.execute("PRAGMA table_info(txs)")}: return None
    rows = con.execute("SELECT height, txid, mine, raw FROM txs "
                       "WHERE tags LIKE '%BSVP:ID:1%' AND raw IS NOT NULL ORDER BY height, txid").fetchall()
    out = []
    for height, txid, mine, raw in rows:
        try:
            for o in bsv.Transaction.from_hex(raw).outputs:
                r = parse_typed_output(o.locking_script.serialize())
                if r and r[0] == "BSVP:ID:1" and len(r[1]) == 5 and len(r[1][0]) == 33:
                    f = r[1]
                    out.append((height, txid, mine, f[0].hex(), f[1].hex(),
                                f[2].decode("utf-8", "replace"), f[3].decode("utf-8", "replace")))
                    break
        except Exception:
            continue
    return out or None


def cluster(con):
    """Union-find over marked txs: link a tx to any marked parent it spends, and link
    txs that share a common funding parent. Each component ≈ one wallet/game stream."""
    txs = {r[0]: {"tags": r[1], "mine": r[2]} for r in con.execute("SELECT txid,tags,mine FROM txs")}
    marked = set(txs)
    parent = {t: t for t in marked}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]; x = parent[x]
        return x

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb: parent[ra] = rb

    byprev = defaultdict(list)
    for txid, prev in con.execute("SELECT txid, prev_txid FROM tx_inputs"):
        if prev in marked: union(txid, prev)      # spends another marked tx
        byprev[prev].append(txid)
    for kids in byprev.values():                  # siblings from the same funding parent
        for k in kids[1:]: union(kids[0], k)

    comps = defaultdict(list)
    for t in marked: comps[find(t)].append(t)
    return txs, list(comps.values())


def main():
    ap = argparse.ArgumentParser(description="Analyze BSV-Poker on-chain activity from a scan DB")
    ap.add_argument("--db", default="bsvp.db")
    ap.add_argument("--buckets", type=int, default=144, help="height bucket size for the timeline (144 ≈ 1 day)")
    a = ap.parse_args()
    con = sqlite3.connect(a.db)
    q = lambda s: con.execute(s).fetchall()

    blocks = q("SELECT count(*) FROM blocks")[0][0]
    scanned_range = q("SELECT min(height), max(height) FROM blocks")[0]
    mtx = q("SELECT count(*) FROM txs")[0][0]
    mine = q("SELECT count(*) FROM txs WHERE mine=1")[0][0]
    other = mtx - mine
    active = q("SELECT min(height), max(height) FROM txs")[0]
    marked_blocks = q("SELECT count(*) FROM blocks WHERE marked>0")[0][0]

    print("=" * 64)
    print("BSV-POKER ON-CHAIN ACTIVITY")
    print("=" * 64)
    print(f"blocks scanned     : {blocks}  (heights {scanned_range[0]}–{scanned_range[1]})")
    print(f"blocks with markers: {marked_blocks}")
    print(f"marked BSVP txs    : {mtx}   (yours/lineage={mine}, other={other})")
    print(f"active height range: {active[0]}–{active[1]}")

    print("\n--- tag breakdown (tx type) ---")
    tagcount = defaultdict(int)
    for tags, in q("SELECT tags FROM txs"):
        for t in tags.split(","):
            if t: tagcount[t] += 1
    for t, n in sorted(tagcount.items(), key=lambda kv: -kv[1]):
        print(f"  {t:16} {n}")

    print("\n--- distinct participants/games (funding-graph clusters) ---")
    txs, comps = cluster(con)
    mine_c = [g for g in comps if any(txs[t]["mine"] for t in g)]
    other_c = [g for g in comps if not any(txs[t]["mine"] for t in g)]
    print(f"  total clusters            : {len(comps)}")
    print(f"  clusters touching yours   : {len(mine_c)}")
    print(f"  independent (no lineage)  : {len(other_c)}")
    print(f"  independent cluster sizes : {sorted((len(g) for g in other_c), reverse=True)[:25]}")

    print("\n--- key counts (proxies) ---")
    def has(tag): return q(f"SELECT count(*) FROM txs WHERE tags LIKE '%{tag}%'")[0][0]
    ids = q("SELECT mine FROM txs WHERE tags LIKE '%BSVP:ID:1%'")
    print(f"  identity registrations (players) : {len(ids)}  (yours={sum(m for m, in ids)}, other={sum(1-m for m, in ids)})")
    print(f"  tables (TBL)  : {has('BSVP:TBL:1')}")
    print(f"  games (GAME)  : {has('BSVP:GAME:1')}")
    print(f"  hands (HAND)  : {has('BSVP:HAND:1')}")
    print(f"  bets (BET)    : {has('BSVP:BET:1')}")
    print(f"  chat (DM)     : {has('BSVP:DM:1')}")
    print(f"  node publishes: {has('BSVP:NODE:1')}")

    print("\n--- on-chain identity saves (every BSVP:ID:1 registration) ---")
    saves = identity_saves(con)
    if saves is None:
        print("  (no raw txs stored — re-scan with bsvp_scan.py --range to populate txs.raw)")
    else:
        distinct = len({r[3] for r in saves})
        print(f"  identity saves: {len(saves)}   distinct Base ID keys: {distinct}  "
              f"(yours={sum(r[2] for r in saves)}, other={sum(1 - r[2] for r in saves)} saves)")
        print(f"  {'height':>7}  {'txid':12}  {'pseudonym':16}  {'email':26}  base-ID")
        for height, txid, mine, idpub, attpub, pseudonym, email in saves:
            who = "yours" if mine else "other"
            print(f"  {height:>7}  {txid[:12]}  @{(pseudonym or '?')[:15]:15}  "
                  f"{(email or '-')[:26]:26}  {idpub[:16]}… [{who}]")

    print(f"\n--- timeline (marked txs per {a.buckets}-block bucket) ---")
    for h0, n in q(f"SELECT (height/{a.buckets})*{a.buckets} AS b, count(*) FROM txs GROUP BY b ORDER BY b"):
        print(f"  {h0}: {'#' * min(n, 60)} {n}")
    con.close()


if __name__ == "__main__":
    main()
