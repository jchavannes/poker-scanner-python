#!/usr/bin/env python3
"""Analyze a bsvp.db produced by bsvp_scan.py: how much BSV-Poker on-chain activity,
how many distinct participants/games, and how much is yours vs. other wallets.

Usage: python analyze.py [--db bsvp.db]
"""
import argparse, sqlite3
from collections import defaultdict


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

    print(f"\n--- timeline (marked txs per {a.buckets}-block bucket) ---")
    for h0, n in q(f"SELECT (height/{a.buckets})*{a.buckets} AS b, count(*) FROM txs GROUP BY b ORDER BY b"):
        print(f"  {h0}: {'#' * min(n, 60)} {n}")
    con.close()


if __name__ == "__main__":
    main()
