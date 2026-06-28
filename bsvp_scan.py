#!/usr/bin/env python3
"""Scan the BSV chain for BSV-Poker on-chain activity (the `BSVP:` data marker).

Pulls blocks from a BSV node over P2P (correct varint-framed getdata) and parses
them with the BSV-native **bsv-sdk** (`Transaction.from_reader`). For every marked
tx it records the tag(s) (BSVP:ID:1, BSVP:BET:1, BSVP:DM:1, BSVP:POT:1, …), the
height, and whether the txid is in a known funding lineage vs another wallet — into
SQLite. See README.md.
"""
import argparse, socket, struct, time, json, os, sqlite3, hashlib, urllib.request, re
import bsv

MAGIC = bytes.fromhex("e3e1f3e8")          # BSV mainnet message-start
NEEDLE = b"BSVP:"
PROTOCOL = 70016
UA = b"/poker-scanner:0.1/"
BSVP_GENESIS_HEIGHT = 951000               # conservative start, safely before the first BSVP-Poker tx (first marker seen at 952808)

SCHEMA = """
CREATE TABLE IF NOT EXISTS blocks(
  height INTEGER PRIMARY KEY, hash TEXT, size INTEGER, txcount INTEGER,
  marked INTEGER, scanned_at INTEGER, time INTEGER);
CREATE TABLE IF NOT EXISTS txs(
  txid TEXT PRIMARY KEY, height INTEGER, tags TEXT, mine INTEGER,
  n_in INTEGER, n_out INTEGER, size INTEGER, raw TEXT);
CREATE TABLE IF NOT EXISTS tx_inputs(
  txid TEXT, vin INTEGER, prev_txid TEXT, prev_vout INTEGER,
  PRIMARY KEY(txid, vin));
CREATE INDEX IF NOT EXISTS ix_txs_height ON txs(height);
CREATE INDEX IF NOT EXISTS ix_txs_mine   ON txs(mine);
CREATE INDEX IF NOT EXISTS ix_inputs_prev ON tx_inputs(prev_txid);
"""

# ----------------------------- P2P (raw, correct framing) -----------------------------
def _dsha(b): return hashlib.sha256(hashlib.sha256(b).digest()).digest()

def frame(cmd, payload=b""):
    return MAGIC + cmd.encode().ljust(12, b"\x00") + struct.pack("<I", len(payload)) + _dsha(payload)[:4] + payload

def varint(n):
    if n < 0xfd: return bytes([n])
    if n <= 0xffff: return b"\xfd" + struct.pack("<H", n)
    if n <= 0xffffffff: return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)

class Peer:
    def __init__(self, host, port, timeout=180):
        self.s = socket.create_connection((host, port), timeout=30)
        self.s.settimeout(timeout); self.buf = b""
    def _recvn(self, n):
        while len(self.buf) < n:
            c = self.s.recv(1 << 20)
            if not c: raise ConnectionError("peer closed")
            self.buf += c
        out, self.buf = self.buf[:n], self.buf[n:]; return out
    def read(self):
        h = self._recvn(24)
        if h[:4] != MAGIC: raise ValueError("bad magic")
        cmd = h[4:16].split(b"\x00", 1)[0].decode("ascii", "replace")
        ln = struct.unpack("<I", h[16:20])[0]
        return cmd, (self._recvn(ln) if ln else b"")
    def send(self, cmd, payload=b""): self.s.sendall(frame(cmd, payload))
    def close(self):
        try: self.s.close()
        except Exception: pass

def version_payload():
    netaddr = struct.pack("<Q", 0) + bytes(16) + bytes(2)
    return (struct.pack("<i", PROTOCOL) + struct.pack("<Q", 0) + struct.pack("<q", int(time.time()))
            + netaddr + netaddr + struct.pack("<Q", 0x706f6b6572)
            + varint(len(UA)) + UA + struct.pack("<i", 0) + b"\x00")   # relay=0

def handshake(peer):
    peer.send("version", version_payload())
    gotv = gotk = False
    while not (gotv and gotk):
        cmd, pl = peer.read()
        if cmd == "version": gotv = True; peer.send("verack")
        elif cmd == "verack": gotk = True
        elif cmd == "ping": peer.send("pong", pl)

def get_block(peer, internal_hash):
    # getdata: varint(count=1) + inv(type=2 MSG_BLOCK LE + 32-byte internal hash). The count MUST be a varint.
    peer.send("getdata", varint(1) + struct.pack("<I", 2) + internal_hash)
    while True:
        cmd, pl = peer.read()
        if cmd == "block": return pl
        if cmd == "ping": peer.send("pong", pl)
        if cmd == "notfound": raise RuntimeError("node returned notfound")

def get_headers(peer, locator_internal):
    peer.send("getheaders", struct.pack("<I", PROTOCOL) + varint(1) + locator_internal + bytes(32))
    while True:
        cmd, pl = peer.read()
        if cmd == "headers": return pl
        if cmd == "ping": peer.send("pong", pl)

# ----------------------------- parsing (bsv-sdk) -----------------------------
def read_varint_from(b, o):
    v = b[o]; o += 1
    if v < 0xfd: return v, o
    if v == 0xfd: return struct.unpack_from("<H", b, o)[0], o + 2
    if v == 0xfe: return struct.unpack_from("<I", b, o)[0], o + 4
    return struct.unpack_from("<Q", b, o)[0], o + 8

def header_hashes(headers_payload):
    n, o = read_varint_from(headers_payload, 0); out = []
    for _ in range(n):
        out.append(_dsha(headers_payload[o:o + 80]))      # internal hash
        o += 80
        _, o = read_varint_from(headers_payload, o)        # tx count (0)
    return out

def iter_block_txs(payload):
    """Yield bsv-sdk Transaction objects for every tx in a raw block (BSV-native parse)."""
    r = bsv.Reader(payload)
    r.read(80)                                             # skip block header
    n = r.read_var_int_num()
    for _ in range(n):
        yield bsv.Transaction.from_reader(r)

def block_txcount(payload):
    n, _ = read_varint_from(payload, 80); return n

_TAG_RE = re.compile(rb"BSVP:[A-Z]+:[0-9]+")        # e.g. BSVP:ID:1, BSVP:DEAL:1, BSVP:STEALTHP:1
def markers_in(raw):
    return [m.decode("ascii") for m in _TAG_RE.findall(raw)]

def _prevout(vin):
    txid = getattr(vin, "source_txid", None) or getattr(vin, "txid", None) or ""
    vout = getattr(vin, "source_output_index", None)
    if vout is None: vout = getattr(vin, "vout", -1)
    return txid, vout

def scan_block(payload, height, bh_hex, prefixes, con):
    marked = mine = other = 0; tags = {}; ntx = block_txcount(payload)
    if NEEDLE in payload:                                  # fast reject: skip blocks with no marker
        for tx in iter_block_txs(payload):
            raw = tx.serialize()
            tg = markers_in(raw)
            if not tg: continue
            marked += 1
            for t in tg: tags[t] = tags.get(t, 0) + 1
            txid = tx.txid()
            is_mine = txid[:10] in prefixes
            mine += is_mine; other += (not is_mine)
            if con is not None:
                # store the FULL raw tx so any field-level analysis runs from the DB later
                con.execute("INSERT OR REPLACE INTO txs VALUES(?,?,?,?,?,?,?,?)",
                            (txid, height, ",".join(tg), int(is_mine), len(tx.inputs), len(tx.outputs), len(raw), raw.hex()))
                rows = []
                for i, vin in enumerate(tx.inputs):
                    pt, pv = _prevout(vin); rows.append((txid, i, pt, pv))
                con.executemany("INSERT OR REPLACE INTO tx_inputs VALUES(?,?,?,?)", rows)
    if con is not None:
        block_time = struct.unpack_from("<I", payload, 68)[0]   # header timestamp (LE uint32)
        con.execute("INSERT OR REPLACE INTO blocks VALUES(?,?,?,?,?,?,?)",
                    (height, bh_hex, len(payload), ntx, marked, int(time.time()), block_time))
        con.commit()
    return marked, mine, other, tags, ntx

# ----------------------------- helpers -----------------------------
def woc_hash(height):
    with urllib.request.urlopen(f"https://api.whatsonchain.com/v1/bsv/main/block/height/{height}", timeout=30) as r:
        return json.load(r)["hash"]

def load_prefixes(path):
    import re
    s = set()
    if path and os.path.exists(path):
        for line in open(path):
            m = re.search(r"\b([0-9a-f]{10})\b", line)
            if m: s.add(m.group(1))
    return s

# ----------------------------- CLI -----------------------------
def cmd_one(a):
    prefixes = load_prefixes(a.prefixes)
    peer = Peer(a.host, a.port); handshake(peer)
    bhh = woc_hash(a.one); t0 = time.time()
    payload = get_block(peer, bytes.fromhex(bhh)[::-1])
    m, mi, o, tags, ntx = scan_block(payload, a.one, bhh, prefixes, None)
    print(f"block {a.one} ({len(payload)/1e6:.2f}MB, {ntx} txs, {time.time()-t0:.1f}s): marked={m} mine={mi} other={o} tags={tags}")
    if m:
        for tx in iter_block_txs(payload):
            tg = markers_in(tx.serialize())
            if tg:
                txid = tx.txid()
                print(f"   {txid}  {tg}  {'MINE' if txid[:10] in prefixes else 'other'}")
    peer.close()

def resolve_hashes(peer, anchor_internal, start, end=None):
    """Walk getheaders from anchor; return {height: internal_hash} for start..end (end=None → to chain tip)."""
    h2h = {}; cur = anchor_internal; h = start
    while end is None or h <= end:
        hashes = header_hashes(get_headers(peer, cur))
        if not hashes: break
        for ih in hashes:
            if end is not None and h > end: break
            h2h[h] = ih; h += 1
        cur = hashes[-1]
    return h2h

def scan_hashes(con, peer, host, port, h2h, prefixes, db, rescan=False):
    """Fetch+scan each block in h2h; print totals. Returns the peer. With rescan=False (the automatic
    update) heights already in the DB are skipped; with rescan=True every block is re-fetched and
    re-written (INSERT OR REPLACE), so explicit --from/--range always reprocess."""
    done = set() if rescan else {r[0] for r in con.execute("SELECT height FROM blocks")}
    todo = [h for h in sorted(h2h) if h not in done]
    g = {"marked": 0, "mine": 0, "other": 0, "tags": {}}; scanned = bytes_dl = 0; t_start = time.time()
    for hgt in todo:
        ih = h2h[hgt]
        try:
            payload = get_block(peer, ih)
        except Exception as e:
            print(f"  !! {hgt} fetch error {e}; reconnecting")
            try:
                peer.close(); peer = Peer(host, port); handshake(peer); payload = get_block(peer, ih)
            except Exception as e2:
                print(f"  !! {hgt} retry failed ({e2}); skipping block"); continue
        bytes_dl += len(payload); scanned += 1
        m, mi, o, tags, ntx = scan_block(payload, hgt, ih[::-1].hex(), prefixes, con)
        g["marked"] += m; g["mine"] += mi; g["other"] += o
        for k, v in tags.items(): g["tags"][k] = g["tags"].get(k, 0) + v
        if m or scanned % 200 == 0:
            print(f"  [{hgt}] {scanned}/{len(todo)} done, {bytes_dl/1e6:.0f}MB, {time.time()-t_start:.0f}s"
                  + (f"  >>> marked={m} mine={mi} other={o} {tags}" if m else ""), flush=True)
    print("\n==== TOTAL ====")
    print(f"blocks scanned={scanned}  data={bytes_dl/1e6:.0f}MB  time={time.time()-t_start:.0f}s")
    print(f"BSVP-marked txs={g['marked']}  mine(lineage)={g['mine']}  other(non-lineage)={g['other']}")
    print(f"tag breakdown={g['tags']}\nDB -> {db}  (tables: blocks, txs, tx_inputs)")
    return peer

def cmd_range(a):
    if a.start > a.end:
        print(f"empty range: start {a.start} > end {a.end}"); return
    prefixes = load_prefixes(a.prefixes)
    con = sqlite3.connect(a.db); con.executescript(SCHEMA)
    peer = Peer(a.host, a.port); handshake(peer)
    anchor = bytes.fromhex(woc_hash(a.start - 1))[::-1]   # one WoC call to anchor the start
    h2h = resolve_hashes(peer, anchor, a.start, a.end)
    print(f"DB={a.db}  prefixes={len(prefixes)}  RESCAN range={a.start}..{a.end}  resolved {len(h2h)} hashes")
    peer = scan_hashes(con, peer, a.host, a.port, h2h, prefixes, a.db, rescan=True)
    con.close(); peer.close()

def cmd_from(a):
    """Explicit RESCAN from a height to the chain tip — re-fetches and re-writes every block in range,
    even ones already in the DB. Also seeds a fresh DB."""
    prefixes = load_prefixes(a.prefixes)
    con = sqlite3.connect(a.db); con.executescript(SCHEMA)
    peer = Peer(a.host, a.port); handshake(peer)
    anchor = bytes.fromhex(woc_hash(a.from_height - 1))[::-1]
    h2h = resolve_hashes(peer, anchor, a.from_height, None)
    print(f"DB={a.db}  RESCAN {a.from_height}..tip  resolved {len(h2h)} blocks")
    peer = scan_hashes(con, peer, a.host, a.port, h2h, prefixes, a.db, rescan=True)
    con.close(); peer.close()

def cmd_update(a):
    """DEFAULT (automatic): stay up to date — scan only NEW blocks, up to the chain tip, skipping anything
    already in the DB. Once the DB has data it anchors on its own last block hash (no WoC call); a fresh/empty
    DB bootstraps from BSVP_GENESIS_HEIGHT (where BSVP-Poker activity starts)."""
    prefixes = load_prefixes(a.prefixes)
    con = sqlite3.connect(a.db); con.executescript(SCHEMA)
    row = con.execute("SELECT height, hash FROM blocks ORDER BY height DESC LIMIT 1").fetchone()
    if row:
        start = row[0] + 1; anchor = bytes.fromhex(row[1])[::-1]
        print(f"DB={a.db}  last scanned height={row[0]}; checking for new blocks {start}..tip")
    else:
        start = BSVP_GENESIS_HEIGHT; anchor = bytes.fromhex(woc_hash(start - 1))[::-1]
        print(f"DB={a.db}  empty — bootstrapping from BSVP genesis height {start} to tip")
    peer = Peer(a.host, a.port); handshake(peer)
    h2h = resolve_hashes(peer, anchor, start, None)
    if not h2h:
        print(f"up to date — no new blocks past height {start-1}."); con.close(); peer.close(); return
    print(f"resolved {len(h2h)} new block(s): {start}..{start+len(h2h)-1}")
    peer = scan_hashes(con, peer, a.host, a.port, h2h, prefixes, a.db, rescan=False)
    con.close(); peer.close()

def main():
    ap = argparse.ArgumentParser(description="Scan BSV chain for BSV-Poker BSVP: markers")
    ap.add_argument("--host", default="127.0.0.1"); ap.add_argument("--port", type=int, default=8333)
    ap.add_argument("--db", default="bsvp.db"); ap.add_argument("--prefixes", default="/tmp/tx-prefixes.txt")
    mode = ap.add_mutually_exclusive_group()             # default (none given) = automatic incremental update
    mode.add_argument("--one", type=int, help="fetch+scan a single block height (prints; no DB write)")
    mode.add_argument("--range", nargs=2, type=int, metavar=("START", "END"),
                      help="RESCAN an explicit height range (re-fetches and re-writes, even blocks already in the DB)")
    mode.add_argument("--from", dest="from_height", type=int,
                      help="RESCAN from a height to the chain tip (also seeds a fresh DB)")
    a = ap.parse_args()
    if a.one is not None: cmd_one(a)
    elif a.range: a.start, a.end = a.range; cmd_range(a)
    elif a.from_height is not None: cmd_from(a)
    else: cmd_update(a)                                   # DEFAULT (automatic): incremental — only new blocks to tip

if __name__ == "__main__":
    main()
