# Poker Scanner

Scan the BSV chain for on-chain **BSV-Poker** activity and report on it.

BSV-Poker tags its transactions with a `BSVP:<KIND>:<v>` marker (e.g. `BSVP:ID:1`,
`BSVP:BET:1`, `BSVP:DM:1`, `BSVP:GAME:1`) carried as a **PUSHDATA element + `OP_DROP`
inside otherwise-spendable scripts** — *not* OP_RETURN, which is why ordinary explorers
and indexers miss it. This project pulls full blocks from a BSV node, finds those
markers, stores the marked transactions in SQLite, and analyses them.

Two tools:

- **`bsvp_scan.py`** — pull blocks from a node over P2P, detect the `BSVP:` marker,
  store each marked tx to SQLite (tags, lineage flag, input prevouts, **and the full raw
  tx**), plus each block's timestamp.
- **`analyze.py`** — read the DB and print a report: activity totals, tag breakdown,
  funding-graph clustering, **games played** (player identity, stakes, hands, bets),
  **identity registrations** (pseudonym/email, dated), and a timeline. Pure SQLite +
  local parsing — no network.

## How it gets blocks

Speaks the BSV P2P protocol to a node with plain sockets (BSV mainnet magic `e3e1f3e8`),
and parses blocks/txs with the BSV-native **bsv-sdk** (`Transaction.from_reader`). Block
hashes for a height range are walked via the node's own `getheaders`, so only the start
height needs an external lookup (WhatsOnChain, one call).

> Gotcha that cost a while to find: a `getdata` inventory **count must be a varint**
> (1 byte for count=1), not a 4-byte int — otherwise the node silently drops the request
> (no block, no `notfound`) while `getheaders` still works. See `get_block()`.

Because the scanner stores the **full raw tx** for every marked tx, any new field-level
analysis (chat, bets, points, …) is just a new function in `analyze.py` reading
`txs.raw` — no re-scan and no network.

## Setup

Requires **Python 3.11** (bsv-sdk's native deps lack wheels for newer Pythons).

```bash
python3.11 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

All commands below use `.venv/bin/python` so you don't have to activate the venv; if you
prefer, `source .venv/bin/activate` first and just run `python`.

## Usage

```bash
# scan
.venv/bin/python bsvp_scan.py                           # DEFAULT (automatic): new blocks → tip; a fresh DB bootstraps from BSVP genesis (951000)
.venv/bin/python bsvp_scan.py --from 951700             # RESCAN from a height to the tip (re-fetches even blocks already in the DB)
.venv/bin/python bsvp_scan.py --range 951700 955284     # RESCAN an explicit window (re-fetches even blocks already in the DB)
.venv/bin/python bsvp_scan.py --one 953701              # fetch + scan a single block (prints; no DB write)
#   options: --host 127.0.0.1 --port 8333 --db bsvp.db --prefixes /tmp/tx-prefixes.txt

# analyse
.venv/bin/python analyze.py --db bsvp.db                # full report from the DB
#   options: --buckets 144   (timeline bucket size, ~1 day of blocks)
```

`--prefixes` is an optional file of 10-char txid prefixes for a known funding lineage;
marked txs are flagged `mine` vs `other` against it (used to separate your own activity
from everyone else's).

## SQLite schema

- **`blocks`** — `height, hash, size, txcount, marked, scanned_at, time` (block header time)
- **`txs`** — `txid, height, tags, mine, n_in, n_out, size, raw` (raw = full tx hex)
- **`tx_inputs`** — `txid, vin, prev_txid, prev_vout` (for funding-graph clustering)

## Requirements

Beyond the venv (see Setup): a reachable BSV node (`--host`/`--port`, default
`127.0.0.1:8333`) that serves full blocks over P2P.
</content>
