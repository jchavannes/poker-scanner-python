# poker-scanner

Scan the BSV chain for on-chain **BSV-Poker** activity by detecting the app's
`BSVP:` data marker (a PUSHDATA element + `OP_DROP` carried in otherwise-spendable
scripts — *not* OP_RETURN, which is why ordinary explorers/indexers miss it).

For every marked transaction it records the tag (`BSVP:ID:1`, `BSVP:BET:1`,
`BSVP:DM:1`, `BSVP:POT:1`, …), the block height, and whether the txid belongs to a
known funding lineage vs. another wallet — into SQLite for further analysis.

## How it gets blocks

Talks the BSV P2P protocol to a node using **python-bitcoinlib** for message
construction (`msg_version`, `msg_getdata`, `msg_getheaders`) and for robust
`CBlock` / `CTransaction` deserialization. BSV specifics added on top: the
`e3e1f3e8` network magic and the `protoconf` size/stream negotiation.

Block hashes for a height range are walked via the node's own `getheaders`, so only
the start height needs an external lookup.

## Usage

```bash
.venv/bin/python bsvp_scan.py --one 953701                 # fetch+scan one block
.venv/bin/python bsvp_scan.py --range 951760 955267        # scan a window
# options: --host 127.0.0.1 --port 8333 --db bsvp.db --prefixes /tmp/tx-prefixes.txt
```

## Requirements

`pip install -r requirements.txt` (python-bitcoinlib). Python 3.11.
</content>
