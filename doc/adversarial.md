# Adversarial node mode (`-adversarial`)

`-adversarial` turns a node into a **programmable network adversary** for
full-system testing (e.g. [Antithesis](https://antithesis.com/)). It gives the
node the same capabilities as the
[fuzzamoto](https://github.com/dergoegge/fuzzamoto) IR — open arbitrary
connections, send raw/malformed p2p messages, construct adversarial blocks and
transactions — but baked into the node and driven over RPC, rather than from an
external harness.

> **WARNING**: a node started with `-adversarial` can attack the network it is
> connected to (send malformed messages, invalid blocks, mutate compact-block
> relay, ...). It is a test-only tool. **Never enable it on a node reachable
> from mainnet peers.** The startup flag is the only gate, so treat the whole
> namespace as dangerous.

The flag is off by default. When set, the node logs a warning at startup and
registers the `adv_*` RPC namespace.

## Fuzzer-controlled randomness

Wherever the adversarial code makes a "random" choice it reads bytes **directly
from `/dev/urandom`** on every draw (`UrandomSource`, see
`src/common/urandom.h`) rather than using `FastRandomContext`. `FastRandomContext`
seeds once and then expands the stream internally, so an external fuzzer that
controls the entropy device could not steer the individual decisions. By issuing
a fresh `read()` per choice, a deterministic hypervisor / coverage-guided fuzzer
that instruments `/dev/urandom` (such as Antithesis) drives the construction of
every adversarial message, block and transaction.

## Capabilities

### Connections and raw messages (node RPCs)

| RPC | Description |
| --- | --- |
| `adv_connect` | Open an outbound connection of any connection type to a node. Works on any chain (unlike the regtest-only `addconnection`). |
| `adv_disconnect` | Disconnect a peer by node id. |
| `adv_sendrawmessage` | Send an arbitrary (possibly malformed) p2p message body to a peer over the node's own p2p stack. |

### Adversarial blocks (node RPCs)

| RPC | Description |
| --- | --- |
| `adv_buildblock` | Construct a block with full control over every field (prev, version, time, nbits, nonce, coinbase, transactions, merkle root, witness commitment, proof-of-work). Returns the block as hex; does not submit it. |
| `adv_sendblock` | Send a serialized block to a peer as a `block` message, with or without witness data. The block is not validated locally, so invalid blocks can be delivered. |

`adv_buildblock` performs **no policy/standardness checks** on the transactions
it includes — only consensus rules apply when a peer later validates the block.
This is the key to the chaoswallet workflow below: a transaction that would be
rejected from a mempool for being non-standard can still be mined into an
adversarial block and delivered to a victim.

### chaoswallet — adversarial transactions (wallet RPCs)

| RPC | Description |
| --- | --- |
| `adv_chaoswallet_setup` | Import descriptors for a wide range of script types (p2pk, p2wsh, p2sh-p2wsh, multisig in p2wsh and p2sh) so the wallet **tracks and can spend** outputs of each type. The four native descriptor-wallet types (legacy/p2sh-segwit/p2wpkh/p2tr) are already tracked. |
| `adv_createchaostx` | Build an adversarial transaction from the wallet's spendable coins. By default the node chooses everything itself (version, input/output counts, per-input sequences, output script types and the signing sighash type) from `/dev/urandom`; any field may be pinned via options. Outputs pay to wallet-tracked scripts so the transaction stays spendable and chaos transactions can be chained. |

By default a chaos transaction is **consensus-final** (`nLockTime=0`, BIP68
disabled) so it can be mined into a block even though it is typically
non-standard (e.g. zero fee, odd version, bare multisig / p2pk / anchor
outputs). Set `locktime`/`sequence` explicitly to build intentionally non-final
transactions that test block rejection.

Typical workflow to get a non-standard transaction confirmed by a victim:

```
adv_chaoswallet_setup
tx=$(adv_createchaostx '{"sighash":"ALL"}')          # -> hex
blk=$(adv_buildblock prev=<tip> txs="[$tx_hex]" solve=true)
adv_sendblock <peer_id> $blk_hex                      # victim accepts at consensus level
```

### Autonomous generators (parameterless RPCs)

These port the decision logic of the fuzzamoto IR generators into the node. Each
is a **parameterless** RPC: it takes no arguments and reads *every* choice from
`/dev/urandom`, so the controlling fuzzer drives the construction. They use the
node's own context (peers, chain, mempool, addrman) and send over its p2p stack.
The RPC is only the trigger; calling it once fires the generator once.

| RPC | fuzzamoto generator | Random choices |
| --- | --- | --- |
| `adv_gen_sendmessage` | SendMessage | message type (~38) + payload bytes |
| `adv_gen_inv` / `adv_gen_getdata` | GetData/Inventory | subset of known txs/blocks, inv type per item |
| `adv_gen_getaddr` | GetAddr | target peer |
| `adv_gen_addr` / `adv_gen_addrv2` | AddrRelay(V2) | 1..1000 addrs, per-addr network/services/port/time |
| `adv_gen_filterload` | BloomFilterLoad | size, bytes, hashfuncs, tweak, flags |
| `adv_gen_filteradd` / `adv_gen_filterclear` | FilterAdd/Clear | data |
| `adv_gen_cfilterquery` | CompactFilterQuery | getcfilters/getcfheaders/getcfcheckpt, type, height, stop hash |
| `adv_gen_compactblock` | CompactBlock | block, nonce, prefill subset, corrupted short ids |
| `adv_gen_blocktxn` | BlockTxn | block, (possibly wrong) tx set, block hash |
| `adv_gen_tx` | (relay) | mempool tx, with/without witness |
| `adv_gen_headers` | Block (header msg) | header set |
| `adv_gen_block` | Block/Tip/Reorg | prev, version, time, coinbase, tx subset, PoW |
| `adv_gen_addconnection` | AddConnection | count, connection type, v2transport, target |

The `chaoswallet` transaction generator (`adv_createchaostx`) covers fuzzamoto's
transaction generators: it builds the IR's full set of output script types
(p2pkh, p2sh, p2wpkh, p2tr, p2pk, p2wsh, p2sh-p2wsh, multisig, raw OP_TRUE
P2WSH/P2SH, OP_RETURN, pay-to-anchor) and, with low probability, applies
adversarial witness/annex mutation — all chosen from `/dev/urandom`. Taproot
outputs are built with a real `TaprootBuilder` tree (key-path, or with a
script-path leaf); `adv_chaoswallet_setup` imports a `tr(key,leaf)` descriptor so
the wallet tracks and can spend both the key path and the script path.

When `-adversarial` is set, the node also randomizes its **own handshake**
(fuzzamoto `LoadHandshakeOpts`) on every connection: the advertised `relay` flag
and `starting_height`, and whether it announces `wtxidrelay` / `sendaddrv2` /
`sendtxrcncl` (erlay) / `sendcmpct` (and the compact-block high-bandwidth bit) —
each choice read from `/dev/urandom`.

### Compact-block relay fuzzing (autonomous, in `net_processing`)

Unlike the RPC capabilities above, BIP152 compact-block relay is fuzzed
**autonomously** inside `net_processing`, because the adversarial behaviour
depends on the real, negotiated per-peer relay state (high/low bandwidth mode,
in-flight tracking) that an external driver cannot easily reconstruct. When
`-adversarial` is set the node mutates the compact-block messages it sends,
with every choice taken from `/dev/urandom`:

* **`cmpctblock`** (high-bandwidth announcement and low-bandwidth `getdata`
  response): a random subset of the block's transactions is prefilled and the
  remaining short ids are occasionally corrupted, forcing peers down the
  `getblocktxn` / reconstruction-failure paths.
* **`blocktxn`** (response to `getblocktxn`): transactions are randomly dropped,
  duplicated, replaced with other block transactions or appended, and the
  block hash is occasionally randomized.

## Testing

`test/functional/feature_adversarial.py` exercises the RPC surface, the
chaoswallet (including mining a non-standard chaos transaction into a block) and
the `-adversarial` gating.
