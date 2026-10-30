# D.S.I — Decentralized Swarm Investigation

An exposure scanner for Ethereum mainnet hot wallets. For each wallet it lists what an attacker
also gets if they get an **EIP-7702 delegation onto the wallet, or its key**: contracts and smart
accounts the wallet owns, token allowances it has granted, and the value held in all of them.

It is read-only. It holds no private key, signs nothing, sends no transaction, and needs no API key.
It uses only the Python 3 standard library (3.10 or newer), so there is nothing to install.

## Why

On 2026-10-29 the wallet `0x28C6c06298d514Db089934071355E5743bf21d60` (Binance 14 on Etherscan)
carried an EIP-7702 delegation to `0x63e842b054bd624a465454d533c33f573e9c6fae` from block 26300753
to block 26301895. Through it the caller also emptied `0xEe7aE85f2Fe2239E27D9c1E23fFFe168D63b4055`,
a Circle SingleOwnerMSCA smart account whose `getNativeOwner()` is that wallet. The wallet's own
balance was not the whole exposure: everything the wallet *owns* went with it. D.S.I finds that
inherited exposure before an incident.

## Run it

```sh
./scan --wallets examples/wallets.json                       # at the latest block
./scan --wallets examples/wallets.json --block 26300700 \
       --candidates examples/candidates.json --out reports/  # at a past block (needs an archive RPC)
```

`python3 -m dsi scan --wallets …` does the same. Options:

| Option | Meaning |
| --- | --- |
| `--wallets FILE` | JSON list of addresses, or of `{"address": …, "label": …}` (required) |
| `--block N` | report block; default is the latest block, read once and used for every call |
| `--candidates FILE` | JSON list of extra contract addresses to confirm as owned, like the event candidates |
| `--config FILE` | config file; default `$DSI_CONFIG`, else `./dsi.config.json` if present, else built-in defaults |
| `--out DIR` | where `report.json` and `report.md` go (default: current directory) |
| `--quiet` | no progress on stderr |

Progress (which endpoint is used, rotations, chunk halving, call counts) goes to stderr.

Run the tests (offline, from recorded fixtures):

```sh
python3 -m unittest discover -s tests -v
```

## Configuration

Copy `dsi.config.example.json` to `dsi.config.json` and edit it; it lists every key with its
default. Environment variables override the file:

| Key / variable | Meaning |
| --- | --- |
| `rpcUrls` / `DSI_RPC_URLS` (comma-separated) | rotation list of public mainnet endpoints. Each is checked with `eth_chainId` before use; 429/503 are retried twice with a growing pause, any other failure retires the endpoint for the run |
| `archiveRpcUrls` / `DSI_ARCHIVE_RPC_URLS` | endpoints for state at old blocks, used whenever `--block` is given. Empty means use `rpcUrls`; many public nodes refuse historical `eth_call`, so set one for past blocks |
| `timeoutSeconds` / `DSI_TIMEOUT` | timeout of every RPC and HTTP request |
| `history.sources` | where log history comes from, tried in order: `blockscout`, `rpc` |
| `history.blockscoutUrl`, `blockscoutTimeoutSeconds`, `blockscoutStartBlock` | the keyless Blockscout logs API and the first block asked of it (default 0, all history) |
| `history.rpcStartBlock`, `rpcChunkBlocks`, `rpcMaxChunkBlocks` | the `eth_getLogs` backfill: first block, starting chunk, largest chunk |
| `history.cacheDir` / `DSI_CACHE_DIR` | where the log stores and watermarks live (default `.dsi-cache/`) |
| `safeTransactionService` | Safe Transaction Service base URL; empty string disables it |
| `multicallBatchSize` | calls per Multicall3 `aggregate3` batch |
| `tokens` | ERC-20s whose balances are read for every owned account (USDC, USDT, WETH, DAI, WBTC by default); approved tokens are added per wallet |

## How it works

1. **Delegation.** `eth_getCode(wallet, block)`. `0xef0100` followed by 20 bytes is an EIP-7702
   delegation to that address; other code is a contract; `0x` is a plain account.
2. **History.** For each wallet four log filters are kept, each naming the wallet in an indexed topic:

   | Filter | Event | Wallet in |
   | --- | --- | --- |
   | `ownershipTransferred` | `OwnershipTransferred(address indexed previousOwner, address indexed newOwner)` (OpenZeppelin `Ownable`) | `newOwner` |
   | `accountOwnershipTransferred` | `OwnershipTransferred(address indexed account, address indexed previousOwner, address indexed newOwner)`, emitted by Circle's `SingleOwnerMSCA` (native owner) and by the ERC-6900 `SingleOwnerPlugin` (circlefin/buidl-wallet-contracts) | `newOwner` |
   | `roleGranted` | `RoleGranted(bytes32 indexed role, address indexed account, address indexed sender)` | `account` |
   | `approval` | `Approval(address indexed owner, address indexed spender, uint256 value)` (ERC-20, three topics) | `owner` |

   Each filter has a store file in `cacheDir` with its logs and the block range covered (the
   watermark). A scan at block N reads the store and fetches only blocks above the watermark, then
   appends them; a second scan over the same range makes no log requests at all. For a missing range
   the Blockscout logs API is asked first; if it does not answer (timeout, 429, error) the range
   comes from chunked `eth_getLogs`, which halves its chunk on any refusal, timeout or JSON-RPC
   range/result-limit error (rate/quota errors and other JSON-RPC errors rotate to the next endpoint), doubles it
   again after a success, and saves the watermark after every chunk so an interrupted backfill resumes.
3. **Owned contracts and accounts.** Candidates are the emitting contracts of `OwnershipTransferred`
   and `RoleGranted`, the `account` of the MSCA / plugin events, the Safes the Safe Transaction Service
   lists under `owners/<wallet>/safes`, and the `--candidates` file. Each is confirmed at the report
   block with `owner()`, `getNativeOwner()`, `isOwner(wallet)`, `hasRole(role, wallet)` for every role
   seen granted, and `plugin.getOwnerOf(account)` for plugin events. A candidate is listed as owned
   only if one of these names the wallet; the rest go to `droppedCandidates`. The wallet's own address
   is never its own candidate, so its balances are counted once.
4. **Allowances.** Each `(token, spender)` pair from the Approval logs is read with
   `allowance(wallet, spender)` at the report block; only values above zero are listed.
5. **Value at stake.** ETH and token balances of every owned account, plus the wallet's own balance of
   each token it has an allowance on, and its own ETH.

All state (owners, roles, allowances, balances, ETH via `getEthBalance`, symbols, decimals) is read
through Multicall3 `0xcA11bde05977b3631167028862bE2a173976CA11` `aggregate3` at the report block,
with failures allowed per call. A malformed or short `aggregate3` answer is reported as an error rather
than treated as a zero balance: the result count must equal the call count, and a body cut off
before its results, or a null `eth_call` result, is an error for that wallet. Only `eth_getCode` and `eth_getLogs` are separate requests. A Safe
reported by the Safe Transaction Service, or any candidate confirmed by `isOwner(wallet)` that also
answers both calls (a Safe from `--candidates`, or with the service disabled or down), is confirmed
with `getOwners()` and `getThreshold()`; a
threshold-one Safe is included in owned-account value, while a higher-threshold Safe is shown as
**Shared control** and excluded from value at stake.

## Reading the report

`report.json` is a list with one object per wallet; `report.md` has one table per wallet.

| Field / row | Meaning |
| --- | --- |
| `delegation` / **Delegation** | `plain-account`, `contract`, or `eip7702-delegated` with `delegate`: the code that runs as this wallet. A delegate you did not set means the wallet and everything below is already compromised |
| `ownedAccounts` / **Owned account** | contracts and smart accounts the wallet controls at the block: `confirmedBy` (the view calls that named the wallet), `sources` (how it was found), `ethWei`, `tokens` (non-zero balances, raw units with symbol and decimals) |
| `droppedCandidates` | candidates found but not controlled at the block (ownership moved away, role revoked, or not an owned contract) |
| `allowances` / **Allowance** | token, spender, current allowance; `unlimited` is true at or above 2^255 (max uint256, including max after the token decremented it) |
| `valueAtStake` / **Value at stake** | per asset: `wallet` (its ETH, and its balance of approved tokens), `ownedAccounts` (summed), `total` |
| `historyCoverage` | for each filter, the block range searched and the sources used; an `error` means the filter could not be read and its section may be incomplete |
| `sharedControl` / **Shared control** | Safes for which this wallet is an owner but more than one signature is required; owners and threshold are reported, but their balances are not counted as individually exposed |

Amounts in `report.json` are decimal strings in base units; `report.md` shows them scaled by decimals.

## Limits

- **Ownership recorded without an event is invisible to discovery.** An owner set in a constructor
  without emitting an event, written directly to storage, set via a factory's own event, or inherited
  through a proxy admin, is not found. Add such contracts to `--candidates`; they are confirmed the same way.
- **Events the tool does not know.** Other ownership schemes (Ownable2Step's pending owner, custom
  `OwnerChanged`/`AdminChanged` events, Safe owners not indexed by the Transaction Service, ERC-6900
  v0.8 validation modules, multisig signer sets other than Safe, Kernel/Biconomy/other smart accounts)
  are not searched. ERC-721/1155 approvals (`Approval` with an indexed token id, `ApprovalForAll`),
  Permit2 allowances and EIP-2612 signatures that were signed but never used are not covered.
- **Confirmation is by known view calls.** A contract that is controlled by the wallet but answers none
  of `owner()`, `getNativeOwner()`, `isOwner`, `hasRole` or `getOwnerOf` is dropped.
- **Token coverage.** Owned-account balances are read for the configured `tokens` plus tokens the wallet
  approved; other ERC-20s an owned account holds are not discovered. Prices are not looked up.
- **History coverage is what `historyCoverage` says.** The Blockscout watermark stops at the
  explorer's indexed head, so a lagging explorer never records an unsearched range as covered. If the explorer does not answer and
  `rpcStartBlock` is above 0, that filter starts at `rpcStartBlock`. Logs are not reorg-checked: a scan
  at the very tip can store a log that is later reorged out.
- **Store integrity.** The cache trusts its files; delete `cacheDir` to rebuild from scratch.
- **Safe and endpoint availability.** The Safe Transaction Service is advisory and may be unavailable;
  a wallet-level RPC failure is recorded in the reports while other wallets continue. A Safe threshold
  of one indicates unilateral execution at that block, not that all other access paths have been found.
- **Range-limit errors are recognised by wording.** A JSON-RPC `eth_getLogs` error whose message
  mentions a range, limit or size shrinks the chunk; rate/quota wording takes precedence and retires
  the endpoint immediately. After rotation the next endpoint starts with `rpcChunkBlocks` again.
  Other messages retire the endpoint; unfamiliar throttling wording can still be mistaken for a size limit.
- **Allowance, Safe, role and pagination paths have no recorded mainnet fixture yet.** They are covered
  by the synthetic chains in `tests/test_units.py` only; the second recording asked for in point 6 of
  the review is still outstanding. The Blockscout indexed-head entry in the incident fixture was added
  by hand (decimal form; the live API answers hex, and both are accepted) when the head request was
  introduced, and equals the last scan block, so the lagging-head case is covered by the unit test only.

## Tests and fixtures

- `tests/test_incident_replay.py` replays `tests/fixtures/incident-2026-10-29.json`, a recording of
  every request the scanner made for four scans of Binance 14 sharing one cache: block 26300700 (with
  `tests/fixtures/candidates.json`), 26300760, 26301900, and 26301900 again. It checks the delegation
  to `0x63e8…6fae` at 26300760 and a plain account at 26301900; the MSCA `0xEe7a…4055` owned at
  26300700, confirmed by `getNativeOwner()` and found from its `OwnershipTransferred` event, with its
  USDC balance; USDC (from the candidates file) dropped as not owned; that the appended scan only asks
  for blocks above the watermark and that the repeat scan makes no log requests. The replay transport
  fails on any request not in the fixture, so the suite cannot reach the network.
- `tests/test_units.py` covers Keccak-256, the `aggregate3` encoding, delegation parsing, the
  confirmation rules on a synthetic chain (zero allowances and lost ownership are not listed, all reads
  at the report block), Safe thresholds (including Safes reached through `--candidates` with the
  service disabled), short, truncated and null `aggregate3` answers, JSON-RPC error rotation and
  per-wallet error entries, range-limit chunk shrinking, a lagging explorer's watermark, and that the
  package contains no signing or sending code.
- `tests/record_fixture.py` re-records the fixture:
  `DSI_RPC_URLS=<archive mainnet RPC> python3 tests/record_fixture.py`. Only methods, parameters and
  answers are stored, never the endpoint URL. In the recording, Blockscout answered three filters over
  all history and timed out on `approval`, which therefore came from `eth_getLogs` from block 26290000
  (the fixture config's `rpcStartBlock`); the later appends hit Blockscout's rate limit and fell back to RPC.

## Layout

```
scan                     entry point (python3 script)
dsi/cli.py               argument parsing, report files
dsi/scan.py              delegation, candidates, confirmation, allowances, value at stake
dsi/history.py           log stores with watermarks; Blockscout and eth_getLogs sources
dsi/transport.py         HTTP with timeouts, RPC rotation, record/replay transports
dsi/abi.py, keccak.py    ABI encoding/decoding, Multicall3 aggregate3, Keccak-256
dsi/report.py            report.json and report.md
dsi/config.py            defaults, config file, environment
examples/                sample wallets.json and candidates.json
tests/                   offline tests, fixtures, and the fixture recorder
```

License: MIT (see `LICENSE`).
