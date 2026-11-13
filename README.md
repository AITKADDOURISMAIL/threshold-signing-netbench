# threshold-signing-netbench

Code and data for the paper *Threshold Signing for Exchange Hot Wallets over Real
Wireless Networks: FROST versus CGGMP with Preprocessing* (I. Ait Kaddour, Y. Maleh,
M. Lahby; submitted to IWCMC 2027).

- `src/`, `experiments.ps1`: the networked benchmark (`net-bench`)
- `results/`: all measurements (see `results/README.md` for which series are used)
- `analysis/`: figures of the paper and the script that produces them (`python analysis/plot_net.py`)

## net-bench: FROST vs CGGMP threshold signing over a real network

Each party is a separate process, normally on a separate machine, and the
parties exchange messages over TCP. Node 0 is the coordinator and one of the
signers; it measures the end-to-end latency of every signature (from the
signing request to a verified signature), the round-trip time to every node,
and, for CGGMP, the split between presigning (rounds 1-3, independent of the
message) and online signing (round 4).

The output `results/summary.csv` also gives the latency predicted by the
analytic model of the journal article (CPU on the critical path + one-way
delay x sequential steps), so the model can be checked against measurements.

## Build (on every machine)

```powershell
cargo build --release
```

## Allow incoming connections (Windows, once, PowerShell as administrator)

```powershell
New-NetFirewallRule -DisplayName "net-bench" -Direction Inbound -Protocol TCP -LocalPort 7100-7199 -Action Allow
```

## Run the experiments on two machines

Find the IP address of each machine with `ipconfig` (IPv4 address), then run the
same command on both machines, changing only `-Machine`:

```powershell
# machine A (coordinator, writes the results)
.\experiments.ps1 -Machine A -IpA 192.168.1.10 -IpB 192.168.1.20 -Label wifi
# machine B
.\experiments.ps1 -Machine B -IpA 192.168.1.10 -IpB 192.168.1.20 -Label wifi
```

The script runs FROST and CGGMP in the (2,3) and (3,5) configurations. The first
CGGMP run generates the key material (Paillier keys) once per configuration and
caches it in `cggmp_keys_*.bin`.

Use a different `-Label` for each network (e.g. `ethernet`, `wifi`,
`wifi-busy`). `-DelayMs 25` adds an emulated one-way delay to every message,
which emulates a wide-area network on top of the local one.

## Single command (any number of machines)

```
net-bench --id <i> --config nodes.txt --proto frost|frost-pre|cggmp --t <t> [--count N] [--label L] [--delay-ms D]
```

`nodes.txt` contains one line per node, `<id> <host>:<port>`, ids 0..n-1. Node i
connects to every node j > i.

`--proto frost-pre` runs FROST with preprocessing: before the timed signatures,
every signer publishes one commitment per future signature (round 1 done in
advance, as allowed by RFC 9591), so that each timed signature needs only the
signing package and the signature shares. With `experiments.ps1`, use `-Set frostpre`.

## Notes and limitations

- Key material comes from a dealer with a fixed seed, so that every machine
  derives the same keys; a fingerprint is checked at connection time. This is
  for benchmarking only.
- Messages between parties are authenticated with the `manul` test signatures
  (no real signature cost) and sent over plain TCP (no TLS).
- `synedrion` 0.3 binds the message to the session from round 1, so true
  pre-signatures are not available; the online cost is measured as the time of
  round 4, the only round that uses the message in CGGMP'24.

## License

MIT. Research code, not production software.
