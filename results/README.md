# net-bench measurements (November 2026)

Two laptops: machine A (Intel Core i5-1035G1, 8 GB) and machine B (Intel Core 3 100U, 8 GB), Windows 11, Rust 1.99.1.
`summary.csv` has one line per experiment; the other files contain every signature.

| Label | Network | Added one-way delay | Notes |
|---|---|---|---|
| home, home25, home50 | home network H: machine B wired (USB Ethernet, 100 Mb/s), machine A on Wi-Fi of the same router, power saving off | 0 / 25 / 50 ms | reference environment, FROST, FROST with preprocessing and CGGMP |
| test | one machine (localhost) | 0 | functional test |
| wifi, wifi2 | public Wi-Fi W1, day 1 | 0 | |
| wan25, wan50 | W1 | 25 / 50 ms | old version (imprecise emulated delay), not used |
| wan25v2 | W1 | 25 ms | machine B still on the old version, not used |
| wan25v3, wan50v2 | W1 | 25 / 50 ms | used; RTT to machine B includes Wi-Fi power saving |
| wifi2 (frost-pre), wifi3 | public Wi-Fi W2, day 2 | 0 | Wi-Fi power saving disabled on machine B |
| wan25v3 (frost-pre), wan50v3 (frost-pre) | W2 | 25 / 50 ms | used |
| wan50v2 (frost-pre) | W2 | 50 ms | machine B ran with 25 ms by mistake, not used |
| pson25, pson25b, pson25c | H, Wi-Fi power saving of machine A set to maximum power saving | 25 ms | A/B test (CGGMP reduced to 5 or 1 signatures) |
| psoff25, psoff25b, psoff25c | H, Wi-Fi power saving of machine A set to maximum performance | 25 ms | A/B test, alternated with the runs above |

`throughput.csv`: sustained throughput on H (label `home`, no added delay), with 16 FROST
signatures or 4 CGGMP signatures in flight (`experiments.ps1 -Set throughput`).
