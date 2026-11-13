"""Plots the network measurements of net-bench (results/summary.csv).

Usage: python plot_net.py   (run from the net-bench folder)
Produces analysis/fig_latency_vs_rtt.pdf and analysis/fig_model_vs_measured.pdf.

Series used (see results/README.md): home, home25, home50 (home network);
wifi, wifi2, wifi3 (Wi-Fi, no added delay),
wan25v3 and wan50v2 (25 / 50 ms emulated one-way delay, FROST and CGGMP),
wan25v3 and wan50v3 (FROST with preprocessing).
"""
import csv
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

USE = {("wifi", "frost"), ("wifi", "cggmp"), ("wifi2", "frost"), ("wifi2", "cggmp"),
       ("wan25v3", "frost"), ("wan25v3", "cggmp"), ("wan50v2", "frost"), ("wan50v2", "cggmp"),
       ("wifi3", "frost"), ("wifi3", "cggmp"), ("wifi2", "frost-pre"),
       ("wan25v3", "frost-pre"), ("wan50v3", "frost-pre")}
USE |= {(l, p) for l in ("home", "home25", "home50") for p in ("frost", "frost-pre", "cggmp")}

rows = [r for r in csv.DictReader(open("results/summary.csv")) if (r["label"], r["proto"]) in USE]

# Figure 1: latency against measured RTT
fig, ax = plt.subplots(figsize=(5.2, 3.8))
sty = {"cggmp": ("CGGMP, full", "#c05621", "s"), "frost": ("FROST, full (round 1 online)", "#2b6cb0", "o"),
       "frost-pre": ("FROST, preprocessed round 1", "#6b46c1", "D"), "online": ("CGGMP, online round only", "#2f855a", "^")}
for key, (lab, c, m) in sty.items():
    pts = [(float(r["rtt_ms"]), float(r["online_median_ms"] if key == "online" else r["latency_median_ms"]))
           for r in rows if r["proto"] == ("cggmp" if key == "online" else key)]
    ax.scatter(*zip(*pts), label=lab, color=c, marker=m, s=28, zorder=3)
x = np.logspace(np.log10(3), np.log10(250), 50)
ax.plot(x, x, "k:", lw=1); ax.plot(x, 2 * x, "k--", lw=0.8, alpha=0.6)
ax.set_xscale("log"); ax.set_yscale("log"); ax.set_ylim(2, 20000)
ax.set_xlabel("measured RTT to remote signers (ms)"); ax.set_ylabel("median signing latency (ms)")
ax.grid(alpha=0.25, which="both"); ax.legend(fontsize=7, loc="upper left", ncol=2)
plt.tight_layout(); plt.savefig("analysis/fig_latency_vs_rtt.pdf")

# Figure 2: model against measurement
fig, ax = plt.subplots(figsize=(3.4, 3.0))
for key in ["frost", "frost-pre", "cggmp"]:
    lab, c, m = sty[key]
    pts = [(float(r["model_ms"]), float(r["latency_median_ms"])) for r in rows if r["proto"] == key]
    ax.scatter(*zip(*pts), label=lab, color=c, marker=m, s=22, zorder=3)
x = np.logspace(0.6, 4, 50)
ax.plot(x, x, "k:", lw=1); ax.fill_between(x, 0.9 * x, 1.1 * x, color="grey", alpha=0.15, label="±10%")
ax.set_xscale("log"); ax.set_yscale("log"); ax.set_xlabel("model latency (ms)"); ax.set_ylabel("measured median latency (ms)")
ax.grid(alpha=0.25, which="both"); ax.legend(fontsize=6.5, loc="upper left")
plt.tight_layout(); plt.savefig("analysis/fig_model_vs_measured.pdf")
print("written analysis/fig_latency_vs_rtt.pdf and analysis/fig_model_vs_measured.pdf")
