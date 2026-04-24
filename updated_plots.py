import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

# ----------------------------
# Core metric definitions
# ----------------------------

def analytical_fpr(m, n, k=3):
    return (1 - np.exp(-k * n / m)) ** k

def attacker_confidence(P, f):
    return P / (P + (1 - P) * f)

# Choose realistic attacker prior
# You can adjust this, but keep it small.
P = 1e-6
k = 3

# ----------------------------
# Table 1: varying m, fixed n=1000
# ----------------------------

m_data = pd.DataFrame({
    "m_exp": [10, 11, 12, 13, 14],
    "m": [2**10, 2**11, 2**12, 2**13, 2**14],
    "n": [1000, 1000, 1000, 1000, 1000],
    "fp": [8582, 4570, 1352, 296, 38],
    "fake_probes": [10000]*5,
})

m_data["observed_f"] = m_data["fp"] / m_data["fake_probes"]
m_data["analytical_f"] = analytical_fpr(m_data["m"], m_data["n"], k)
m_data["probing_precision"] = m_data["n"] / (m_data["n"] + m_data["fp"])
m_data["attacker_confidence"] = attacker_confidence(P, m_data["observed_f"])
m_data["exact_layer_burden"] = m_data["observed_f"]

# ----------------------------
# Table 2: varying n, fixed m=2^12
# ----------------------------

n_data = pd.DataFrame({
    "n": [100, 500, 1000, 2000, 5000],
    "m": [2**12]*5,
    "fp": [2, 242, 1352, 4645, 9261],
    "fake_probes": [10000]*5,
})

n_data["observed_f"] = n_data["fp"] / n_data["fake_probes"]
n_data["analytical_f"] = analytical_fpr(n_data["m"], n_data["n"], k)
n_data["probing_precision"] = n_data["n"] / (n_data["n"] + n_data["fp"])
n_data["attacker_confidence"] = attacker_confidence(P, n_data["observed_f"])
n_data["exact_layer_burden"] = n_data["observed_f"]

# ----------------------------
# Figure 1: analytical vs observed f, varying m
# ----------------------------

plt.figure(figsize=(7, 4.5))
plt.plot(m_data["m_exp"], m_data["analytical_f"], marker="o", label="Analytical f")
plt.plot(m_data["m_exp"], m_data["observed_f"], marker="s", label="Observed f / exact-layer burden")
plt.xlabel(r"Bloom filter size $m = 2^x$")
plt.ylabel("False positive rate")
plt.title(r"False Positive Rate vs Bloom Filter Size ($n=1000$, $k=3$)")
plt.legend()
plt.grid(True, alpha=0.3)
plt.tight_layout()
plt.savefig("fig1: analytical vs observed f, varying m", dpi=300)
plt.show()

# ----------------------------
# Figure 2: analytical vs observed f, varying n
# ----------------------------

plt.figure(figsize=(7, 4.5))
plt.plot(n_data["n"], n_data["analytical_f"], marker="o", label="Analytical f")
plt.plot(n_data["n"], n_data["observed_f"], marker="s", label="Observed f / exact-layer burden")
plt.xlabel(r"Number of inserted flows $n$")
plt.ylabel("False positive rate")
plt.title(r"False Positive Rate vs Flow Volume ($m=2^{12}$, $k=3$)")
plt.legend()
plt.grid(True, alpha=0.3)
plt.tight_layout()
plt.savefig("fig2: analytical vs observed f, varying n", dpi=300)
plt.show()

# ----------------------------
# Figure 3: probing precision vs attacker confidence, varying m
# Use log-scale for attacker confidence because it is tiny.
# ----------------------------

plt.figure(figsize=(7, 4.5))
plt.plot(m_data["m_exp"], m_data["probing_precision"], marker="o", label="Probing precision")
plt.plot(m_data["m_exp"], m_data["attacker_confidence"], marker="s", label="Attacker confidence")
plt.yscale("log")
plt.xlabel(r"Bloom filter size $m = 2^x$")
plt.ylabel("Metric value (log scale)")
plt.title(r"Probing Precision vs Attacker Confidence ($n=1000$)")
plt.legend()
plt.grid(True, alpha=0.3, which="both")
plt.tight_layout()
plt.savefig("fig3: probing precision vs attacker confidence, varying m", dpi=300)
plt.show()

# ----------------------------
# Figure 4: probing precision vs attacker confidence, varying n
# ----------------------------

plt.figure(figsize=(7, 4.5))
plt.plot(n_data["n"], n_data["probing_precision"], marker="o", label="Probing precision")
plt.plot(n_data["n"], n_data["attacker_confidence"], marker="s", label="Attacker confidence")
plt.yscale("log")
plt.xlabel(r"Number of inserted flows $n$")
plt.ylabel("Metric value (log scale)")
plt.title(r"Probing Precision vs Attacker Confidence ($m=2^{12}$)")
plt.legend()
plt.grid(True, alpha=0.3, which="both")
plt.tight_layout()
plt.savefig("fig4: probing precision vs attacker confidence, varying n", dpi=300)
plt.show()

# ----------------------------
# Figure 5: exact-layer burden vs attacker confidence
# This is the key "saturation" plot.
# ----------------------------

combined = pd.concat([
    m_data.assign(sweep="varying m"),
    n_data.assign(sweep="varying n")
], ignore_index=True)

plt.figure(figsize=(7, 4.5))
for sweep, df in combined.groupby("sweep"):
    plt.scatter(df["exact_layer_burden"], df["attacker_confidence"], label=sweep)

plt.yscale("log")
plt.xlabel("Exact-layer burden / observed false positive rate")
plt.ylabel("Attacker confidence (log scale)")
plt.title("Attacker Confidence Remains Negligible While Burden Varies")
plt.legend()
plt.grid(True, alpha=0.3, which="both")
plt.tight_layout()
plt.savefig("fig5: exact-layer burden vs attacker confidence", dpi=300)
plt.show()

# ----------------------------
# Figure 6: privacy-cost saturation curve
# Theoretical curve using a wide range of f.
# ----------------------------

f_vals = np.linspace(1e-6, 1.0, 1000)
conf_vals = attacker_confidence(P, f_vals)

plt.figure(figsize=(7, 4.5))
plt.plot(f_vals, conf_vals)
plt.scatter(combined["observed_f"], combined["attacker_confidence"], marker="o", label="Experimental configurations")
plt.yscale("log")
plt.xlabel("False positive rate / exact-layer burden")
plt.ylabel("Attacker confidence (log scale)")
plt.title("Privacy Saturation: Confidence Is Negligible Across Configurations")
plt.legend()
plt.grid(True, alpha=0.3, which="both")
plt.tight_layout()
plt.savefig("fig6: privacy-ost saturation curve", dpi=300)
plt.show()
