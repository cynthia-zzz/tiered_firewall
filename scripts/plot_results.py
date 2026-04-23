import matplotlib.pyplot as plt

# Figure 1: Bloom size m vs privacy metrics (fp rate, attacker confidence)
# fixed: n = 1000, k = 3, num of attacker flows = 10000

m_exponents = [10, 11, 12, 13, 14]

# from test_bloom_configs/results/
fp_counts_m = [8587, 4623, 1366, 266, 39]
fake_flows_m = 10000
fpr_m = [fp / fake_flows_m for fp in fp_counts_m]
confidence_m = [0.1043, 0.1778, 0.4227, 0.7899, 0.9625]

plt.figure(figsize=(6, 4))
plt.plot(m_exponents, confidence_m, marker='o', label='Attacker confidence')
plt.plot(m_exponents, fpr_m, marker='s', label='False positive rate')
plt.xlabel('Bloom size exponent m (Bloom bits = 2^m)')
plt.ylabel('Value')
plt.title('Effect of Bloom Size on Privacy')
plt.xticks(m_exponents)
plt.ylim(0, 1.05)
plt.legend()
plt.tight_layout()
plt.savefig('figure1_m_vs_privacy.png', dpi=300)
plt.close()

# Figure 2: Number of flows n vs privacy metrics (fp rate, attacker confidence)
# fixed: m = 12, k = 3, num of attacker flows = 10000

n_values = [100, 500, 1000, 2000, 5000, 10000]

# from test_bloom_configs/results/
fp_counts_n = [1, 235, 1366, 4687, 9262, 9974]
fake_flows_n = 10000
fpr_n = [fp / fake_flows_n for fp in fp_counts_n]
confidence_n = [0.9901, 0.6803, 0.4227, 0.2970, 0.3506, 0.5007]

plt.figure(figsize=(6, 4))
plt.plot(n_values, confidence_n, marker='o', label='Attacker confidence')
plt.plot(n_values, fpr_n, marker='s', label='False positive rate')
plt.xlabel('Number of inserted flows n')
plt.ylabel('Value')
plt.title('Effect of Flow Volume on Privacy')
plt.xticks(n_values)
plt.ylim(0, 1.05)
plt.legend()
plt.tight_layout()
plt.savefig('figure2_n_vs_privacy.png', dpi=300)
plt.close()


# Figure 3: Bloom size m vs fraction of adversarial traffic reaching exact layer
# fixed: n = 1000, k = 3, num of attack flows = 10000

# from test_pipeline_burden/results/
burden_fraction_by_m = {
    11: 0.4633,
    12: 0.1374,
    13: 0.0280,
    14: 0.0040,
}

m_burden = sorted(burden_fraction_by_m.keys())
burden_fraction_m = [burden_fraction_by_m[m] for m in m_burden]

plt.figure(figsize=(6, 4))
plt.plot(m_burden, burden_fraction_m, marker='o')
plt.xlabel('Bloom size exponent m (Bloom bits = 2^m)')
plt.ylabel('Fraction of adversarial traffic reaching Exact')
plt.title('Effect of Bloom Size on Exact-Layer Burden')
plt.xticks(m_burden)
plt.ylim(0, 1.05)
plt.tight_layout()
plt.savefig('figure3_m_vs_burden.png', dpi=300)
plt.close()


# Figure 4: Number of flows n vs fraction of adversarial traffic reaching exact layer
# fixed: m = 2^12, k = 3, fake attack flows = 10000

# from test_pipeline_burden/results
burden_fraction_by_n = {
    100: 0.0002,
    500: 0.0286,
    1000: 0.1374,
    2000: 0.4692,
    5000: 0.9271,
    10000: 0.9972,
}

n_burden = sorted(burden_fraction_by_n.keys())
burden_fraction_n = [burden_fraction_by_n[n] for n in n_burden]

plt.figure(figsize=(6, 4))
plt.plot(n_burden, burden_fraction_n, marker='o')
plt.xlabel('Number of inserted flows n')
plt.ylabel('Fraction of adversarial traffic reaching Exact')
plt.title('Effect of Flow Volume on Exact-Layer Burden')
plt.xticks(n_burden)
plt.ylim(0, 1.05)
plt.tight_layout()
plt.savefig('figure4_n_vs_burden.png', dpi=300)
plt.close()


# Figure 5: Attacker confidence vs fraction of adversarial traffic reaching exact layer
 
tradeoff_by_m = {
    11: (0.1778, 0.4633),
    12: (0.4227, 0.1374),
    13: (0.7899, 0.0280),
    14: (0.9625, 0.0040),
}

tradeoff_keys = sorted(tradeoff_by_m.keys())
tradeoff_conf = [tradeoff_by_m[m][0] for m in tradeoff_keys]
tradeoff_burden = [tradeoff_by_m[m][1] for m in tradeoff_keys]

plt.figure(figsize=(6, 4))
plt.plot(tradeoff_conf, tradeoff_burden, marker='o')
for m, x, y in zip(tradeoff_keys, tradeoff_conf, tradeoff_burden):
    plt.annotate(f"m=2^{m}", (x, y), textcoords="offset points", xytext=(4, 4))
plt.xlabel('Attacker confidence')
plt.ylabel('Fraction of adversarial traffic reaching Exact')
plt.title('Privacy–Functionality Tradeoff')
plt.xlim(0, 1.05)
plt.ylim(0, 1.05)
plt.tight_layout()
plt.savefig('figure5_tradeoff.png', dpi=300)
plt.close()

print("Saved figures:")
print("  figure1_m_vs_privacy.png")
print("  figure2_n_vs_privacy.png")
print("  figure3_m_vs_burden.png")
print("  figure4_n_vs_burden.png")
print("  figure5_tradeoff.png")
