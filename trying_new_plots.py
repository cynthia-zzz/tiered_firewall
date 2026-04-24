import numpy as np
import matplotlib.pyplot as plt

# ---- Parameters ----
k = 3                  # number of hash functions (adjust if needed)
P = 1e-6               # prior probability (very small!)

# ---- Bloom filter false positive rate ----
def bf_false_positive_rate(m, n, k):
    return (1 - np.exp(-k * n / m)) ** k

# ---- Attacker confidence ----
def attacker_confidence(P, f):
    return P / (P + (1 - P) * f)


# f1: attacker confidence vs f
f_vals = np.linspace(1e-6, 0.2, 200)
conf_vals = attacker_confidence(P, f_vals)

plt.figure()
plt.plot(f_vals, conf_vals)
plt.xlabel("False Positive Rate (f)")
plt.ylabel("Attacker Confidence")
plt.title("Attacker Confidence vs False Positive Rate")
plt.grid(True)
plt.savefig("test_fig1.png", dpi=300)
plt.show()
plt.close()

# f2: BF size (m) vs orivacy
n = 1000
m_vals = np.linspace(100, 10000, 100)

f_vals = bf_false_positive_rate(m_vals, n, k)
conf_vals = attacker_confidence(P, f_vals)

plt.figure()
plt.plot(m_vals, conf_vals)
plt.xlabel("Bloom Filter Size (m)")
plt.ylabel("Attacker Confidence")
plt.title("Effect of Bloom Filter Size on Attacker Confidence")
plt.grid(True)
plt.savefig("test_fig2.png", dpi=300)
plt.show()
plt.close()

# f3: num real flow (n) vs privacy
m = 2000
n_vals = np.linspace(100, 5000, 100)

f_vals = bf_false_positive_rate(m, n_vals, k)
conf_vals = attacker_confidence(P, f_vals)

plt.figure()
plt.plot(n_vals, conf_vals)
plt.xlabel("Number of Flows (n)")
plt.ylabel("Attacker Confidence")
plt.title("Effect of Flow Volume on Attacker Confidence")
plt.grid(True)
plt.savefig("test_fig3.png", dpi=300)
plt.show()
plt.close()

# f4: exact layer burden vs f
f_vals = np.linspace(0, 0.2, 100)
burden = f_vals  # approx: fraction forwarded

plt.figure()
plt.plot(f_vals, burden)
plt.xlabel("False Positive Rate (f)")
plt.ylabel("Fraction Forwarded to Exact Layer")
plt.title("Exact Layer Burden vs False Positive Rate")
plt.grid(True)
plt.savefig("test_fig4.png", dpi=300)
plt.show()
plt.close()

# f5: attacker confidence vs exact layer burden
f_vals = np.linspace(1e-6, 0.2, 200)
conf_vals = attacker_confidence(P, f_vals)

plt.figure()
plt.plot(f_vals, conf_vals)
plt.xlabel("Exact Layer Burden (≈ f)")
plt.ylabel("Attacker Confidence")
plt.title("Privacy–Cost Tradeoff")
plt.grid(True)
plt.savefig("test_fig5.png", dpi=300)
plt.show()
plt.close()
