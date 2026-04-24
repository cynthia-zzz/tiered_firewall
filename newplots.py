import numpy as np
import matplotlib.pyplot as plt

P = 1e-6  # extremely sparse flow space

f_vals = np.linspace(1e-6, 0.2, 100)
confidence = P / (P + (1 - P) * f_vals)

plt.plot(f_vals, confidence)
plt.xlabel("False Positive Rate (f)")
plt.ylabel("Attacker Confidence")
plt.title("Attacker Confidence vs False Positive Rate")
plt.grid(True)
plt.savefig("test_fig.png", dpi=300)
plt.show()
plt.close()
