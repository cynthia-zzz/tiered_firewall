import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker

import matplotx

# Data
df_m = pd.DataFrame({
    "m": [10, 11, 12, 13, 14],
    "ε": [0.8582, 0.4570, 0.1352, 0.0296, 0.0038],
    "AC": [0.000001, 0.000002, 0.000007, 0.000034, 0.000263],
})

df_n = pd.DataFrame({
    "n": [100, 500, 1000, 2000, 5000],
    "ε": [0.0002, 0.0242, 0.1352, 0.4645, 0.9261],
    "AC": [0.004975, 0.000041, 0.000007, 0.000002, 0.000001],
})

# Plot styling
plt.rcParams.update({
    "font.size": 12,
    "axes.titlesize": 17,
    "axes.labelsize": 14,
    "xtick.labelsize": 12,
    "ytick.labelsize": 12,
    "legend.fontsize": 11,
    "figure.dpi": 150,
})
plt.rcParams['font.family'] = 'sans-serif'
plt.rcParams['font.sans-serif'] = ['Libre Franklin'] + plt.rcParams['font.sans-serif']


# Helper functions
def dual_axis_plot(df, x_col, title, x_label, tick, filename=None):

    with plt.style.context(matplotx.styles.ayu["light"]):
        fig, (ax1, ax2) = plt.subplots(nrows = 2, figsize=(6.4, 4.8))
        ax1.tick_params(axis='both', colors='black', labelsize=12) 
        ax2.tick_params(axis='both', colors='black', labelsize=12)

        for spine in ax1.spines.values():
            spine.set_color('black')
        for spine in ax2.spines.values():
            spine.set_color('black')

        ax1.xaxis.label.set_color('black')
        ax1.yaxis.label.set_color('black')
        ax1.title.set_color('black')

        ax2.xaxis.label.set_color('black')
        ax2.yaxis.label.set_color('black')
        ax2.title.set_color('black')

        # Observed false positive rate
        ax1.plot(
            df[x_col],
            df["ε"],
            marker="o",
            linewidth=2.5,
            label="ε",
            color = "#eec15d"
        )
        ax1.set_ylabel("Observed ε",color='black')
        ax1.set_ylim(-0.05, 1.02)
        ax1.set_xticklabels([])
        if tick:
            ax1.xaxis.set_major_locator(ticker.MultipleLocator(1))

        # Attacker confidence
        ax2.plot(
            df[x_col],
            df["AC"],
            marker="s",
            linestyle="--",
            linewidth=2.5,
            label="AC",
            color="#e10000" 
        )
        ax2.set_ylabel("AC",color='black')
        ax2.set_yscale("log")
        ax2.set_xlabel(x_label,color='black')
        if tick:
            ax2.xaxis.set_major_locator(ticker.MultipleLocator(1))

        # Title
        ax1.set_title(title, pad=12)

        # Combined legend
        lines_1, labels_1 = ax1.get_legend_handles_labels()
        lines_2, labels_2 = ax2.get_legend_handles_labels()
        fig.legend(lines_1 + lines_2,
            labels_1 + labels_2, ncol = 2, frameon = True, loc = "lower center", labelcolor='black')
        fig.tight_layout(rect = [0.05,0.05, .95,.95])
        fig.align_ylabels((ax1,ax2))

        if filename:
            plt.savefig(filename, bbox_inches="tight", dpi=300)

        plt.show()

# Graph 1: Varying Bloom filter size m
dual_axis_plot(
    df_m,
    x_col="m",
    title="Bloom Bits",
    x_label=r"Bloom Filter Size ($2^m$ bits)",
    filename="bloom_size_privacy_burden.png",
    tick = True
)

# Graph 2: Varying flow volume n
dual_axis_plot(
    df_n,
    x_col="n",
    title="Flow Volume",
    x_label="Number of Inserted Flows (n)",
    filename="flow_volume_privacy_burden.png",
    tick = False
)
