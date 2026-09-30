import pandas as pd
import matplotlib.pyplot as plt

# 正确的 Round Keys
correct_keys = {
    "k31": "7fbe",
    "k30": "92b1",
    "k29": "a2e8",
    "k28": "6155"
}

# 读取 CSV
df = pd.read_csv("py/result.csv")

# 去掉空格，并统一为小写
df.columns = df.columns.str.strip()

for key in correct_keys:
    df[key] = df[key].astype(str).str.strip().str.lower()

# K31 -> K28
key_order = ["k31", "k30", "k29", "k28"]

success_rates = []

for key in key_order:
    success_count = (df[key] == correct_keys[key]).sum()
    total_count = len(df)

    success_rate = success_count / total_count * 100
    success_rates.append(success_rate)

    print(
        f"{key.upper()}: "
        f"{success_count}/{total_count} "
        f"({success_rate:.2f}%)"
    )


# ==============================
# Figure settings
# ==============================

# 全局字体放大
plt.rcParams.update({
    "font.size": 16,
    "axes.labelsize": 18,
    "xtick.labelsize": 18,
    "ytick.labelsize": 16
})

# 论文概要用：不要太宽
fig, ax = plt.subplots(figsize=(6.5, 4.5))

bars = ax.bar(
    [key.upper() for key in key_order],
    success_rates,

    # 原来是 0.5
    # 改成 0.75 后柱间距明显变小
    width=0.75
)

# 坐标轴
ax.set_xlabel("Round Key", fontsize=18)
ax.set_ylabel("Success Rate (%)", fontsize=18)

# 一般论文图中可以不放 title
# 标题写在 Figure caption 里更合适
# ax.set_title(
#     "DFA Round-Key Recovery Success Rate (SFLL-HD = 4)",
#     fontsize=17
# )

ax.set_ylim(0, 108)

# 刻度数字
ax.tick_params(
    axis="both",
    labelsize=16,
    width=1.3,
    length=5
)

# 百分比
for bar, rate in zip(bars, success_rates):
    ax.text(
        bar.get_x() + bar.get_width() / 2,
        bar.get_height() + 1.5,
        f"{rate:.1f}%",
        ha="center",
        va="bottom",
        fontsize=17,
        fontweight="bold"
    )

# 坐标轴稍微加粗
for spine in ax.spines.values():
    spine.set_linewidth(1.2)

plt.tight_layout()

# 推荐同时保存 PDF 和 PNG
# PDF 是矢量图，论文最推荐
plt.savefig(
    "dfa_success_hd4.pdf",
    bbox_inches="tight"
)

# PNG 用于 PPT 或预览
plt.savefig(
    "dfa_success_hd4.png",
    dpi=600,
    bbox_inches="tight"
)

plt.show()