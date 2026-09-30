import pandas as pd
import matplotlib.pyplot as plt

# =========================
# 正确的 Round Keys
# =========================
true_keys = {
    "k31": 0x7fbe,
    "k30": 0x92b1,
    "k29": 0xa2e8,
    "k28": 0x6155
}

# =========================
# 读取 CSV
# =========================
df = pd.read_csv(
    "py/result.csv",
    usecols=["trial", "k28", "k29", "k30", "k31", "sfll"],
    dtype=str
)

df.columns = df.columns.str.strip()

for col in ["k28", "k29", "k30", "k31", "sfll"]:
    df[col] = df[col].str.strip()


# =========================
# 判定函数
# =========================
def is_correct(recovered_hex, sfll_hex, true_key):
    recovered = int(recovered_hex, 16)
    sfll_key = int(sfll_hex, 16)

    # 条件1：恢复结果本身等于真密钥
    if recovered == true_key:
        return True

    # 条件2：恢复结果 XOR SFLL key 等于真密钥
    if (recovered ^ sfll_key) == true_key:
        return True

    return False


# =========================
# 计算成功率
# =========================
key_order = ["k31", "k30", "k29", "k28"]

success_rates = []

for key in key_order:

    success_count = 0

    for _, row in df.iterrows():
        if is_correct(
            row[key],
            row["sfll"],
            true_keys[key]
        ):
            success_count += 1

    total_count = len(df)
    success_rate = success_count / total_count * 100

    success_rates.append(success_rate)

    print(
        f"{key.upper()}: "
        f"{success_count}/{total_count} "
        f"({success_rate:.2f}%)"
    )


# =========================
# 可视化设置
# =========================
plt.rcParams.update({
    "font.size": 16,
    "axes.labelsize": 18,
    "xtick.labelsize": 18,
    "ytick.labelsize": 16
})

fig, ax = plt.subplots(figsize=(6.5, 4.5))

bars = ax.bar(
    [key.upper() for key in key_order],
    success_rates,
    width=0.75
)

# 坐标轴标签
ax.set_xlabel("Round Key", fontsize=18)
ax.set_ylabel("Success Rate (%)", fontsize=18)

# 论文概要里建议不要放图内标题
# ax.set_title(
#     "DFA Round-Key Recovery Success Rate under SFLL-HD (h = 4)",
#     fontsize=17
# )

ax.set_ylim(0, 108)

# 刻度样式
ax.tick_params(
    axis="both",
    labelsize=16,
    width=1.3,
    length=5
)

# =========================
# 显示百分比
# =========================
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

# =========================
# 保存论文用图片
# =========================
plt.savefig(
    "dfa_success_hd4_xor.pdf",
    bbox_inches="tight"
)

plt.savefig(
    "dfa_success_hd4_xor.png",
    dpi=600,
    bbox_inches="tight"
)

plt.show()