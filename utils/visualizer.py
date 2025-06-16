import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

# 设置中文字体支持
plt.rcParams["font.family"] = ["SimHei", "WenQuanYi Micro Hei", "Heiti TC"]


class Visualizer:
    @staticmethod
    def create_encryption_flowchart(parent):
        """创建加密流程图并嵌入到Tkinter父容器中"""
        fig, ax = plt.subplots(figsize=(10, 6))

        # 设置图表标题和样式
        ax.set_title("混合加密流程图", fontsize=14)
        ax.axis('off')

        # 定义流程步骤
        steps = [
            "用户输入明文",
            "生成随机 AES 密钥",
            "AES 加密明文",
            "使用 RSA 公钥加密 AES 密钥",
            "发送加密的 AES 密钥和密文",
            "使用 RSA 私钥解密 AES 密钥",
            "使用解密的 AES 密钥解密密文",
            "获取原始明文"
        ]

        # 绘制流程图
        y_pos = 0.9
        for i, step in enumerate(steps):
            ax.text(0.5, y_pos, step, ha='center', va='center',
                    bbox=dict(boxstyle="round,pad=0.3", fc="lightblue", ec="navy", lw=2),
                    fontsize=12)

            if i < len(steps) - 1:
                ax.arrow(0.5, y_pos - 0.05, 0, -0.08, head_width=0.03, head_length=0.02,
                         fc='navy', ec='navy', lw=2)

            y_pos -= 0.12

        # 将图表嵌入Tkinter窗口
        canvas = FigureCanvasTkAgg(fig, master=parent)
        canvas.draw()
        return canvas