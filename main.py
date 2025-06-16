import tkinter as tk
from tkinter import ttk

from crypto_tool.gui import EncryptionToolApp

if __name__ == "__main__":
    root = tk.Tk()
    # 配置样式
    style = ttk.Style()
    style.configure("TButton.Selected", background="#a6c9e2")
    app = EncryptionToolApp(root)
    root.mainloop()
