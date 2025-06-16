import base64
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import json
import logging
import threading
import queue

from Crypto.Random import get_random_bytes

from crypto_tool.crypto.aes import AESCipher, EncryptionError, DecryptionError
from crypto_tool.crypto.rsa import RSAEncryptor, EncryptionError as RSAEncryptionError, DecryptionError as RSADecryptionError
from crypto_tool.crypto.hybrid import HybridEncryptor, EncryptionError as HybridEncryptionError, DecryptionError as HybridDecryptionError
from crypto_tool.crypto.hash import sha256_hash, HashingError
from crypto_tool.utils.visualizer import Visualizer

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class EncryptionToolApp:
    """加密工具图形界面应用"""

    def __init__(self, root):
        self.root = root
        self.root.title("加密工具")
        self.root.geometry("1000x700")
        self.root.minsize(900, 600)

        # 绑定窗口关闭事件
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

        # 创建加密器实例
        self.rsa_key_size = 2048
        self.reset_encryptors()

        # 暴力破解相关状态
        self.brute_force_thread = None
        self.brute_force_running = False
        self.brute_force_paused = False
        self.brute_force_queue = queue.Queue() # For communication from thread to GUI
        self.pause_event = threading.Event() # For pausing/resuming the thread
        self.pause_event.set() # Initially, allow the thread to run

        # 创建主框架
        self.main_frame = ttk.Frame(root, padding="10")
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        # 创建顶部导航栏
        self.create_navbar()

        # 创建主内容区域
        self.content_frame = ttk.Frame(self.main_frame)
        self.content_frame.pack(fill=tk.BOTH, expand=True, pady=10)

        # 创建状态栏
        self.status_var = tk.StringVar()
        self.status_var.set("就绪")
        self.status_bar = ttk.Label(self.main_frame, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        # 初始化各标签页
        self.create_aes_tab()
        self.create_rsa_tab()
        self.create_hybrid_tab()
        self.create_hash_tab()
        # self.create_flowchart_tab()

        # 默认显示AES标签页
        self.show_tab("aes")

        # 显示欢迎弹窗
        self.show_welcome_popup()

    def reset_encryptors(self):
        """重置所有加密器实例"""
        self.rsa_encryptor = RSAEncryptor(self.rsa_key_size)
        self.hybrid_encryptor = HybridEncryptor(self.rsa_key_size)

    def create_navbar(self):
        """创建顶部导航栏"""
        navbar = ttk.Frame(self.main_frame)
        navbar.pack(fill=tk.X, pady=5)

        self.aes_btn = ttk.Button(navbar, text="AES", command=lambda: self.show_tab("aes"))
        self.aes_btn.pack(side=tk.LEFT, padx=5, pady=5)

        self.rsa_btn = ttk.Button(navbar, text="RSA", command=lambda: self.show_tab("rsa"))
        self.rsa_btn.pack(side=tk.LEFT, padx=5, pady=5)

        self.hybrid_btn = ttk.Button(navbar, text="混合加密", command=lambda: self.show_tab("hybrid"))
        self.hybrid_btn.pack(side=tk.LEFT, padx=5, pady=5)

        self.hash_btn = ttk.Button(navbar, text="哈希", command=lambda: self.show_tab("hash"))
        self.hash_btn.pack(side=tk.LEFT, padx=5, pady=5)

        self.instructions_btn = ttk.Button(navbar, text="操作说明", command=self.show_welcome_popup)
        self.instructions_btn.pack(side=tk.LEFT, padx=5, pady=5)

        # 分隔线
        ttk.Separator(self.main_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=5)

    def create_aes_tab(self):
        """创建AES加密标签页"""
        self.aes_frame = ttk.LabelFrame(self.content_frame, text="AES 加密", padding="10")

        # 左侧：输入区域
        left_frame = ttk.Frame(self.aes_frame)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)

        # 明文输入
        ttk.Label(left_frame, text="明文:").pack(anchor=tk.W)
        self.aes_plaintext = scrolledtext.ScrolledText(left_frame, width=40, height=8)
        self.aes_plaintext.pack(fill=tk.BOTH, expand=True, pady=5)

        ttk.Label(left_frame, text="密文:").pack(anchor=tk.W)
        self.aes_ciphertext_input = scrolledtext.ScrolledText(left_frame, width=40, height=8)
        self.aes_ciphertext_input.pack(fill=tk.BOTH, expand=True, pady=5)

        # 操作按钮
        btn_frame = ttk.Frame(left_frame)
        btn_frame.pack(fill=tk.X, pady=10)

        ttk.Button(btn_frame, text="加密", command=self.aes_encrypt).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="解密", command=self.aes_decrypt).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="清空", command=self.clear_aes_fields).pack(side=tk.LEFT, padx=5)

        # 密钥管理
        key_management_frame = ttk.LabelFrame(self.aes_frame, text="密钥管理", padding="5")
        key_management_frame.pack(fill=tk.X, pady=10, side=tk.BOTTOM)

        ttk.Label(key_management_frame, text="密钥 (16/24/32字节): ").pack(side=tk.LEFT, padx=5)
        self.aes_key_entry = ttk.Entry(key_management_frame, width=40)
        self.aes_key_entry.pack(side=tk.LEFT, padx=5)
        ttk.Button(key_management_frame, text="生成随机密钥", command=self.generate_aes_key).pack(side=tk.LEFT, padx=5)

        ttk.Label(key_management_frame, text="IV:").pack(side=tk.LEFT, padx=5)
        self.aes_iv_entry = ttk.Entry(key_management_frame, width=50)
        self.aes_iv_entry.pack(side=tk.LEFT, padx=5)

        # 右侧：结果输出区域
        right_frame = ttk.Frame(self.aes_frame)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)

        ttk.Label(right_frame, text="结果:").pack(anchor=tk.W)
        self.aes_result_output = scrolledtext.ScrolledText(right_frame, width=40, height=15)
        self.aes_result_output.pack(fill=tk.BOTH, expand=True, pady=5)

    def generate_aes_key(self):
        """生成随机 AES 密钥并填充到输入框"""
        key = get_random_bytes(16)  # 生成 16 字节 (128 位) 密钥
        self.aes_key_entry.delete(0, tk.END)
        self.aes_key_entry.insert(0, base64.b64encode(key).decode('utf-8')) # 转换为 Base64 字符串
        self.status_var.set("已生成随机 AES 密钥")

    def aes_encrypt(self):
        """执行 AES 加密"""
        plaintext = self.aes_plaintext.get(1.0, tk.END).strip()
        key_b64 = self.aes_key_entry.get().strip()

        if not plaintext:
            messagebox.showwarning("警告", "请输入要加密的文本")
            return
        if not key_b64:
            messagebox.showwarning("警告", "请输入密钥")
            return

        try:
            key = base64.b64decode(key_b64) # 将 Base64 字符串解码为字节
            if len(key) not in [16, 24, 32]:
                raise ValueError("密钥长度必须是16、24或32字节")

            encrypted_data = AESCipher.encrypt(plaintext, key)

            self.aes_result_output.delete(1.0, tk.END)
            self.aes_result_output.insert(tk.END, base64.b64encode(encrypted_data['ciphertext']).decode('utf-8'))
            print(f"AES Ciphertext (Base64): {base64.b64encode(encrypted_data['ciphertext']).decode('utf-8')}")
            
            # 显示密钥和IV (现在从 AESCipher 返回时是字节，需要Base64编码)
            self.aes_key_entry.delete(0, tk.END)
            self.aes_key_entry.insert(0, base64.b64encode(encrypted_data['key']).decode('utf-8'))
            print(f"AES Key (Base64): {base64.b64encode(encrypted_data['key']).decode('utf-8')}")
            self.aes_iv_entry.delete(0, tk.END)
            self.aes_iv_entry.insert(0, base64.b64encode(encrypted_data['iv']).decode('utf-8'))
            print(f"AES IV (Base64): {base64.b64encode(encrypted_data['iv']).decode('utf-8')}")

            self.status_var.set("AES 加密完成")
        except Exception as e:
            messagebox.showerror("错误", f"加密失败: {str(e)}")
            self.status_var.set(f"加密失败: {str(e)}")

    def aes_decrypt(self):
        """执行 AES 解密"""
        ciphertext = self.aes_ciphertext_input.get(1.0, tk.END).strip()
        key_b64 = self.aes_key_entry.get().strip() # 从输入框获取 Base64 编码的密钥
        iv_b64 = self.aes_iv_entry.get().strip()   # 从输入框获取 Base64 编码的 IV

        if not ciphertext:
            messagebox.showwarning("警告", "请输入要解密的密文")
            return
        if not key_b64 or not iv_b64:
            messagebox.showwarning("警告", "缺少密钥或 IV")
            return

        try:
            # 将 Base64 编码的字符串解码为字节，再传递给 decrypt 方法
            key_bytes = base64.b64decode(key_b64)
            iv_bytes = base64.b64decode(iv_b64)
            ciphertext_bytes = base64.b64decode(ciphertext)

            decrypted_data = AESCipher.decrypt({'ciphertext': ciphertext_bytes, 'key': key_bytes, 'iv': iv_bytes})
            self.aes_result_output.delete(1.0, tk.END)
            self.aes_result_output.insert(tk.END, decrypted_data)
            self.status_var.set("AES 解密完成")
        except Exception as e:
            messagebox.showerror("错误", f"解密失败: {str(e)}")
            self.status_var.set(f"解密失败: {str(e)}")

    def clear_aes_fields(self):
        """清空 AES 字段"""
        self.aes_plaintext.delete(1.0, tk.END)
        self.aes_ciphertext_input.delete(1.0, tk.END)
        self.aes_result_output.delete(1.0, tk.END)
        self.aes_key_entry.delete(0, tk.END)
        self.aes_iv_entry.delete(0, tk.END)
        self.status_var.set("就绪")

    def create_rsa_tab(self):
        """创建RSA加密标签页"""
        self.rsa_frame = ttk.LabelFrame(self.content_frame, text="RSA 加密", padding="10")

        # 左侧：输入区域
        left_frame = ttk.Frame(self.rsa_frame)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)

        # 明文输入
        ttk.Label(left_frame, text="明文:").pack(anchor=tk.W)
        self.rsa_plaintext = scrolledtext.ScrolledText(left_frame, width=40, height=8)
        self.rsa_plaintext.pack(fill=tk.BOTH, expand=True, pady=5)

        ttk.Label(left_frame, text="密文:").pack(anchor=tk.W)
        self.rsa_ciphertext_input = scrolledtext.ScrolledText(left_frame, width=40, height=8)
        self.rsa_ciphertext_input.pack(fill=tk.BOTH, expand=True, pady=5)

        # 操作按钮
        btn_frame = ttk.Frame(left_frame)
        btn_frame.pack(fill=tk.X, pady=10)

        ttk.Button(btn_frame, text="加密", command=self.rsa_encrypt).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="解密", command=self.rsa_decrypt).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="清空", command=self.clear_rsa_fields).pack(side=tk.LEFT, padx=5)

        # 右侧：结果输出区域
        right_frame = ttk.Frame(self.rsa_frame)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)

        ttk.Label(right_frame, text="结果:").pack(anchor=tk.W)
        self.rsa_result_output = scrolledtext.ScrolledText(right_frame, width=40, height=15)
        self.rsa_result_output.pack(fill=tk.BOTH, expand=True, pady=5)

        # 密钥管理
        key_frame = ttk.LabelFrame(left_frame, text="密钥管理", padding="5")
        key_frame.pack(fill=tk.X, pady=10)

        ttk.Label(key_frame, text="密钥大小:").pack(anchor=tk.W)
        self.rsa_key_size_var = tk.StringVar(value=str(self.rsa_key_size))
        key_size_combo = ttk.Combobox(
            key_frame,
            textvariable=self.rsa_key_size_var,
            values=["1024", "2048", "3072", "4096"],
            width=10
        )
        key_size_combo.pack(side=tk.LEFT, padx=5)

        ttk.Button(
            key_frame,
            text="生成密钥对",
            command=self.generate_rsa_keys
        ).pack(side=tk.LEFT, padx=5)

        ttk.Label(key_frame, text="公钥:").pack(anchor=tk.W, pady=(10, 0))
        self.rsa_public_key_entry = ttk.Entry(key_frame, width=60, state=tk.DISABLED)
        self.rsa_public_key_entry.pack(fill=tk.X, padx=5, pady=2)

        ttk.Label(key_frame, text="私钥:").pack(anchor=tk.W, pady=(10, 0))
        self.rsa_private_key_entry = ttk.Entry(key_frame, width=60, state=tk.DISABLED)
        self.rsa_private_key_entry.pack(fill=tk.X, padx=5, pady=2)

    def generate_rsa_keys(self):
        """生成 RSA 密钥对并更新界面"""
        try:
            # rsa_encryptor 已经在 reset_encryptors 中初始化为 RSAEncryptor(self.rsa_key_size)
            # 这里根据用户选择的key_size重新生成密钥对
            selected_key_size = int(self.rsa_key_size_var.get())
            self.rsa_encryptor = RSAEncryptor(key_size=selected_key_size)

            # 显示公钥
            self.rsa_public_key_entry.config(state=tk.NORMAL)
            self.rsa_public_key_entry.delete(0, tk.END)
            # 从 rsa_encryptor.public_key_obj 获取并解码
            self.rsa_public_key_entry.insert(0, self.rsa_encryptor.public_key_obj.export_key().decode('utf-8'))
            self.rsa_public_key_entry.config(state=tk.DISABLED)

            # 显示私钥
            self.rsa_private_key_entry.config(state=tk.NORMAL)
            self.rsa_private_key_entry.delete(0, tk.END)
            # 从 rsa_encryptor.private_key_obj 获取并解码
            self.rsa_private_key_entry.insert(0, self.rsa_encryptor.private_key_obj.export_key().decode('utf-8'))
            self.rsa_private_key_entry.config(state=tk.DISABLED)

            self.status_var.set(f"RSA 密钥对生成成功，大小: {selected_key_size} 位")
        except Exception as e:
            messagebox.showerror("错误", f"生成 RSA 密钥对失败: {str(e)}")
            self.status_var.set(f"生成 RSA 密钥对失败: {str(e)}")

    def rsa_encrypt(self):
        """执行 RSA 加密"""
        plaintext = self.rsa_plaintext.get(1.0, tk.END).strip()
        public_key_str = self.rsa_public_key_entry.get().strip()

        if not plaintext:
            messagebox.showwarning("警告", "请输入要加密的文本")
            return
        if not public_key_str:
            messagebox.showwarning("警告", "请生成或输入公钥")
            return

        try:
            key_size = int(self.rsa_key_size_var.get()) # 获取当前选定的密钥大小
            # 使用界面上的公钥创建临时的 RSAEncryptor 实例进行加密
            temp_encryptor = RSAEncryptor(key_size=key_size, public_key_str=public_key_str, private_key_str=None) # Private key not needed for encryption
            encrypted = temp_encryptor.encrypt(plaintext)
            
            self.rsa_result_output.delete(1.0, tk.END)
            self.rsa_result_output.insert(tk.END, encrypted['ciphertext'])
            self.status_var.set("RSA 加密完成")
        except Exception as e:
            messagebox.showerror("错误", f"加密失败: {str(e)}")
            self.status_var.set(f"加密失败: {str(e)}")

    def rsa_decrypt(self):
        """执行 RSA 解密"""
        ciphertext = self.rsa_ciphertext_input.get(1.0, tk.END).strip()
        private_key_str = self.rsa_private_key_entry.get().strip()

        if not ciphertext:
            messagebox.showwarning("警告", "请输入要解密的密文")
            return
        if not private_key_str:
            messagebox.showwarning("警告", "请生成或输入私钥")
            return

        try:
            key_size = int(self.rsa_key_size_var.get()) # 获取当前选定的密钥大小
            # 使用界面上的私钥创建临时的 RSAEncryptor 实例进行解密
            temp_encryptor = RSAEncryptor(key_size=key_size, public_key_str=None, private_key_str=private_key_str) # Public key not needed for decryption
            decrypted = temp_encryptor.decrypt({'ciphertext': ciphertext})
            
            self.rsa_result_output.delete(1.0, tk.END)
            self.rsa_result_output.insert(tk.END, decrypted)
            self.status_var.set("RSA 解密完成")
        except Exception as e:
            messagebox.showerror("错误", f"解密失败: {str(e)}")
            self.status_var.set(f"解密失败: {str(e)}")

    def clear_rsa_fields(self):
        """清空 RSA 字段"""
        self.rsa_plaintext.delete(1.0, tk.END)
        self.rsa_ciphertext_input.delete(1.0, tk.END)
        self.rsa_result_output.delete(1.0, tk.END)
        self.rsa_public_key_entry.config(state=tk.NORMAL)
        self.rsa_public_key_entry.delete(0, tk.END)
        self.rsa_public_key_entry.config(state=tk.DISABLED)
        self.rsa_private_key_entry.config(state=tk.NORMAL)
        self.rsa_private_key_entry.delete(0, tk.END)
        self.rsa_private_key_entry.config(state=tk.DISABLED)
        self.status_var.set("就绪")

    def create_hybrid_tab(self):
        """创建混合加密标签页"""
        self.hybrid_frame = ttk.LabelFrame(self.content_frame, text="混合加密", padding="10")

        # 左侧：输入区域
        left_frame = ttk.Frame(self.hybrid_frame)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)

        # 明文输入
        ttk.Label(left_frame, text="明文:").pack(anchor=tk.W)
        self.hybrid_plaintext = scrolledtext.ScrolledText(left_frame, width=40, height=8)
        self.hybrid_plaintext.pack(fill=tk.BOTH, expand=True, pady=5)

        ttk.Label(left_frame, text="密文:").pack(anchor=tk.W)
        self.hybrid_ciphertext_input = scrolledtext.ScrolledText(left_frame, width=40, height=8)
        self.hybrid_ciphertext_input.pack(fill=tk.BOTH, expand=True, pady=5)

        # 操作按钮
        btn_frame = ttk.Frame(left_frame)
        btn_frame.pack(fill=tk.X, pady=10)

        ttk.Button(btn_frame, text="加密", command=self.hybrid_encrypt).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="解密", command=self.hybrid_decrypt).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="清空", command=self.clear_hybrid_fields).pack(side=tk.LEFT, padx=5)

        # 右侧：结果输出区域
        right_frame = ttk.Frame(self.hybrid_frame)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)

        ttk.Label(right_frame, text="结果:").pack(anchor=tk.W)
        self.hybrid_result_output = scrolledtext.ScrolledText(right_frame, width=40, height=15)
        self.hybrid_result_output.pack(fill=tk.BOTH, expand=True, pady=5)

        # 详细信息
        details_frame = ttk.LabelFrame(right_frame, text="详细信息", padding="5")
        details_frame.pack(fill=tk.BOTH, expand=True, pady=10)

        ttk.Label(details_frame, text="公钥:").pack(anchor=tk.W)
        self.hybrid_public_key = ttk.Entry(details_frame, width=60, state=tk.DISABLED)
        self.hybrid_public_key.pack(fill=tk.X, padx=5, pady=2)

        ttk.Label(details_frame, text="加密的 AES 密钥:").pack(anchor=tk.W)
        self.hybrid_encrypted_key = ttk.Entry(details_frame, width=60, state=tk.DISABLED)
        self.hybrid_encrypted_key.pack(fill=tk.X, padx=5, pady=2)

        ttk.Label(details_frame, text="IV:").pack(anchor=tk.W)
        self.hybrid_iv = ttk.Entry(details_frame, width=60, state=tk.DISABLED)
        self.hybrid_iv.pack(fill=tk.X, padx=5, pady=2)

    def hybrid_encrypt(self):
        """执行混合加密"""
        plaintext = self.hybrid_plaintext.get(1.0, tk.END).strip()
        if not plaintext:
            messagebox.showwarning("警告", "请输入要加密的文本")
            return

        try:
            # 执行加密
            encrypted = self.hybrid_encryptor.encrypt(plaintext)

            # 显示结果
            self.hybrid_result_output.delete(1.0, tk.END)
            self.hybrid_result_output.insert(tk.END, encrypted['ciphertext'])

            # 显示详细信息
            self.hybrid_public_key.config(state=tk.NORMAL)
            self.hybrid_public_key.delete(0, tk.END)
            self.hybrid_public_key.insert(0, encrypted['public_key'])
            self.hybrid_public_key.config(state=tk.DISABLED)

            self.hybrid_encrypted_key.config(state=tk.NORMAL)
            self.hybrid_encrypted_key.delete(0, tk.END)
            self.hybrid_encrypted_key.insert(0, encrypted['encrypted_key'])
            self.hybrid_encrypted_key.config(state=tk.DISABLED)

            self.hybrid_iv.config(state=tk.NORMAL)
            self.hybrid_iv.delete(0, tk.END)
            self.hybrid_iv.insert(0, encrypted['iv'])
            self.hybrid_iv.config(state=tk.DISABLED)

            self.status_var.set("混合加密完成")
        except Exception as e:
            messagebox.showerror("错误", f"加密失败: {str(e)}")
            self.status_var.set(f"加密失败: {str(e)}")

    def hybrid_decrypt(self):
        """执行混合解密"""
        ciphertext = self.hybrid_ciphertext_input.get(1.0, tk.END).strip()
        encrypted_key = self.hybrid_encrypted_key.get()
        iv = self.hybrid_iv.get()

        if not ciphertext:
            messagebox.showwarning("警告", "请输入要解密的密文")
            return

        if not encrypted_key or not iv:
            messagebox.showwarning("警告", "缺少必要的加密信息")
            return

        try:
            # 执行解密
            decrypted = self.hybrid_encryptor.decrypt({
                'ciphertext': ciphertext,
                'encrypted_key': encrypted_key,
                'iv': iv
            })

            # 显示结果
            self.hybrid_result_output.delete(1.0, tk.END)
            self.hybrid_result_output.insert(tk.END, decrypted)
            self.status_var.set("混合解密完成")
        except Exception as e:
            messagebox.showerror("错误", f"解密失败: {str(e)}")
            self.status_var.set(f"解密失败: {str(e)}")

    def clear_hybrid_fields(self):
        """清空混合加密字段"""
        self.hybrid_plaintext.delete(1.0, tk.END)
        self.hybrid_ciphertext_input.delete(1.0, tk.END)
        self.hybrid_result_output.delete(1.0, tk.END)
        self.hybrid_public_key.config(state=tk.NORMAL)
        self.hybrid_public_key.delete(0, tk.END)
        self.hybrid_public_key.config(state=tk.DISABLED)
        self.hybrid_encrypted_key.config(state=tk.NORMAL)
        self.hybrid_encrypted_key.delete(0, tk.END)
        self.hybrid_encrypted_key.config(state=tk.DISABLED)
        self.hybrid_iv.config(state=tk.NORMAL)
        self.hybrid_iv.delete(0, tk.END)
        self.hybrid_iv.config(state=tk.DISABLED)
        self.status_var.set("就绪")

    def create_hash_tab(self):
        """创建哈希标签页"""
        self.hash_frame = ttk.LabelFrame(self.content_frame, text="SHA-256 哈希")

        # 配置 hash_frame 的 grid 布局，用于管理顶部内容区和底部暴力破解区
        self.hash_frame.grid_rowconfigure(0, weight=1) # 顶部内容行垂直扩展
        self.hash_frame.grid_rowconfigure(1, weight=0) # 底部暴力破解行不额外垂直扩展
        self.hash_frame.grid_columnconfigure(0, weight=1) # 确保唯一一列水平扩展

        # 新增一个框架来容纳左右输入/输出区域
        hash_top_content_frame = ttk.Frame(self.hash_frame)
        hash_top_content_frame.grid(row=0, column=0, sticky=tk.NSEW) # 填充所有方向

        # 配置 hash_top_content_frame 的 grid 布局，容纳左右两个区域
        hash_top_content_frame.grid_columnconfigure(0, weight=1) # 左侧区域水平扩展
        hash_top_content_frame.grid_columnconfigure(1, weight=1) # 右侧区域水平扩展
        hash_top_content_frame.grid_rowconfigure(0, weight=1) # 确保行可以垂直扩展

        # 左侧：输入区域
        left_frame = ttk.Frame(hash_top_content_frame)
        left_frame.grid(row=0, column=0, sticky=tk.NSEW, padx=5, pady=5)

        # 输入文本
        ttk.Label(left_frame, text="输入文本:").pack(anchor=tk.W)
        self.hash_input_text = scrolledtext.ScrolledText(left_frame, height=15)
        self.hash_input_text.pack(fill=tk.BOTH, expand=True, pady=5)

        # 操作按钮
        btn_frame = ttk.Frame(left_frame)
        btn_frame.pack(fill=tk.X, pady=10)

        ttk.Button(btn_frame, text="计算哈希", command=self.hash_data).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="清空", command=self.clear_hash_fields).pack(side=tk.LEFT, padx=5)

        # 右侧：结果输出区域
        right_frame = ttk.Frame(hash_top_content_frame)
        right_frame.grid(row=0, column=1, sticky=tk.NSEW, padx=5, pady=5)

        ttk.Label(right_frame, text="哈希结果:").pack(anchor=tk.W)
        self.hash_output_text = scrolledtext.ScrolledText(right_frame, height=15)
        self.hash_output_text.pack(fill=tk.BOTH, expand=True, pady=5)

        # 暴力破解区域 (现在直接grid到self.hash_frame)
        brute_force_frame = ttk.LabelFrame(self.hash_frame, text="SHA-256 暴力破解 (仅限短字符串)")
        brute_force_frame.grid(row=1, column=0, sticky=tk.EW, pady=5) # 水平填充

        # 使用 grid 布局来更精确地控制内部组件
        brute_force_frame.grid_columnconfigure(0, weight=1) # 确保第一列（内容列）可以扩展

        # 目标哈希值
        ttk.Label(brute_force_frame, text="目标哈希值:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.hash_target_hash_entry = ttk.Entry(brute_force_frame)
        self.hash_target_hash_entry.grid(row=1, column=0, sticky=tk.EW, pady=5)

        # 暴力破解按钮框架
        brute_force_btn_frame = ttk.Frame(brute_force_frame)
        brute_force_btn_frame.grid(row=2, column=0, sticky=tk.EW, pady=5)

        ttk.Button(brute_force_btn_frame, text="暴力破解", command=self.brute_force_hash).pack(side=tk.LEFT, padx=5)
        self.pause_brute_force_btn = ttk.Button(brute_force_btn_frame, text="暂停", command=self.toggle_brute_force_pause, state=tk.DISABLED)
        self.pause_brute_force_btn.pack(side=tk.LEFT, padx=5)

        # 警告信息放置在单独的行，确保完整显示
        ttk.Label(brute_force_frame, 
                  text="警告: 暴力破解仅对极短（如5字符以内）的字符串有效。\n耗时可能很长，请耐心等待。", 
                  foreground="red").grid(row=3, column=0, sticky=tk.EW, pady=5)

    def hash_data(self):
        """计算输入文本的 SHA-256 哈希值"""
        input_text = self.hash_input_text.get("1.0", tk.END).strip()
        if not input_text:
            messagebox.showwarning("警告", "请输入要计算哈希的文本")
            return

        try:
            hashed_result = sha256_hash(input_text)
            self.hash_output_text.delete("1.0", tk.END)
            self.hash_output_text.insert(tk.END, hashed_result)
            self.status_var.set("SHA-256 哈希计算完成")
        except HashingError as e:
            messagebox.showerror("错误", str(e))
            self.status_var.set(f"哈希计算失败: {str(e)}")
        except Exception as e:
            messagebox.showerror("错误", f"发生未知错误: {str(e)}")
            self.status_var.set(f"发生未知错误: {str(e)}")

    def brute_force_hash(self):
        """启动一个新线程来尝试暴力破解 SHA-256 哈希值"""
        if self.brute_force_running:
            messagebox.showwarning("警告", "暴力破解已在进行中。")
            return

        target_hash = self.hash_target_hash_entry.get().strip()
        if not target_hash:
            messagebox.showwarning("警告", "请输入目标哈希值进行破解")
            return
        if len(target_hash) != 64: # SHA-256 hash is 64 hex characters
            messagebox.showwarning("警告", "请输入有效的 SHA-256 哈希值 (64个十六进制字符)。")
            return

        self.brute_force_running = True
        self.brute_force_paused = False # 确保初始状态未暂停
        self.pause_event.set() # 确保事件设置为允许运行
        self.pause_brute_force_btn.config(text="暂停", state=tk.NORMAL)

        self.hash_output_text.delete("1.0", tk.END)
        self.hash_output_text.insert(tk.END, "正在尝试暴力破解...这可能需要一些时间。\n")
        self.status_var.set("开始暴力破解...")
        self.root.update_idletasks() # 强制更新UI

        # 在新线程中运行暴力破解逻辑
        self.brute_force_thread = threading.Thread(target=self._run_brute_force_in_thread, args=(target_hash,))
        self.brute_force_thread.daemon = True # 允许程序在线程运行中退出
        self.brute_force_thread.start()

        # 定期检查线程发送过来的消息
        self.root.after(100, self.check_brute_force_queue)

    def _run_brute_force_in_thread(self, target_hash):
        """在新线程中执行暴力破解逻辑"""
        CHARSET = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        MAX_LENGTH = 5 # 最大破解长度

        try:
            import itertools
            found = False
            for length in range(1, MAX_LENGTH + 1):
                for combination in itertools.product(CHARSET, repeat=length):
                    # 检查暂停信号
                    self.pause_event.wait() # 如果事件未设置（暂停），则线程将在此阻塞

                    if not self.brute_force_running: # 检查是否收到停止信号
                        break

                    attempt = "".join(combination)
                    hashed_attempt = sha256_hash(attempt)
                    if hashed_attempt == target_hash:
                        self.brute_force_queue.put({"status": "found", "result": attempt})
                        found = True
                        break
                if found or not self.brute_force_running:
                    break
            
            if not found and self.brute_force_running:
                self.brute_force_queue.put({"status": "not_found"})
        except Exception as e:
            self.brute_force_queue.put({"status": "error", "message": str(e)})
        finally:
            self.brute_force_queue.put({"status": "finished"}) # 发送线程完成信号

    def check_brute_force_queue(self):
        """定期从队列中检查并处理来自暴力破解线程的消息"""
        while not self.brute_force_queue.empty():
            data = self.brute_force_queue.get()
            if data["status"] == "found":
                self.hash_output_text.insert(tk.END, f"匹配成功! 原始字符串: {data['result']}\n")
                self.status_var.set("暴力破解完成: 匹配成功")
                self._reset_brute_force_state()
            elif data["status"] == "not_found":
                self.hash_output_text.insert(tk.END, "未找到匹配的原始字符串 (或超出最大破解长度限制)。\n")
                self.status_var.set("暴力破解完成: 未找到匹配")
                self._reset_brute_force_state()
            elif data["status"] == "error":
                messagebox.showerror("错误", f"暴力破解过程中发生错误: {data['message']}")
                self.status_var.set(f"暴力破解失败: {data['message']}")
                self._reset_brute_force_state()
            elif data["status"] == "finished":
                # 线程完成，但可能在找到结果或出错前就结束了 (例如被停止)
                if self.brute_force_running: # 如果仍然标记为running，说明是正常完成未找到
                    self.status_var.set("暴力破解完成")
                self._reset_brute_force_state() 
        
        # 如果暴力破解仍在进行，则继续安排下一次检查
        if self.brute_force_running:
            self.root.after(100, self.check_brute_force_queue)

    def toggle_brute_force_pause(self):
        """切换暴力破解的暂停/继续状态"""
        if self.brute_force_running:
            if self.brute_force_paused:
                # 继续
                self.brute_force_paused = False
                self.pause_event.set() # 发出信号让线程继续运行
                self.pause_brute_force_btn.config(text="暂停")
                self.status_var.set("暴力破解已恢复")
            else:
                # 暂停
                self.brute_force_paused = True
                self.pause_event.clear() # 发出信号让线程暂停
                self.pause_brute_force_btn.config(text="继续")
                self.status_var.set("暴力破解已暂停")
        else:
            messagebox.showwarning("警告", "没有正在运行的暴力破解任务。")

    def _reset_brute_force_state(self):
        """重置暴力破解相关的状态和UI元素"""
        self.brute_force_running = False
        self.brute_force_paused = False
        self.pause_brute_force_btn.config(text="暂停", state=tk.DISABLED)
        self.brute_force_thread = None # 清除线程引用
        self.pause_event.set() # 确保事件设置为允许运行，为下次启动做准备

    def clear_hash_fields(self):
        """清空哈希标签页的输入和输出"""
        # 如果暴力破解正在进行，则停止它
        if self.brute_force_running:
            self.brute_force_running = False # 信号线程停止
            self.pause_event.set() # 确保线程不会因为暂停而卡住
        self._reset_brute_force_state()
        
        self.hash_input_text.delete("1.0", tk.END)
        self.hash_output_text.delete("1.0", tk.END)
        self.hash_target_hash_entry.delete(0, tk.END)
        self.status_var.set("就绪")

    def on_closing(self):
        """处理窗口关闭事件，确保线程安全退出"""
        if self.brute_force_running:
            self.brute_force_running = False # 信号线程停止
            self.pause_event.set() # 解除线程阻塞，如果它处于暂停状态
            # 由于brute_force_thread被设置为daemon=True，程序退出时线程会自动终止
        self.root.destroy()

    def show_tab(self, tab_name):
        """显示指定的标签页"""
        # 隐藏所有标签页
        self.aes_frame.pack_forget()
        self.rsa_frame.pack_forget()
        self.hybrid_frame.pack_forget()
        self.hash_frame.pack_forget()
        # self.flowchart_frame.pack_forget()
        
        # 显示选中的标签页
        if tab_name == "aes":
            self.aes_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
            self.status_var.set("AES 加密")
        elif tab_name == "rsa":
            self.rsa_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
            self.status_var.set("RSA 加密")
        elif tab_name == "hybrid":
            self.hybrid_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
            self.status_var.set("混合加密")
        elif tab_name == "hash":
            self.hash_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
            self.status_var.set("SHA-256 哈希")
        # elif tab_name == "flowchart":
        #     self.flowchart_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        #     self.status_var.set("加密流程图")

    def show_welcome_popup(self):
        """显示欢迎弹窗"""
        popup = tk.Toplevel(self.root)
        
        # 立即隐藏弹窗并暂时移除窗口装饰，避免闪烁
        popup.withdraw()
        popup.overrideredirect(True) 
        
        # 设置最小尺寸
        popup.minsize(800, 600) 
        
        # 创建内容框架
        content_frame = ttk.Frame(popup, padding="20")
        content_frame.pack(fill=tk.BOTH, expand=True)
        
        # 添加标题、说明文本和关闭按钮（内容）
        title_label = ttk.Label(content_frame, text="欢迎使用加密工具！", font=("Arial", 16, "bold"))
        title_label.pack(pady=(0, 20))
        
        instructions_text = """
欢迎使用加密工具！本工具提供了AES、RSA、混合加密以及SHA-256哈希功能。

**AES 加密/解密:**
1. 输入明文或密文。
2. 输入或生成密钥。密钥长度必须为16、24或32字节（Base64编码）。
3. 点击"加密"或"解密"按钮。

**RSA 加密/解密:**
1. 输入明文或密文。
2. 输入或生成公钥/私钥。私钥用于解密，公钥用于加密。
3. 点击"加密"或"解密"按钮。

**混合加密/解密:**
1. 输入明文或密文。
2. 混合加密结合了AES和RSA的优点。加密时，会生成一个随机AES密钥，用RSA公钥加密该AES密钥，然后用AES密钥加密明文。解密时，用RSA私钥解密AES密钥，再用AES密钥解密密文。
3. 点击"加密"或"解密"按钮。

**哈希 (SHA-256):**
1. 输入文本，点击"计算哈希"即可获得其SHA-256哈希值。哈希是单向的，无法解密。
2. "暴力破解"功能可尝试破解**极短**（如5字符以内）的哈希值。点击"暴力破解"，程序将尝试所有可能的组合来匹配目标哈希值。
3. 暴力破解可能非常耗时，可以点击"暂停"按钮暂停，点击"继续"按钮恢复。

请注意：
- 所有密钥和IV都以Base64字符串形式显示和输入。
- 暴力破解功能仅作为演示，不适用于实际安全场景。
        """
        instructions_label = scrolledtext.ScrolledText(content_frame, wrap=tk.WORD, font=("Arial", 10), padx=10, pady=10)
        instructions_label.insert(tk.END, instructions_text)
        instructions_label.config(state=tk.DISABLED)  # 使文本框只读
        instructions_label.pack(fill=tk.BOTH, expand=True)
        
        close_button = ttk.Button(content_frame, text="我知道了", command=popup.destroy)
        close_button.pack(pady=10)

        # 强制更新所有挂起的几何管理任务，获取准确尺寸
        popup.update_idletasks()

        # 获取屏幕尺寸
        screen_width = popup.winfo_screenwidth()
        screen_height = popup.winfo_screenheight()

        # 获取弹窗的实际宽度和高度
        width = popup.winfo_width()
        height = popup.winfo_height()

        # 计算弹窗居中位置
        x = (screen_width // 2) - (width // 2)
        y = (screen_height // 2) - (height // 2)

        # 调试信息
        print(f"Screen size: {screen_width}x{screen_height}")
        print(f"Popup size (final): {width}x{height}")
        print(f"Calculated position (final): {x},{y}")
        
        # 设置弹窗最终位置和尺寸
        popup.geometry(f'{width}x{height}+{x}+{y}')
        
        # 恢复窗口装饰、设置标题、模态，并显示
        popup.overrideredirect(False) 
        popup.title("欢迎使用加密工具") 
        popup.transient(self.root) 
        popup.grab_set() 
        popup.deiconify() 