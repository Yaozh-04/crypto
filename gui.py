import base64
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import json
import logging

from Crypto.Random import get_random_bytes

from crypto_tool.crypto.aes import AESCipher, EncryptionError, DecryptionError
from crypto_tool.crypto.rsa import RSAEncryptor, EncryptionError as RSAEncryptionError, DecryptionError as RSADecryptionError
from crypto_tool.crypto.hybrid import HybridEncryptor, EncryptionError as HybridEncryptionError, DecryptionError as HybridDecryptionError
from crypto_tool.utils.visualizer import Visualizer

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class EncryptionToolApp:
    """加密工具图形界面应用"""

    def __init__(self, root):
        self.root = root
        self.root.title("加密工具")
        self.root.geometry("1000x700")
        self.root.minsize(900, 600)

        # 创建加密器实例
        self.rsa_key_size = 2048
        self.reset_encryptors()

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

        # 默认显示AES标签页
        self.show_tab("aes")

    def reset_encryptors(self):
        """重置所有加密器实例"""
        self.rsa_encryptor = RSAEncryptor(self.rsa_key_size)
        self.hybrid_encryptor = HybridEncryptor(self.rsa_key_size)

    def create_navbar(self):
        """创建顶部导航栏"""
        navbar = ttk.Frame(self.main_frame)
        navbar.pack(fill=tk.X)

        # 导航按钮
        self.aes_btn = ttk.Button(navbar, text="AES 加密", command=lambda: self.show_tab("aes"))
        self.aes_btn.pack(side=tk.LEFT, padx=5, pady=5)

        self.rsa_btn = ttk.Button(navbar, text="RSA 加密", command=lambda: self.show_tab("rsa"))
        self.rsa_btn.pack(side=tk.LEFT, padx=5, pady=5)

        self.hybrid_btn = ttk.Button(navbar, text="混合加密", command=lambda: self.show_tab("hybrid"))
        self.hybrid_btn.pack(side=tk.LEFT, padx=5, pady=5)

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

    def show_tab(self, tab_name):
        """显示指定的标签页"""
        # 隐藏所有标签页
        self.aes_frame.pack_forget()
        self.rsa_frame.pack_forget()
        self.hybrid_frame.pack_forget()
        
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