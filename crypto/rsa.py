from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import logging
import os
import json
import base64

logger = logging.getLogger(__name__)

class EncryptionError(Exception):
    """加密操作异常"""
    pass

class DecryptionError(Exception):
    """解密操作异常"""
    pass

class RSAEncryptor:
    """RSA 加密/解密实现"""
    
    def __init__(self, key_size=2048, key_file=None, public_key_str=None, private_key_str=None):
        """
        初始化 RSA 加密器
        
        Args:
            key_size: RSA 密钥大小（默认2048位）
            key_file: 密钥文件路径（可选）
            public_key_str: 公钥字符串（可选，用于初始化现有密钥）
            private_key_str: 私钥字符串（可选，用于初始化现有密钥）
        """
        self.key_size = key_size # 默认值，如果从字符串导入，会被更新
        self.key_file = key_file
        
        self.public_key_obj = None
        self.private_key_obj = None

        if public_key_str:
            try:
                self.public_key_obj = RSA.import_key(public_key_str)
                self.key_size = self.public_key_obj.size_in_bits() # 从导入的密钥中获取实际大小
                logger.info("RSA public key initialized from provided string.")
            except Exception as e:
                logger.error(f"Failed to import RSA public key from string: {str(e)}")
                raise EncryptionError(f"Failed to import RSA public key from string: {str(e)}")
        
        if private_key_str:
            try:
                self.private_key_obj = RSA.import_key(private_key_str)
                # 如果只提供了私钥，确保 key_size 也被设置
                if not self.public_key_obj:
                    self.key_size = self.private_key_obj.size_in_bits() # 从导入的密钥中获取实际大小
                logger.info("RSA private key initialized from provided string.")
            except Exception as e:
                logger.error(f"Failed to import RSA private key from string: {str(e)}")
                raise DecryptionError(f"Failed to import RSA private key from string: {str(e)}")

        # 如果没有通过字符串导入密钥，且提供了密钥文件，则从文件加载
        if not (public_key_str or private_key_str) and key_file and os.path.exists(key_file):
            self._load_keys()
        # 如果仍然没有密钥对象，则生成新的密钥对
        elif not (self.public_key_obj or self.private_key_obj):
            self._generate_keys()
            
        # 确保 key_size 在所有情况下都被正确设置，以防生成或加载的密钥大小与默认值不同
        if self.public_key_obj and self.public_key_obj.size_in_bits() != self.key_size:
            self.key_size = self.public_key_obj.size_in_bits()
        elif self.private_key_obj and self.private_key_obj.size_in_bits() != self.key_size:
            self.key_size = self.private_key_obj.size_in_bits()

    def _generate_keys(self):
        """生成新的 RSA 密钥对"""
        try:
            self.private_key_obj = RSA.generate(self.key_size)
            self.public_key_obj = self.private_key_obj.publickey()
            
            if self.key_file:
                self._save_keys()
                
            logger.info("RSA key pair generated successfully")
        except Exception as e:
            logger.error(f"Failed to generate RSA key pair: {str(e)}")
            raise EncryptionError(f"Failed to generate RSA key pair: {str(e)}")
            
    def _save_keys(self):
        """保存密钥到文件"""
        try:
            key_data = {
                'private_key': self.private_key_obj.export_key().decode(),
                'public_key': self.public_key_obj.export_key().decode()
            }
            with open(self.key_file, 'w') as f:
                json.dump(key_data, f)
            logger.info(f"RSA keys saved to {self.key_file}")
        except Exception as e:
            logger.error(f"Failed to save RSA keys: {str(e)}")
            raise EncryptionError(f"Failed to save RSA keys: {str(e)}")
            
    def _load_keys(self):
        """从文件加载密钥"""
        try:
            with open(self.key_file, 'r') as f:
                key_data = json.load(f)
            self.private_key_obj = RSA.import_key(key_data['private_key'])
            self.public_key_obj = RSA.import_key(key_data['public_key'])
            self.key_size = self.public_key_obj.size_in_bits() # 从加载的密钥中获取实际大小
            logger.info(f"RSA keys loaded from {self.key_file}")
        except Exception as e:
            logger.error(f"Failed to load RSA keys: {str(e)}")
            raise EncryptionError(f"Failed to load RSA keys: {str(e)}")

    def encrypt(self, plaintext: str) -> dict:
        """
        使用 RSA 公钥加密文本
        
        Args:
            plaintext: 要加密的文本
            
        Returns:
            dict: 包含 Base64 编码的密文的字典
            
        Raises:
            TypeError: 输入参数类型错误
            EncryptionError: 加密过程出错
        """
        if not isinstance(plaintext, str):
            raise TypeError("plaintext must be a string")
            
        try:
            if not self.public_key_obj:
                raise EncryptionError("Public key not initialized for encryption.")
            cipher = PKCS1_OAEP.new(self.public_key_obj)
            # RSA 加密有长度限制，这里使用分块加密
            max_length = (self.key_size // 8) - 42  # PKCS1_OAEP 的填充开销
            plaintext_bytes = plaintext.encode('utf-8')
            
            if len(plaintext_bytes) > max_length:
                raise ValueError(f"Plaintext too long. Maximum length is {max_length} bytes")
                
            encrypted_bytes = cipher.encrypt(plaintext_bytes)
            logger.info("RSA encryption successful")
            return {'ciphertext': base64.b64encode(encrypted_bytes).decode('utf-8')}
        except Exception as e:
            logger.error(f"RSA encryption failed: {str(e)}")
            raise EncryptionError(f"RSA encryption failed: {str(e)}")

    def decrypt(self, cipher_data: dict) -> str:
        """
        使用 RSA 私钥解密文本
        
        Args:
            cipher_data: 包含 Base64 编码的密文的字典
            
        Returns:
            str: 解密后的明文
            
        Raises:
            TypeError: 输入参数类型错误
            DecryptionError: 解密过程出错
        """
        if not isinstance(cipher_data, dict):
            raise TypeError("cipher_data must be a dictionary")
            
        if 'ciphertext' not in cipher_data or not isinstance(cipher_data['ciphertext'], str):
            raise ValueError("cipher_data must contain 'ciphertext' as a Base64 string")
            
        try:
            if not self.private_key_obj:
                raise DecryptionError("Private key not initialized for decryption.")
            ciphertext_bytes = base64.b64decode(cipher_data['ciphertext'])
            cipher = PKCS1_OAEP.new(self.private_key_obj)
            decrypted = cipher.decrypt(ciphertext_bytes)
            logger.info("RSA decryption successful")
            return decrypted.decode('utf-8')
        except Exception as e:
            logger.error(f"RSA decryption failed: {str(e)}")
            raise DecryptionError(f"RSA decryption failed: {str(e)}")