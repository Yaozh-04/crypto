from crypto_tool.crypto.aes import AESCipher
from crypto_tool.crypto.rsa import RSAEncryptor
import base64
import logging

logger = logging.getLogger(__name__)

class EncryptionError(Exception):
    """加密操作异常"""
    pass

class DecryptionError(Exception):
    """解密操作异常"""
    pass

class HybridEncryptor:
    """混合加密实现（AES + RSA）"""
    
    def __init__(self, rsa_key_size=2048, key_file=None):
        """
        初始化混合加密器
        
        Args:
            rsa_key_size: RSA 密钥大小（默认2048位）
            key_file: RSA 密钥文件路径（可选）
        """
        self.rsa = RSAEncryptor(rsa_key_size, key_file)
        
    def encrypt(self, plaintext: str) -> dict:
        """
        使用混合加密方式加密文本
        
        Args:
            plaintext: 要加密的文本
            
        Returns:
            dict: 包含加密结果的字典
            
        Raises:
            TypeError: 输入参数类型错误
            EncryptionError: 加密过程出错
        """
        if not isinstance(plaintext, str):
            raise TypeError("plaintext must be a string")
            
        try:
            # 使用 AES 加密数据
            aes_result = AESCipher.encrypt(plaintext)
            
            # 使用 RSA 加密 AES 密钥 (aes_result['key']是bytes，rsa.encrypt期望str，所以先base64编码)
            encrypted_aes_key_dict = self.rsa.encrypt(base64.b64encode(aes_result['key']).decode('utf-8'))
            
            result = {
                'ciphertext': base64.b64encode(aes_result['ciphertext']).decode('utf-8'),
                'iv': base64.b64encode(aes_result['iv']).decode('utf-8'),
                'encrypted_key': encrypted_aes_key_dict['ciphertext'], # 已经由RSA加密后base64编码
                'public_key': self.rsa.public_key_obj.export_key().decode('utf-8') # 获取RSA公钥字符串
            }
            
            logger.info("Hybrid encryption successful")
            return result
        except Exception as e:
            logger.error(f"Hybrid encryption failed: {str(e)}")
            raise EncryptionError(f"Hybrid encryption failed: {str(e)}")

    def decrypt(self, cipher_data: dict) -> str:
        """
        使用混合加密方式解密文本
        
        Args:
            cipher_data: 包含加密数据的字典
            
        Returns:
            str: 解密后的明文
            
        Raises:
            TypeError: 输入参数类型错误
            ValueError: 输入数据格式错误
            DecryptionError: 解密过程出错
        """
        if not isinstance(cipher_data, dict):
            raise TypeError("cipher_data must be a dictionary")
            
        required_keys = {'ciphertext', 'iv', 'encrypted_key'}
        if not all(key in cipher_data for key in required_keys):
            raise ValueError("cipher_data must contain 'ciphertext', 'iv', and 'encrypted_key'")
            
        try:
            # 解密 AES 密钥 (RSA.decrypt期望一个字典)
            encrypted_aes_key_b64 = cipher_data['encrypted_key']
            decrypted_aes_key_b64_str = self.rsa.decrypt({'ciphertext': encrypted_aes_key_b64})
            decrypted_aes_key = base64.b64decode(decrypted_aes_key_b64_str) # 从Base64字符串解码为字节
            
            # 解密数据
            ciphertext = base64.b64decode(cipher_data['ciphertext'])
            iv = base64.b64decode(cipher_data['iv'])
            
            result = AESCipher.decrypt({
                'ciphertext': ciphertext,
                'iv': iv,
                'key': decrypted_aes_key
            })
            
            logger.info("Hybrid decryption successful")
            return result
        except Exception as e:
            logger.error(f"Hybrid decryption failed: {str(e)}")
            raise DecryptionError(f"Hybrid decryption failed: {str(e)}")