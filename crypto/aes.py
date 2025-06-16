import base64
from Crypto.Cipher import AES as CryptoAES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import logging

logger = logging.getLogger(__name__)

class EncryptionError(Exception):
    """加密操作异常"""
    pass

class DecryptionError(Exception):
    """解密操作异常"""
    pass

class AESCipher:
    """AES 加密/解密实现"""
    
    @staticmethod
    def encrypt(plaintext: str, key: bytes = None) -> dict:
        """
        使用 AES 加密文本
        
        Args:
            plaintext: 要加密的文本
            key: AES 密钥（可选，默认生成随机密钥）
            
        Returns:
            dict: 包含 Base64 编码的密文、IV 和密钥的字典
            
        Raises:
            TypeError: 输入参数类型错误
            EncryptionError: 加密过程出错
        """
        if not isinstance(plaintext, str):
            raise TypeError("plaintext must be a string")
        if key is not None and not isinstance(key, bytes):
            raise TypeError("key must be bytes")
            
        try:
            key = key or get_random_bytes(16)  # 128-bit key by default
            if len(key) not in [16, 24, 32]:
                raise ValueError("key must be 16, 24, or 32 bytes long")
                
            cipher = CryptoAES.new(key, CryptoAES.MODE_CBC)
            ciphertext = cipher.encrypt(pad(plaintext.encode(), CryptoAES.block_size))
            
            logger.info("AES encryption successful")
            return {
                'ciphertext': ciphertext,
                'iv': cipher.iv,
                'key': key
            }
        except Exception as e:
            logger.error(f"AES encryption failed: {str(e)}")
            raise EncryptionError(f"AES encryption failed: {str(e)}")

    @staticmethod
    def decrypt(cipher_data: dict) -> str:
        """
        使用 AES 解密文本
        
        Args:
            cipher_data: 包含 Base64 编码的密文、IV 和密钥的字典
            
        Returns:
            str: 解密后的明文
            
        Raises:
            TypeError: 输入参数类型错误
            ValueError: 输入数据格式错误
            DecryptionError: 解密过程出错
        """
        if not isinstance(cipher_data, dict):
            raise TypeError("cipher_data must be a dictionary")
            
        # 这里的检查要相应调整，因为现在可能接收的是 bytes 而不是 str，但 GUI 传递的仍然是 Base64 字符串，所以此处保持对 Base64 字符串的预期
        required_keys = {'ciphertext', 'iv', 'key'}
        if not all(key in cipher_data and isinstance(cipher_data[key], (str, bytes)) for key in required_keys):
            raise ValueError("cipher_data must contain 'ciphertext', 'iv', and 'key' as Base64 strings or bytes")
            
        try:
            # 解码 Base64 字符串回字节，如果已经是字节则直接使用
            key = cipher_data['key'] if isinstance(cipher_data['key'], bytes) else base64.b64decode(cipher_data['key'])
            iv = cipher_data['iv'] if isinstance(cipher_data['iv'], bytes) else base64.b64decode(cipher_data['iv'])
            ciphertext = cipher_data['ciphertext'] if isinstance(cipher_data['ciphertext'], bytes) else base64.b64decode(cipher_data['ciphertext'])

            cipher = CryptoAES.new(key, CryptoAES.MODE_CBC, iv)
            plaintext = unpad(cipher.decrypt(ciphertext), CryptoAES.block_size)
            
            logger.info("AES decryption successful")
            return plaintext.decode()
        except Exception as e:
            logger.error(f"AES decryption failed: {str(e)}")
            raise DecryptionError(f"AES decryption failed: {str(e)}")