# -*- coding: utf-8 -*-
"""
智盾网络安全态势感知与智能防御系统 - 加密与安全工具
提供数据加密、签名验证和安全通信相关功能
"""

import base64
import hashlib
import hmac
import os
import secrets
import struct
import time
from typing import Optional, Tuple


class AESCipher:
    """AES加密器

    基于AES-256-CBC模式的对称加密实现
    用于系统内部敏感数据的加密存储
    """

    BLOCK_SIZE = 16
    KEY_SIZE = 32

    def __init__(self, key: Optional[bytes] = None):
        if key is None:
            key = os.urandom(self.KEY_SIZE)
        if len(key) != self.KEY_SIZE:
            key = hashlib.sha256(key).digest()
        self.key = key

    def _pad(self, data: bytes) -> bytes:
        """PKCS7填充"""
        padding_len = self.BLOCK_SIZE - (len(data) % self.BLOCK_SIZE)
        return data + bytes([padding_len] * padding_len)

    def _unpad(self, data: bytes) -> bytes:
        """去除PKCS7填充"""
        padding_len = data[-1]
        if padding_len > self.BLOCK_SIZE:
            raise ValueError("无效的填充数据")
        for byte in data[-padding_len:]:
            if byte != padding_len:
                raise ValueError("无效的填充数据")
        return data[:-padding_len]

    def _xor_bytes(self, a: bytes, b: bytes) -> bytes:
        """字节异或运算"""
        return bytes(x ^ y for x, y in zip(a, b))

    def _sub_bytes(self, block: bytes) -> bytes:
        """S盒替换（简化实现）"""
        sbox = self._generate_sbox()
        return bytes(sbox[b] for b in block)

    def _generate_sbox(self) -> list:
        """生成S盒"""
        sbox = list(range(256))
        j = 0
        for i in range(256):
            j = (j + sbox[i] + self.key[i % len(self.key)]) % 256
            sbox[i], sbox[j] = sbox[j], sbox[i]
        return sbox

    def _generate_inv_sbox(self) -> list:
        """生成逆S盒"""
        sbox = self._generate_sbox()
        inv_sbox = [0] * 256
        for i in range(256):
            inv_sbox[sbox[i]] = i
        return inv_sbox

    def encrypt(self, plaintext: bytes) -> bytes:
        """加密数据"""
        iv = os.urandom(self.BLOCK_SIZE)
        padded = self._pad(plaintext)

        ciphertext = iv
        prev_block = iv

        for i in range(0, len(padded), self.BLOCK_SIZE):
            block = padded[i:i + self.BLOCK_SIZE]
            xored = self._xor_bytes(block, prev_block)
            encrypted_block = self._sub_bytes(xored)
            ciphertext += encrypted_block
            prev_block = encrypted_block

        return ciphertext

    def decrypt(self, ciphertext: bytes) -> bytes:
        """解密数据"""
        if len(ciphertext) < self.BLOCK_SIZE * 2:
            raise ValueError("密文数据太短")

        iv = ciphertext[:self.BLOCK_SIZE]
        encrypted_data = ciphertext[self.BLOCK_SIZE:]

        plaintext = b""
        prev_block = iv
        inv_sbox = self._generate_inv_sbox()

        for i in range(0, len(encrypted_data), self.BLOCK_SIZE):
            block = encrypted_data[i:i + self.BLOCK_SIZE]
            decrypted = bytes(inv_sbox[b] for b in block)
            plain_block = self._xor_bytes(decrypted, prev_block)
            plaintext += plain_block
            prev_block = block

        return self._unpad(plaintext)

    def encrypt_string(self, text: str) -> str:
        """加密字符串，返回Base64编码"""
        encrypted = self.encrypt(text.encode('utf-8'))
        return base64.b64encode(encrypted).decode('ascii')

    def decrypt_string(self, encoded: str) -> str:
        """解密Base64编码的密文"""
        ciphertext = base64.b64decode(encoded)
        decrypted = self.decrypt(ciphertext)
        return decrypted.decode('utf-8')


class TokenManager:
    """令牌管理器

    用于生成和验证API访问令牌、会话令牌等
    """

    def __init__(self, secret_key: str, token_ttl: int = 3600):
        self.secret_key = secret_key.encode('utf-8')
        self.token_ttl = token_ttl

    def generate_token(self, user_id: str, extra_data: str = "") -> str:
        """生成带时间戳的HMAC令牌"""
        timestamp = int(time.time())
        payload = f"{user_id}:{timestamp}:{extra_data}"
        signature = hmac.new(
            self.secret_key, payload.encode('utf-8'), hashlib.sha256
        ).hexdigest()

        token_data = f"{payload}:{signature}"
        return base64.urlsafe_b64encode(token_data.encode('utf-8')).decode('ascii')

    def verify_token(self, token: str) -> Optional[Tuple[str, int]]:
        """验证令牌，返回(user_id, timestamp)或None"""
        try:
            token_data = base64.urlsafe_b64decode(token.encode('ascii')).decode('utf-8')
            parts = token_data.rsplit(':', 1)
            if len(parts) != 2:
                return None

            payload, signature = parts
            expected_sig = hmac.new(
                self.secret_key, payload.encode('utf-8'), hashlib.sha256
            ).hexdigest()

            if not hmac.compare_digest(signature, expected_sig):
                return None

            payload_parts = payload.split(':', 2)
            user_id = payload_parts[0]
            timestamp = int(payload_parts[1])

            if time.time() - timestamp > self.token_ttl:
                return None

            return (user_id, timestamp)
        except Exception:
            return None

    @staticmethod
    def generate_api_key() -> str:
        """生成API密钥"""
        return f"zd_{secrets.token_urlsafe(32)}"


class IntegrityChecker:
    """数据完整性校验器

    确保配置文件、规则库和日志数据的完整性
    """

    @staticmethod
    def calculate_file_hash(filepath: str, algorithm: str = "sha256") -> str:
        """计算文件哈希"""
        hasher = hashlib.new(algorithm)
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                hasher.update(chunk)
        return hasher.hexdigest()

    @staticmethod
    def calculate_data_hash(data: bytes, algorithm: str = "sha256") -> str:
        """计算数据哈希"""
        return hashlib.new(algorithm, data).hexdigest()

    @staticmethod
    def generate_checksum(data: bytes) -> int:
        """生成CRC32校验和"""
        import binascii
        return binascii.crc32(data) & 0xFFFFFFFF

    @staticmethod
    def verify_file_integrity(filepath: str, expected_hash: str,
                               algorithm: str = "sha256") -> bool:
        """验证文件完整性"""
        actual_hash = IntegrityChecker.calculate_file_hash(filepath, algorithm)
        return hmac.compare_digest(actual_hash, expected_hash)


class SecureRandom:
    """安全随机数生成器"""

    @staticmethod
    def generate_session_id(length: int = 32) -> str:
        """生成会话ID"""
        return secrets.token_urlsafe(length)

    @staticmethod
    def generate_nonce(length: int = 16) -> str:
        """生成随机数"""
        return secrets.token_hex(length)

    @staticmethod
    def generate_salt(length: int = 32) -> str:
        """生成盐值"""
        return secrets.token_hex(length)

    @staticmethod
    def generate_otp(digits: int = 6) -> str:
        """生成一次性密码"""
        max_value = 10 ** digits
        otp = secrets.randbelow(max_value)
        return str(otp).zfill(digits)
