# -*- coding: utf-8 -*-
"""
智盾网络安全态势感知与智能防御系统 - 用户认证与权限管理模块
提供系统用户的身份认证、角色管理和操作审计功能
"""

import hashlib
import hmac
import logging
import os
import secrets
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


class UserRole(Enum):
    """用户角色"""
    SUPER_ADMIN = "超级管理员"
    SECURITY_ADMIN = "安全管理员"
    SECURITY_ANALYST = "安全分析师"
    OPERATOR = "运维操作员"
    AUDITOR = "审计员"
    VIEWER = "只读用户"


class Permission(Enum):
    """系统权限"""
    VIEW_DASHBOARD = "查看仪表盘"
    VIEW_ALERTS = "查看告警"
    MANAGE_ALERTS = "管理告警"
    VIEW_REPORTS = "查看报告"
    GENERATE_REPORTS = "生成报告"
    MANAGE_RULES = "管理规则"
    BLOCK_IP = "封禁IP"
    UNBLOCK_IP = "解封IP"
    MANAGE_USERS = "管理用户"
    MANAGE_ASSETS = "管理资产"
    VIEW_AUDIT_LOG = "查看审计日志"
    SYSTEM_CONFIG = "系统配置"
    EXPORT_DATA = "导出数据"
    MANAGE_INTEL = "管理情报"


# 角色-权限映射
ROLE_PERMISSIONS: Dict[UserRole, Set[Permission]] = {
    UserRole.SUPER_ADMIN: set(Permission),
    UserRole.SECURITY_ADMIN: {
        Permission.VIEW_DASHBOARD, Permission.VIEW_ALERTS,
        Permission.MANAGE_ALERTS, Permission.VIEW_REPORTS,
        Permission.GENERATE_REPORTS, Permission.MANAGE_RULES,
        Permission.BLOCK_IP, Permission.UNBLOCK_IP,
        Permission.MANAGE_ASSETS, Permission.MANAGE_INTEL,
        Permission.EXPORT_DATA,
    },
    UserRole.SECURITY_ANALYST: {
        Permission.VIEW_DASHBOARD, Permission.VIEW_ALERTS,
        Permission.MANAGE_ALERTS, Permission.VIEW_REPORTS,
        Permission.GENERATE_REPORTS, Permission.MANAGE_INTEL,
    },
    UserRole.OPERATOR: {
        Permission.VIEW_DASHBOARD, Permission.VIEW_ALERTS,
        Permission.BLOCK_IP, Permission.UNBLOCK_IP,
        Permission.MANAGE_ASSETS,
    },
    UserRole.AUDITOR: {
        Permission.VIEW_DASHBOARD, Permission.VIEW_ALERTS,
        Permission.VIEW_REPORTS, Permission.VIEW_AUDIT_LOG,
        Permission.EXPORT_DATA,
    },
    UserRole.VIEWER: {
        Permission.VIEW_DASHBOARD, Permission.VIEW_ALERTS,
        Permission.VIEW_REPORTS,
    },
}


@dataclass
class UserAccount:
    """用户账户"""
    user_id: str
    username: str
    password_hash: str
    salt: str
    role: UserRole
    display_name: str = ""
    email: str = ""
    phone: str = ""
    is_active: bool = True
    is_locked: bool = False
    created_at: float = 0
    last_login: float = 0
    failed_login_count: int = 0
    password_changed_at: float = 0
    mfa_enabled: bool = False
    mfa_secret: str = ""
    allowed_ips: List[str] = field(default_factory=list)

    def __post_init__(self):
        if not self.created_at:
            self.created_at = time.time()

    def to_dict(self) -> Dict:
        return {
            "user_id": self.user_id,
            "username": self.username,
            "role": self.role.value,
            "display_name": self.display_name,
            "email": self.email,
            "is_active": self.is_active,
            "is_locked": self.is_locked,
            "last_login": self.last_login,
            "mfa_enabled": self.mfa_enabled,
        }


@dataclass
class Session:
    """用户会话"""
    session_id: str
    user_id: str
    created_at: float
    expires_at: float
    ip_address: str
    user_agent: str = ""
    is_active: bool = True

    @property
    def is_expired(self) -> bool:
        return time.time() > self.expires_at


@dataclass
class AuditLogEntry:
    """审计日志条目"""
    log_id: str
    timestamp: float
    user_id: str
    username: str
    action: str
    resource: str
    details: str
    ip_address: str
    success: bool

    def to_dict(self) -> Dict:
        return {
            "log_id": self.log_id,
            "timestamp": self.timestamp,
            "username": self.username,
            "action": self.action,
            "resource": self.resource,
            "details": self.details,
            "ip_address": self.ip_address,
            "success": self.success,
        }


class PasswordManager:
    """密码管理器"""

    ITERATIONS = 100000
    HASH_ALGORITHM = "sha256"

    @classmethod
    def hash_password(cls, password: str, salt: Optional[str] = None) -> tuple:
        """哈希密码"""
        if salt is None:
            salt = secrets.token_hex(32)
        password_hash = hashlib.pbkdf2_hmac(
            cls.HASH_ALGORITHM,
            password.encode('utf-8'),
            salt.encode('utf-8'),
            cls.ITERATIONS
        ).hex()
        return password_hash, salt

    @classmethod
    def verify_password(cls, password: str, password_hash: str, salt: str) -> bool:
        """验证密码"""
        computed_hash, _ = cls.hash_password(password, salt)
        return hmac.compare_digest(computed_hash, password_hash)

    @staticmethod
    def check_password_strength(password: str) -> Dict:
        """检查密码强度"""
        issues = []
        score = 0

        if len(password) >= 8:
            score += 20
        else:
            issues.append("密码长度至少8位")

        if len(password) >= 12:
            score += 10

        if any(c.isupper() for c in password):
            score += 20
        else:
            issues.append("需包含大写字母")

        if any(c.islower() for c in password):
            score += 20
        else:
            issues.append("需包含小写字母")

        if any(c.isdigit() for c in password):
            score += 15
        else:
            issues.append("需包含数字")

        special_chars = set("!@#$%^&*()_+-=[]{}|;':\",./<>?")
        if any(c in special_chars for c in password):
            score += 15
        else:
            issues.append("需包含特殊字符")

        if score >= 80:
            strength = "强"
        elif score >= 60:
            strength = "中"
        else:
            strength = "弱"

        return {
            "score": score,
            "strength": strength,
            "issues": issues,
            "is_valid": score >= 60 and not issues,
        }


class UserAuthManager:
    """用户认证与权限管理器

    核心功能：
    1. 用户注册与认证
    2. 基于角色的访问控制(RBAC)
    3. 会话管理
    4. 操作审计日志
    5. 密码安全策略
    6. 登录失败锁定
    """

    MAX_FAILED_ATTEMPTS = 5
    LOCK_DURATION = 1800         # 锁定30分钟
    SESSION_TIMEOUT = 3600       # 会话有效期1小时
    PASSWORD_MAX_AGE = 7776000   # 密码有效期90天

    def __init__(self):
        self._users: Dict[str, UserAccount] = {}
        self._sessions: Dict[str, Session] = {}
        self._audit_log: List[AuditLogEntry] = []
        self._username_index: Dict[str, str] = {}

        self._create_default_admin()
        logger.info("用户认证管理器初始化完成")

    def _create_default_admin(self):
        """创建默认管理员账户"""
        default_password = secrets.token_urlsafe(16)
        password_hash, salt = PasswordManager.hash_password(default_password)

        admin = UserAccount(
            user_id="USR-ADMIN-001",
            username="admin",
            password_hash=password_hash,
            salt=salt,
            role=UserRole.SUPER_ADMIN,
            display_name="系统管理员",
            email="admin@zhidun.local",
        )
        self._users[admin.user_id] = admin
        self._username_index[admin.username] = admin.user_id
        logger.info(f"默认管理员账户已创建, 初始密码: {default_password}")

    def create_user(self, username: str, password: str, role: UserRole,
                    display_name: str = "", email: str = "",
                    operator_id: str = "") -> Optional[UserAccount]:
        """创建用户"""
        if username in self._username_index:
            logger.warning(f"用户名已存在: {username}")
            return None

        strength = PasswordManager.check_password_strength(password)
        if not strength["is_valid"]:
            logger.warning(f"密码不符合安全策略: {strength['issues']}")
            return None

        password_hash, salt = PasswordManager.hash_password(password)
        user_id = f"USR-{secrets.token_hex(8).upper()}"

        user = UserAccount(
            user_id=user_id,
            username=username,
            password_hash=password_hash,
            salt=salt,
            role=role,
            display_name=display_name or username,
            email=email,
            password_changed_at=time.time(),
        )

        self._users[user_id] = user
        self._username_index[username] = user_id

        self._log_audit(operator_id, "创建用户", "user",
                        f"创建用户 {username} (角色: {role.value})", "system", True)
        return user

    def authenticate(self, username: str, password: str,
                     ip_address: str) -> Optional[Session]:
        """用户认证"""
        user_id = self._username_index.get(username)
        if not user_id or user_id not in self._users:
            self._log_audit("", "登录", "auth",
                            f"用户名不存在: {username}", ip_address, False)
            return None

        user = self._users[user_id]

        if not user.is_active:
            self._log_audit(user_id, "登录", "auth",
                            "账户已禁用", ip_address, False)
            return None

        if user.is_locked:
            self._log_audit(user_id, "登录", "auth",
                            "账户已锁定", ip_address, False)
            return None

        if user.allowed_ips and ip_address not in user.allowed_ips:
            self._log_audit(user_id, "登录", "auth",
                            f"IP不在允许列表: {ip_address}", ip_address, False)
            return None

        if not PasswordManager.verify_password(password, user.password_hash, user.salt):
            user.failed_login_count += 1
            if user.failed_login_count >= self.MAX_FAILED_ATTEMPTS:
                user.is_locked = True
                logger.warning(f"用户 {username} 因连续登录失败已被锁定")

            self._log_audit(user_id, "登录", "auth",
                            f"密码错误 (第{user.failed_login_count}次)", ip_address, False)
            return None

        # 认证成功
        user.failed_login_count = 0
        user.last_login = time.time()

        session = Session(
            session_id=secrets.token_urlsafe(32),
            user_id=user_id,
            created_at=time.time(),
            expires_at=time.time() + self.SESSION_TIMEOUT,
            ip_address=ip_address,
        )
        self._sessions[session.session_id] = session

        self._log_audit(user_id, "登录", "auth", "登录成功", ip_address, True)
        return session

    def validate_session(self, session_id: str) -> Optional[UserAccount]:
        """验证会话"""
        session = self._sessions.get(session_id)
        if not session or session.is_expired or not session.is_active:
            return None

        user = self._users.get(session.user_id)
        if not user or not user.is_active:
            return None

        return user

    def check_permission(self, user_id: str, permission: Permission) -> bool:
        """检查权限"""
        user = self._users.get(user_id)
        if not user or not user.is_active:
            return False

        user_permissions = ROLE_PERMISSIONS.get(user.role, set())
        return permission in user_permissions

    def logout(self, session_id: str) -> bool:
        """用户登出"""
        session = self._sessions.get(session_id)
        if session:
            session.is_active = False
            user = self._users.get(session.user_id)
            username = user.username if user else "unknown"
            self._log_audit(session.user_id, "登出", "auth",
                            "用户登出", session.ip_address, True)
            return True
        return False

    def change_password(self, user_id: str, old_password: str,
                        new_password: str) -> bool:
        """修改密码"""
        user = self._users.get(user_id)
        if not user:
            return False

        if not PasswordManager.verify_password(old_password, user.password_hash, user.salt):
            return False

        strength = PasswordManager.check_password_strength(new_password)
        if not strength["is_valid"]:
            return False

        password_hash, salt = PasswordManager.hash_password(new_password)
        user.password_hash = password_hash
        user.salt = salt
        user.password_changed_at = time.time()

        self._log_audit(user_id, "修改密码", "auth",
                        "密码已更新", "system", True)
        return True

    def unlock_user(self, user_id: str, operator_id: str) -> bool:
        """解锁用户"""
        user = self._users.get(user_id)
        if not user:
            return False

        user.is_locked = False
        user.failed_login_count = 0

        self._log_audit(operator_id, "解锁用户", "user",
                        f"解锁用户 {user.username}", "system", True)
        return True

    def _log_audit(self, user_id: str, action: str, resource: str,
                   details: str, ip_address: str, success: bool):
        """记录审计日志"""
        user = self._users.get(user_id)
        username = user.username if user else "unknown"

        entry = AuditLogEntry(
            log_id=f"AUDIT-{secrets.token_hex(8)}",
            timestamp=time.time(),
            user_id=user_id,
            username=username,
            action=action,
            resource=resource,
            details=details,
            ip_address=ip_address,
            success=success,
        )
        self._audit_log.append(entry)

    def get_audit_log(self, limit: int = 100, user_id: Optional[str] = None) -> List[Dict]:
        """获取审计日志"""
        logs = self._audit_log
        if user_id:
            logs = [l for l in logs if l.user_id == user_id]
        logs = sorted(logs, key=lambda x: x.timestamp, reverse=True)
        return [l.to_dict() for l in logs[:limit]]

    def get_user_statistics(self) -> Dict:
        """获取用户统计"""
        role_counts = {}
        active_count = 0
        locked_count = 0

        for user in self._users.values():
            role_counts[user.role.value] = role_counts.get(user.role.value, 0) + 1
            if user.is_active:
                active_count += 1
            if user.is_locked:
                locked_count += 1

        active_sessions = sum(
            1 for s in self._sessions.values()
            if s.is_active and not s.is_expired
        )

        return {
            "total_users": len(self._users),
            "active_users": active_count,
            "locked_users": locked_count,
            "active_sessions": active_sessions,
            "role_distribution": role_counts,
            "audit_log_entries": len(self._audit_log),
        }
