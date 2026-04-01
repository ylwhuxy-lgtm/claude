#!/bin/bash
# 公文校验工具 - 启动脚本 (Linux/macOS)

set -e

echo "========================================"
echo "  公文校验工具 - 启动脚本 (Linux)"
echo "========================================"
echo ""

# 获取脚本所在目录
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# 检查 Python
if ! command -v python3 &> /dev/null; then
    echo "[错误] 未检测到 Python3，请先安装"
    echo "  Ubuntu/Debian: sudo apt install python3 python3-pip python3-venv"
    echo "  CentOS/RHEL:   sudo yum install python3 python3-pip"
    exit 1
fi

PYTHON=python3

echo "[信息] Python 版本: $($PYTHON --version)"

# 创建虚拟环境
if [ ! -d "venv" ]; then
    echo "[步骤1] 创建虚拟环境..."
    $PYTHON -m venv venv
    echo "[完成] 虚拟环境已创建"
fi

# 激活虚拟环境
echo "[步骤2] 激活虚拟环境..."
source venv/bin/activate

# 安装依赖
echo "[步骤3] 检查并安装依赖..."
pip install -r requirements.txt -q
echo "[完成] 依赖安装完成"

# 启动服务
echo ""
echo "[启动] 正在启动公文校验服务..."
echo "[提示] 浏览器访问 http://localhost:5000"
echo "[提示] 局域网访问 http://$(hostname -I 2>/dev/null | awk '{print $1}' || echo '0.0.0.0'):5000"
echo "[提示] 按 Ctrl+C 停止服务"
echo ""
python app.py
