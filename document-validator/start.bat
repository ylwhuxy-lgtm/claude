@echo off
chcp 65001 >nul
title 公文校验工具

echo ========================================
echo   公文校验工具 - 启动脚本 (Windows)
echo ========================================
echo.

:: 检查 Python 是否安装
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [错误] 未检测到 Python，请先安装 Python 3.8+
    echo 下载地址：https://www.python.org/downloads/
    pause
    exit /b 1
)

:: 检查虚拟环境是否存在
if not exist "venv" (
    echo [步骤1] 创建虚拟环境...
    python -m venv venv
    if %errorlevel% neq 0 (
        echo [错误] 创建虚拟环境失败
        pause
        exit /b 1
    )
    echo [完成] 虚拟环境已创建
)

:: 激活虚拟环境
echo [步骤2] 激活虚拟环境...
call venv\Scripts\activate.bat

:: 安装依赖
echo [步骤3] 检查并安装依赖...
pip install -r requirements.txt -q
if %errorlevel% neq 0 (
    echo [警告] 部分依赖安装可能失败，尝试继续运行...
)

:: 启动服务
echo.
echo [启动] 正在启动公文校验服务...
echo [提示] 浏览器访问 http://localhost:5000
echo [提示] 按 Ctrl+C 停止服务
echo.
python app.py

pause
