# -*- coding: utf-8 -*-
"""
公文校验工具 - 主应用

功能：
- 支持 .txt / .docx 文件上传校验
- 支持直接粘贴文本校验
- 错别字检测（词典 + AI模型）
- 格式规范检测（GB/T 9704-2012）
- 完全离线运行，适合政务内网部署
"""

import os
import uuid
import chardet
from flask import Flask, request, jsonify, render_template, send_from_directory
from werkzeug.utils import secure_filename

from config import (
    UPLOAD_FOLDER, MAX_CONTENT_LENGTH, ALLOWED_EXTENSIONS,
    HOST, PORT, DEBUG
)
from checker.typo_checker import TypoChecker
from checker.format_checker import FormatChecker

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

# 确保上传目录存在
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# 初始化检测器（全局单例，避免重复加载词典）
print('[初始化] 正在加载错别字检测模块...')
typo_checker = TypoChecker()
print('[初始化] 正在加载格式检测模块...')
format_checker = FormatChecker()
print('[初始化] 所有模块加载完成，服务就绪！')


def allowed_file(filename):
    """检查文件扩展名是否允许"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def read_text_file(filepath):
    """智能读取文本文件（自动检测编码）"""
    with open(filepath, 'rb') as f:
        raw = f.read()
    detected = chardet.detect(raw)
    encoding = detected.get('encoding', 'utf-8') or 'utf-8'
    try:
        return raw.decode(encoding)
    except (UnicodeDecodeError, LookupError):
        return raw.decode('utf-8', errors='replace')


def extract_docx_text(filepath):
    """从docx文件提取纯文本"""
    from docx import Document
    doc = Document(filepath)
    return '\n'.join(para.text for para in doc.paragraphs)


@app.route('/')
def index():
    """主页"""
    return render_template('index.html')


@app.route('/api/check', methods=['POST'])
def check_document():
    """
    公文校验API

    支持两种方式：
    1. 上传文件（form-data, field: file）
    2. 提交文本（JSON, field: text）

    返回：
    {
        "success": true,
        "typo_errors": [...],
        "format_issues": [...],
        "layout_issues": [...],
        "summary": {...}
    }
    """
    text = None
    filename = None
    layout_issues = []
    is_docx = False

    # 方式1：文件上传
    if 'file' in request.files:
        file = request.files['file']
        if file.filename == '':
            return jsonify({'success': False, 'error': '未选择文件'}), 400

        if not allowed_file(file.filename):
            return jsonify({
                'success': False,
                'error': f'不支持的文件类型，仅支持：{", ".join(ALLOWED_EXTENSIONS)}'
            }), 400

        # 保存文件
        ext = file.filename.rsplit('.', 1)[1].lower()
        safe_name = f'{uuid.uuid4().hex}.{ext}'
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], safe_name)
        file.save(filepath)
        filename = file.filename

        try:
            if ext == 'docx':
                is_docx = True
                text = extract_docx_text(filepath)
            elif ext == 'txt':
                text = read_text_file(filepath)
            else:
                return jsonify({'success': False, 'error': '不支持的文件类型'}), 400
        except Exception as e:
            return jsonify({'success': False, 'error': f'文件读取失败：{str(e)}'}), 500
        finally:
            # 清理上传文件
            try:
                os.remove(filepath)
            except OSError:
                pass

    # 方式2：文本提交
    elif request.is_json:
        data = request.get_json()
        text = data.get('text', '').strip()
        if not text:
            return jsonify({'success': False, 'error': '请输入待校验的文本'}), 400
    else:
        return jsonify({'success': False, 'error': '请上传文件或提交文本'}), 400

    if not text or not text.strip():
        return jsonify({'success': False, 'error': '文档内容为空'}), 400

    # 执行检测
    typo_errors = typo_checker.check(text)

    if is_docx:
        format_issues_text, layout_issues, _ = format_checker.check_docx(filepath if os.path.exists(filepath) else '')
        # 如果docx已删除，仅用纯文本检测
        if not format_issues_text:
            format_issues_text = format_checker.check_text(text)
    else:
        format_issues_text = format_checker.check_text(text)

    # 生成摘要统计
    summary = _build_summary(typo_errors, format_issues_text, layout_issues)

    return jsonify({
        'success': True,
        'filename': filename,
        'text_preview': text[:200] + '...' if len(text) > 200 else text,
        'total_chars': len(text),
        'typo_errors': typo_errors,
        'format_issues': format_issues_text,
        'layout_issues': layout_issues,
        'summary': summary
    })


@app.route('/api/check-text', methods=['POST'])
def check_text_only():
    """纯文本校验接口（简化版）"""
    data = request.get_json()
    if not data or not data.get('text'):
        return jsonify({'success': False, 'error': '请输入文本'}), 400

    text = data['text'].strip()
    typo_errors = typo_checker.check(text)
    format_issues = format_checker.check_text(text)

    summary = _build_summary(typo_errors, format_issues, [])

    return jsonify({
        'success': True,
        'typo_errors': typo_errors,
        'format_issues': format_issues,
        'summary': summary
    })


def _build_summary(typo_errors, format_issues, layout_issues):
    """构建检测结果摘要"""
    typo_by_severity = {'error': 0, 'warning': 0, 'info': 0}
    for e in typo_errors:
        typo_by_severity[e.get('severity', 'info')] += 1

    format_by_severity = {'error': 0, 'warning': 0, 'info': 0}
    for f in format_issues:
        format_by_severity[f.get('severity', 'info')] += 1

    layout_count = len(layout_issues)

    total_errors = typo_by_severity['error'] + format_by_severity['error']
    total_warnings = typo_by_severity['warning'] + format_by_severity['warning']
    total_info = typo_by_severity['info'] + format_by_severity['info'] + layout_count

    # 评分（100分制）
    score = 100
    score -= total_errors * 5
    score -= total_warnings * 2
    score -= total_info * 0.5
    score = max(0, min(100, score))

    # 评级
    if score >= 95:
        grade = 'A'
        grade_text = '优秀'
    elif score >= 85:
        grade = 'B'
        grade_text = '良好'
    elif score >= 70:
        grade = 'C'
        grade_text = '一般'
    elif score >= 60:
        grade = 'D'
        grade_text = '较差'
    else:
        grade = 'E'
        grade_text = '需修改'

    return {
        'total_issues': len(typo_errors) + len(format_issues) + layout_count,
        'typo_count': len(typo_errors),
        'format_count': len(format_issues),
        'layout_count': layout_count,
        'errors': total_errors,
        'warnings': total_warnings,
        'info': total_info,
        'score': round(score, 1),
        'grade': grade,
        'grade_text': grade_text
    }


if __name__ == '__main__':
    print(f'========================================')
    print(f'  公文校验工具 v1.0')
    print(f'  访问地址：http://localhost:{PORT}')
    print(f'  局域网地址：http://0.0.0.0:{PORT}')
    print(f'========================================')
    app.run(host=HOST, port=PORT, debug=DEBUG)
