# -*- coding: utf-8 -*-
"""公文校验工具配置文件"""

import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# 上传文件配置
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB
ALLOWED_EXTENSIONS = {'txt', 'docx', 'doc'}

# 字典文件路径
DICT_DIR = os.path.join(BASE_DIR, 'dictionaries')
GOV_TERMS_FILE = os.path.join(DICT_DIR, 'gov_terms.txt')
CONFUSABLES_FILE = os.path.join(DICT_DIR, 'confusables.txt')
COMMON_ERRORS_FILE = os.path.join(DICT_DIR, 'common_errors.txt')

# 公文格式规范（GB/T 9704-2012）
FORMAT_RULES = {
    # 标题
    'title_font': '方正小标宋体',
    'title_size': 22,  # 二号字
    'title_alignment': 'center',

    # 发文字号
    'doc_number_font': '仿宋',
    'doc_number_size': 16,  # 三号字

    # 正文
    'body_font': '仿宋',
    'body_size': 16,  # 三号字
    'body_line_spacing': 28.95,  # 行距（磅）

    # 页面设置
    'page_top_margin': 37,  # mm
    'page_bottom_margin': 35,
    'page_left_margin': 28,
    'page_right_margin': 26,
}

# 服务器配置
HOST = '0.0.0.0'
PORT = 5000
DEBUG = False
