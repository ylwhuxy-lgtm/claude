# -*- coding: utf-8 -*-
"""
公文错别字检测模块

检测策略：
1. 词典匹配：基于公文常见错误词典进行精确匹配
2. 易混淆字检测：基于易混淆字对照表
3. jieba分词 + 规则检测：识别不常见词组
4. pycorrector模型检测：基于统计语言模型的纠错
"""

import os
import re
import jieba

# pycorrector 可选导入（首次使用需下载模型）
try:
    import pycorrector
    PYCORRECTOR_AVAILABLE = True
except Exception:
    PYCORRECTOR_AVAILABLE = False

from config import DICT_DIR, GOV_TERMS_FILE, CONFUSABLES_FILE, COMMON_ERRORS_FILE


class TypoChecker:
    """公文错别字检测器"""

    def __init__(self):
        self.common_errors = {}      # 常见错误词 -> 正确词
        self.confusables = {}        # 易混淆字词
        self.confusable_notes = {}   # 易混淆字说明
        self.gov_terms = set()       # 政务术语词库
        self._load_dictionaries()
        self._init_jieba()

    def _load_dictionaries(self):
        """加载所有词典文件"""
        # 加载常见错误词典
        if os.path.exists(COMMON_ERRORS_FILE):
            with open(COMMON_ERRORS_FILE, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    parts = line.split('|')
                    if len(parts) >= 2:
                        wrong, correct = parts[0].strip(), parts[1].strip()
                        self.common_errors[wrong] = correct

        # 加载易混淆字词典
        if os.path.exists(CONFUSABLES_FILE):
            with open(CONFUSABLES_FILE, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    parts = line.split('|')
                    if len(parts) >= 2:
                        wrong, correct = parts[0].strip(), parts[1].strip()
                        self.confusables[wrong] = correct
                        if len(parts) >= 3:
                            self.confusable_notes[wrong] = parts[2].strip()

        # 加载政务术语
        if os.path.exists(GOV_TERMS_FILE):
            with open(GOV_TERMS_FILE, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    self.gov_terms.add(line)

    def _init_jieba(self):
        """初始化jieba分词，加载自定义词典"""
        # 将政务术语加入jieba词典
        for term in self.gov_terms:
            jieba.add_word(term, freq=100000)

    def check(self, text):
        """
        执行全面的错别字检查

        Args:
            text: 待检查的文本

        Returns:
            list: 错误列表，每项包含 {position, wrong, correct, type, context, note}
        """
        errors = []
        lines = text.split('\n')

        for line_num, line in enumerate(lines, 1):
            # 1. 常见错误词检测
            errors.extend(self._check_common_errors(line, line_num))

            # 2. 易混淆字检测
            errors.extend(self._check_confusables(line, line_num))

            # 3. 标点符号规范检测
            errors.extend(self._check_punctuation(line, line_num))

            # 4. 数字与单位规范检测
            errors.extend(self._check_numbers(line, line_num))

        # 5. pycorrector 模型检测（全文）
        if PYCORRECTOR_AVAILABLE:
            errors.extend(self._check_with_model(text))

        # 去重
        errors = self._deduplicate(errors)

        return errors

    def _check_common_errors(self, line, line_num):
        """基于常见错误词典检测"""
        errors = []
        for wrong, correct in self.common_errors.items():
            start = 0
            while True:
                pos = line.find(wrong, start)
                if pos == -1:
                    break
                context_start = max(0, pos - 5)
                context_end = min(len(line), pos + len(wrong) + 5)
                context = line[context_start:context_end]

                errors.append({
                    'line': line_num,
                    'column': pos + 1,
                    'wrong': wrong,
                    'correct': correct,
                    'type': 'common_error',
                    'type_label': '常见错别字',
                    'severity': 'error',
                    'context': f'...{context}...',
                    'note': f'"{wrong}"应写作"{correct}"'
                })
                start = pos + len(wrong)
        return errors

    def _check_confusables(self, line, line_num):
        """基于易混淆字词典检测"""
        errors = []
        for wrong, correct in self.confusables.items():
            start = 0
            while True:
                pos = line.find(wrong, start)
                if pos == -1:
                    break
                context_start = max(0, pos - 8)
                context_end = min(len(line), pos + len(wrong) + 8)
                context = line[context_start:context_end]

                note = self.confusable_notes.get(wrong, f'"{wrong}"与"{correct}"易混淆，请确认')

                errors.append({
                    'line': line_num,
                    'column': pos + 1,
                    'wrong': wrong,
                    'correct': correct,
                    'type': 'confusable',
                    'type_label': '易混淆字词',
                    'severity': 'warning',
                    'context': f'...{context}...',
                    'note': note
                })
                start = pos + len(wrong)
        return errors

    def _check_punctuation(self, line, line_num):
        """标点符号规范检测"""
        errors = []

        # 检测英文标点（公文应使用中文标点）
        en_punctuation_map = {
            ',': '，',
            '.': '。',
            ':': '：',
            ';': '；',
            '!': '！',
            '?': '？',
            '(': '（',
            ')': '）',
        }

        for i, ch in enumerate(line):
            if ch in en_punctuation_map:
                # 排除数字中的点号和英文上下文
                if ch == '.':
                    # 小数点或英文缩写不报错
                    if i > 0 and line[i - 1].isdigit():
                        continue
                    if i + 1 < len(line) and line[i + 1].isdigit():
                        continue
                    # 英文字母前后不报错
                    if i > 0 and line[i - 1].isascii() and line[i - 1].isalpha():
                        continue
                if ch == ',':
                    # 数字中的逗号不报错（如 1,000）
                    if i > 0 and line[i - 1].isdigit() and i + 1 < len(line) and line[i + 1].isdigit():
                        continue
                    # 英文上下文中不报错
                    if i > 0 and line[i - 1].isascii() and line[i - 1].isalpha():
                        continue
                if ch in ('(', ')'):
                    # 英文/数字上下文不报错
                    if i > 0 and line[i - 1].isascii() and line[i - 1].isalnum():
                        continue
                    if i + 1 < len(line) and line[i + 1].isascii() and line[i + 1].isalnum():
                        continue
                if ch in (':', ';', '!', '?'):
                    if i > 0 and line[i - 1].isascii() and line[i - 1].isalpha():
                        continue

                context_start = max(0, i - 5)
                context_end = min(len(line), i + 6)
                errors.append({
                    'line': line_num,
                    'column': i + 1,
                    'wrong': ch,
                    'correct': en_punctuation_map[ch],
                    'type': 'punctuation',
                    'type_label': '标点符号',
                    'severity': 'warning',
                    'context': f'...{line[context_start:context_end]}...',
                    'note': f'公文应使用中文标点"{en_punctuation_map[ch]}"，而非英文标点"{ch}"'
                })

        # 检测连续标点
        double_punct = re.finditer(r'([，。！？；：])\1+', line)
        for m in double_punct:
            errors.append({
                'line': line_num,
                'column': m.start() + 1,
                'wrong': m.group(),
                'correct': m.group(1),
                'type': 'punctuation',
                'type_label': '标点符号',
                'severity': 'error',
                'context': f'...{line[max(0, m.start() - 5):m.end() + 5]}...',
                'note': '标点符号不应连续重复使用'
            })

        # 检测句末缺少标点
        stripped = line.strip()
        if stripped and len(stripped) > 10:
            # 只检查看起来像正文的行
            last_char = stripped[-1]
            if '\u4e00' <= last_char <= '\u9fff':
                # 以中文字符结尾但没有标点
                # 排除标题类的行（通常较短或有特殊格式）
                if len(stripped) > 20 and not any(stripped.startswith(p) for p in [
                    '第', '一、', '二、', '三、', '四、', '五、', '六、', '七、',
                    '八、', '九、', '十、', '（一）', '（二）', '（三）',
                    '附件', '抄送', '主送', '关于'
                ]):
                    errors.append({
                        'line': line_num,
                        'column': len(stripped),
                        'wrong': '（缺失）',
                        'correct': '。',
                        'type': 'punctuation',
                        'type_label': '标点符号',
                        'severity': 'info',
                        'context': f'...{stripped[-15:]}',
                        'note': '句末可能缺少标点符号'
                    })

        return errors

    def _check_numbers(self, line, line_num):
        """数字与单位规范检测"""
        errors = []

        # 公文中"二〇"年份不应写成"二零"
        match = re.search(r'二零[一二三四五六七八九〇]{2}年', line)
        if match:
            correct = match.group().replace('零', '〇')
            errors.append({
                'line': line_num,
                'column': match.start() + 1,
                'wrong': match.group(),
                'correct': correct,
                'type': 'number_format',
                'type_label': '数字格式',
                'severity': 'error',
                'context': f'...{line[max(0, match.start() - 5):match.end() + 5]}...',
                'note': '公文年份中"零"应写作"〇"（圆圈零）'
            })

        # 检测阿拉伯数字与中文数字混用（在同一句中）
        has_arabic = bool(re.search(r'\d+[年月日号届次]', line))
        has_chinese = bool(re.search(r'[一二三四五六七八九十百千万亿]+[年月日号届次]', line))
        if has_arabic and has_chinese:
            errors.append({
                'line': line_num,
                'column': 1,
                'wrong': '（混用）',
                'correct': '统一使用',
                'type': 'number_format',
                'type_label': '数字格式',
                'severity': 'info',
                'context': line[:30] + '...' if len(line) > 30 else line,
                'note': '同一句中阿拉伯数字与中文数字混用，建议统一'
            })

        return errors

    def _check_with_model(self, text):
        """使用pycorrector模型检测"""
        errors = []
        if not PYCORRECTOR_AVAILABLE:
            return errors

        try:
            lines = text.split('\n')
            for line_num, line in enumerate(lines, 1):
                line = line.strip()
                if not line or len(line) < 2:
                    continue
                # 对过长的行分段处理
                segments = [line[i:i + 128] for i in range(0, len(line), 128)]
                for seg_idx, segment in enumerate(segments):
                    corrected, detail = pycorrector.correct(segment)
                    for wrong, correct, pos in detail:
                        actual_col = seg_idx * 128 + pos + 1
                        context_start = max(0, pos - 5)
                        context_end = min(len(segment), pos + len(wrong) + 5)
                        errors.append({
                            'line': line_num,
                            'column': actual_col,
                            'wrong': wrong,
                            'correct': correct,
                            'type': 'model_detection',
                            'type_label': 'AI模型检测',
                            'severity': 'warning',
                            'context': f'...{segment[context_start:context_end]}...',
                            'note': f'语言模型建议将"{wrong}"修改为"{correct}"'
                        })
        except Exception as e:
            errors.append({
                'line': 0,
                'column': 0,
                'wrong': '',
                'correct': '',
                'type': 'model_detection',
                'type_label': 'AI模型检测',
                'severity': 'info',
                'context': '',
                'note': f'模型检测跳过：{str(e)}'
            })

        return errors

    def _deduplicate(self, errors):
        """去除重复错误"""
        seen = set()
        unique_errors = []
        for err in errors:
            key = (err['line'], err['column'], err['wrong'], err['correct'])
            if key not in seen:
                seen.add(key)
                unique_errors.append(err)
        # 按行号和列号排序
        unique_errors.sort(key=lambda x: (x['line'], x['column']))
        return unique_errors
