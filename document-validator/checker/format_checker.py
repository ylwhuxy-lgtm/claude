# -*- coding: utf-8 -*-
"""
公文格式校验模块

基于《党政机关公文格式》（GB/T 9704-2012）标准
检测公文的格式规范性，包括：
- 文本结构完整性
- 发文字号格式
- 标题格式
- 正文段落格式
- 成文日期格式
- 附件标注规范
- 主送机关与抄送机关
- 页面设置（针对docx文件）
"""

import re
from docx import Document
from docx.shared import Pt, Cm, Mm
from docx.enum.text import WD_ALIGN_PARAGRAPH


class FormatChecker:
    """公文格式校验器"""

    def __init__(self):
        # 公文要素正则
        self.patterns = {
            # 发文字号：〔〕括起年份 + 号
            'doc_number': re.compile(
                r'^[\u4e00-\u9fff]+〔\d{4}〕\d+号$'
            ),
            # 成文日期（中文格式）
            'date_chinese': re.compile(
                r'^[二〇一三四五六七八九]{4}年[一二三四五六七八九十]{1,3}月[一二三四五六七八九十]{1,4}日$'
            ),
            # 成文日期（阿拉伯数字格式）
            'date_arabic': re.compile(
                r'^\d{4}年\d{1,2}月\d{1,2}日$'
            ),
            # 附件标注
            'attachment': re.compile(
                r'^附件[：:]?\s*\d*[.、]?\s*'
            ),
            # 主送机关行
            'recipient': re.compile(
                r'^[\u4e00-\u9fff].*[：:]$'
            ),
            # 抄送行
            'cc_line': re.compile(
                r'^抄送[：:]'
            ),
            # 标题行（关于...的...）
            'title_pattern': re.compile(
                r'关于.+的(通知|通报|请示|报告|批复|决定|命令|公告|通告|意见|函|纪要|办法|规定|方案|计划|总结)'
            ),
        }

    def check_text(self, text):
        """
        检查纯文本公文格式

        Args:
            text: 公文全文

        Returns:
            list: 格式问题列表
        """
        issues = []
        lines = text.split('\n')
        non_empty_lines = [(i + 1, line) for i, line in enumerate(lines) if line.strip()]

        if not non_empty_lines:
            return [self._issue(0, 'structure', 'error', '文档内容为空')]

        # 1. 检查基本结构完整性
        issues.extend(self._check_structure(text, non_empty_lines))

        # 2. 检查发文字号
        issues.extend(self._check_doc_number(text, non_empty_lines))

        # 3. 检查标题
        issues.extend(self._check_title(text, non_empty_lines))

        # 4. 检查正文段落格式
        issues.extend(self._check_paragraphs(text, lines))

        # 5. 检查成文日期
        issues.extend(self._check_date(text, non_empty_lines))

        # 6. 检查附件标注
        issues.extend(self._check_attachment(text, lines))

        # 7. 检查抄送格式
        issues.extend(self._check_cc(text, lines))

        # 8. 检查特此类结束语
        issues.extend(self._check_closing(text, non_empty_lines))

        return issues

    def check_docx(self, filepath):
        """
        检查docx文件的格式（含排版信息）

        Args:
            filepath: docx文件路径

        Returns:
            tuple: (文本格式问题列表, 排版格式问题列表, 提取的纯文本)
        """
        try:
            doc = Document(filepath)
        except Exception as e:
            return [self._issue(0, 'file', 'error', f'无法打开文件：{str(e)}')], [], ''

        text_lines = []
        layout_issues = []

        # 检查页面设置
        layout_issues.extend(self._check_page_setup(doc))

        # 检查段落格式
        for i, para in enumerate(doc.paragraphs):
            text_lines.append(para.text)

            if not para.text.strip():
                continue

            # 检查字体和字号
            layout_issues.extend(self._check_paragraph_format(para, i + 1))

        full_text = '\n'.join(text_lines)
        text_issues = self.check_text(full_text)

        return text_issues, layout_issues, full_text

    def _check_structure(self, text, non_empty_lines):
        """检查公文基本结构"""
        issues = []

        # 检查是否有标题（一般在前几行）
        has_title = False
        for line_num, line in non_empty_lines[:5]:
            if self.patterns['title_pattern'].search(line):
                has_title = True
                break

        if not has_title:
            issues.append(self._issue(
                1, 'structure', 'warning',
                '未检测到标准公文标题（格式通常为"关于XX的通知/报告/请示"等）'
            ))

        # 检查是否有落款单位和日期
        has_date = False
        for line_num, line in non_empty_lines[-8:]:
            line_stripped = line.strip()
            if (self.patterns['date_chinese'].match(line_stripped) or
                    self.patterns['date_arabic'].match(line_stripped)):
                has_date = True
                break

        if not has_date:
            issues.append(self._issue(
                non_empty_lines[-1][0] if non_empty_lines else 0,
                'structure', 'warning',
                '未检测到成文日期，公文应包含成文日期'
            ))

        return issues

    def _check_doc_number(self, text, non_empty_lines):
        """检查发文字号格式"""
        issues = []

        for line_num, line in non_empty_lines[:10]:
            line_stripped = line.strip()

            # 检测疑似发文字号的行
            if re.search(r'〔\d{4}〕', line_stripped) or re.search(r'\[\d{4}\]', line_stripped):
                # 检查是否使用了错误的括号
                if '[' in line_stripped or ']' in line_stripped:
                    issues.append(self._issue(
                        line_num, 'doc_number', 'error',
                        f'发文字号应使用六角括号"〔〕"，而非方括号"[]"，当前："{line_stripped}"'
                    ))
                elif '【' in line_stripped or '】' in line_stripped:
                    issues.append(self._issue(
                        line_num, 'doc_number', 'error',
                        f'发文字号应使用六角括号"〔〕"，而非黑方括号"【】"，当前："{line_stripped}"'
                    ))

                # 检查字号前是否有"第"字
                if re.search(r'第\d+号', line_stripped):
                    issues.append(self._issue(
                        line_num, 'doc_number', 'error',
                        '发文字号中序号前不应加"第"字'
                    ))

                # 验证完整格式
                if not self.patterns['doc_number'].match(line_stripped):
                    if '〔' in line_stripped:
                        issues.append(self._issue(
                            line_num, 'doc_number', 'warning',
                            f'发文字号格式可能不规范，标准格式为"XX〔YYYY〕N号"，当前："{line_stripped}"'
                        ))
                break

        return issues

    def _check_title(self, text, non_empty_lines):
        """检查标题格式"""
        issues = []

        for line_num, line in non_empty_lines[:8]:
            if self.patterns['title_pattern'].search(line):
                title = line.strip()

                # 标题不应有标点（句号等）
                if title.endswith('。') or title.endswith('，') or title.endswith('；'):
                    issues.append(self._issue(
                        line_num, 'title', 'error',
                        '公文标题末尾不应有句号等标点符号'
                    ))

                # 标题中的书名号使用检查
                if '《' in title and '》' not in title:
                    issues.append(self._issue(
                        line_num, 'title', 'error',
                        '标题中书名号不配对'
                    ))

                # 标题过长提醒
                if len(title) > 50:
                    issues.append(self._issue(
                        line_num, 'title', 'info',
                        f'标题较长（{len(title)}字），建议控制在一至两行以内'
                    ))

                break

        return issues

    def _check_paragraphs(self, text, lines):
        """检查正文段落格式"""
        issues = []
        in_body = False

        for i, line in enumerate(lines):
            line_num = i + 1

            # 简单判断是否进入正文区域（在主送机关之后）
            if self.patterns['recipient'].match(line.strip()):
                in_body = True
                continue

            if not in_body or not line.strip():
                continue

            # 检查首行缩进（应有两个中文字符的缩进）
            if line and not line[0].isspace() and '\u4e00' <= line[0] <= '\u9fff':
                # 正文段落未缩进
                # 排除特殊行（标题、序号行等）
                stripped = line.strip()
                if not any(stripped.startswith(p) for p in [
                    '一、', '二、', '三、', '四、', '五、', '六、', '七、',
                    '八、', '九、', '十、', '（一）', '（二）', '（三）',
                    '（四）', '（五）', '附件', '抄送', '主送', '特此',
                    '以上', '此复', '妥否',
                ]):
                    issues.append(self._issue(
                        line_num, 'paragraph', 'info',
                        '正文段落首行可能未缩进两个字符'
                    ))

            # 检查段落间多余空行
            if i > 0 and not lines[i].strip() and i + 1 < len(lines) and not lines[i + 1].strip():
                issues.append(self._issue(
                    line_num, 'paragraph', 'warning',
                    '段落间不应有多余空行'
                ))

        return issues

    def _check_date(self, text, non_empty_lines):
        """检查成文日期格式"""
        issues = []

        for line_num, line in non_empty_lines:
            stripped = line.strip()

            # 中文日期格式检查
            if self.patterns['date_chinese'].match(stripped):
                # 检查"零"和"〇"
                if '零' in stripped:
                    issues.append(self._issue(
                        line_num, 'date', 'error',
                        f'成文日期中"零"应写作"〇"（圆圈零），当前："{stripped}"'
                    ))
                break

            # 阿拉伯日期格式检查
            if self.patterns['date_arabic'].match(stripped):
                # 公文正式用中文日期
                issues.append(self._issue(
                    line_num, 'date', 'info',
                    f'成文日期建议使用中文小写数字，如"二〇二五年一月一日"，当前："{stripped}"'
                ))
                break

            # 检测不规范的日期写法
            date_match = re.search(r'(\d{4})[./\-](\d{1,2})[./\-](\d{1,2})', stripped)
            if date_match and len(stripped) < 20:
                issues.append(self._issue(
                    line_num, 'date', 'error',
                    f'日期格式不规范，不应使用"/""-""."分隔，当前："{stripped}"'
                ))

        return issues

    def _check_attachment(self, text, lines):
        """检查附件标注"""
        issues = []
        has_attachment_ref = '附件' in text
        attachment_section_found = False

        for i, line in enumerate(lines):
            if self.patterns['attachment'].match(line.strip()):
                attachment_section_found = True
                stripped = line.strip()

                # 检查附件标注后是否有冒号
                if '附件' in stripped and '：' not in stripped and ':' not in stripped:
                    if re.match(r'^附件\s*$', stripped):
                        issues.append(self._issue(
                            i + 1, 'attachment', 'warning',
                            '"附件"后应标注附件名称'
                        ))

        # 如果正文中提到附件但没有附件列表
        if has_attachment_ref and not attachment_section_found:
            # 检查是否在正文中引用了附件
            for i, line in enumerate(lines):
                if '见附件' in line or '详见附件' in line or '如附件' in line:
                    issues.append(self._issue(
                        i + 1, 'attachment', 'warning',
                        '正文引用了附件，但未找到附件标注部分'
                    ))
                    break

        return issues

    def _check_cc(self, text, lines):
        """检查抄送格式"""
        issues = []

        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith('抄送'):
                # 检查冒号
                if '：' not in stripped and ':' in stripped:
                    issues.append(self._issue(
                        i + 1, 'cc', 'warning',
                        '抄送后应使用中文冒号"："'
                    ))

                # 检查抄送单位间的分隔符（应用逗号，最后用句号）
                after_colon = stripped.split('：')[-1] if '：' in stripped else stripped.split(':')[-1]
                if '、' in after_colon:
                    issues.append(self._issue(
                        i + 1, 'cc', 'info',
                        '抄送机关之间通常使用逗号"，"分隔，最后以句号"。"结尾'
                    ))

        return issues

    def _check_closing(self, text, non_empty_lines):
        """检查结束语规范"""
        issues = []

        closing_phrases = ['特此通知', '特此通报', '特此函达', '特此函复',
                           '此复', '妥否，请批示', '以上报告，请审议']

        for line_num, line in non_empty_lines:
            stripped = line.strip()
            for phrase in closing_phrases:
                if phrase in stripped:
                    # 结束语应单独成段
                    if stripped != phrase and not stripped.endswith('。'):
                        remaining = stripped.replace(phrase, '').strip()
                        if remaining and remaining not in ['。', '！']:
                            issues.append(self._issue(
                                line_num, 'closing', 'info',
                                f'"{phrase}"通常应单独成段'
                            ))

        return issues

    def _check_page_setup(self, doc):
        """检查docx文件的页面设置"""
        issues = []

        for section in doc.sections:
            # 检查页边距（GB/T 9704-2012标准）
            if section.top_margin and abs(section.top_margin.mm - 37) > 2:
                issues.append(self._issue(
                    0, 'layout', 'warning',
                    f'上页边距为{section.top_margin.mm:.1f}mm，标准为37mm（±2mm）'
                ))
            if section.bottom_margin and abs(section.bottom_margin.mm - 35) > 2:
                issues.append(self._issue(
                    0, 'layout', 'warning',
                    f'下页边距为{section.bottom_margin.mm:.1f}mm，标准为35mm（±2mm）'
                ))
            if section.left_margin and abs(section.left_margin.mm - 28) > 2:
                issues.append(self._issue(
                    0, 'layout', 'warning',
                    f'左页边距为{section.left_margin.mm:.1f}mm，标准为28mm（±2mm）'
                ))
            if section.right_margin and abs(section.right_margin.mm - 26) > 2:
                issues.append(self._issue(
                    0, 'layout', 'warning',
                    f'右页边距为{section.right_margin.mm:.1f}mm，标准为26mm（±2mm）'
                ))

        return issues

    def _check_paragraph_format(self, para, para_num):
        """检查单个段落的排版格式"""
        issues = []
        text = para.text.strip()

        if not text:
            return issues

        # 检查字体和字号
        for run in para.runs:
            if not run.text.strip():
                continue

            font = run.font

            # 判断是否为标题行
            is_title = self.patterns['title_pattern'].search(text)

            if is_title:
                # 标题应为二号字（22pt）
                if font.size and abs(font.size.pt - 22) > 1:
                    issues.append(self._issue(
                        para_num, 'font', 'warning',
                        f'标题字号为{font.size.pt}pt，标准应为二号（22pt）'
                    ))
                # 标题应居中
                if para.alignment != WD_ALIGN_PARAGRAPH.CENTER:
                    issues.append(self._issue(
                        para_num, 'font', 'warning',
                        '公文标题应居中排列'
                    ))
            else:
                # 正文应为三号字（16pt）
                if font.size and abs(font.size.pt - 16) > 1 and abs(font.size.pt - 15.75) > 1:
                    issues.append(self._issue(
                        para_num, 'font', 'info',
                        f'正文字号为{font.size.pt}pt，标准应为三号（16pt）'
                    ))

            # 只检查第一个run即可
            break

        return issues

    def _issue(self, line, category, severity, message):
        """构造格式问题条目"""
        return {
            'line': line,
            'category': category,
            'category_label': {
                'structure': '文档结构',
                'doc_number': '发文字号',
                'title': '标题格式',
                'paragraph': '段落格式',
                'date': '成文日期',
                'attachment': '附件标注',
                'cc': '抄送格式',
                'closing': '结束语',
                'layout': '页面设置',
                'font': '字体字号',
                'file': '文件读取',
            }.get(category, category),
            'severity': severity,
            'message': message
        }
