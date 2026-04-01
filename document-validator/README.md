# 公文校验工具

完全离线运行的公文错别字、格式规范校验工具，适合政务内网部署。

## 功能特性

### 错别字检测
- **词典匹配**：内置 500+ 公文高频错误词组、易混淆字对照表
- **标点规范**：检测英文标点误用、连续标点、缺失标点
- **数字规范**：检测年份中"零/〇"混用、数字格式不统一
- **AI模型检测**（可选）：基于 pycorrector 语言模型的智能纠错

### 格式规范检测（GB/T 9704-2012）
- **文档结构**：检测标题、发文字号、主送机关、成文日期等要素完整性
- **发文字号**：检测括号类型（六角括号〔〕）、格式规范
- **标题格式**：标题标点、书名号配对、长度提醒
- **段落格式**：首行缩进、多余空行
- **成文日期**：中文日期格式、"零/〇"规范
- **附件标注**：引用与标注的一致性
- **抄送格式**：冒号、分隔符规范

### DOCX 排版检测
- **页面设置**：页边距（上37mm/下35mm/左28mm/右26mm）
- **字体字号**：标题二号（22pt）、正文三号（16pt）
- **标题居中**：检测标题对齐方式

## 系统要求

- **Python**: 3.8 或更高版本
- **操作系统**: Windows 10/11、Linux（Ubuntu/CentOS/麒麟等国产系统）
- **浏览器**: Chrome、Firefox、Edge 等现代浏览器
- **磁盘空间**: 约 500MB（含依赖包）
- **内存**: 建议 2GB 以上

## 快速部署

### Windows 系统

#### 方式一：一键启动（推荐）

1. 安装 Python 3.8+（安装时勾选"Add Python to PATH"）
2. 双击 `start.bat`
3. 浏览器访问 `http://localhost:5000`

#### 方式二：手动安装

```cmd
:: 1. 创建虚拟环境
python -m venv venv

:: 2. 激活虚拟环境
venv\Scripts\activate.bat

:: 3. 安装依赖
pip install -r requirements.txt

:: 4. 启动服务
python app.py
```

### Linux 系统

#### 方式一：一键启动（推荐）

```bash
chmod +x start.sh
./start.sh
```

#### 方式二：手动安装

```bash
# 1. 安装 Python（以 Ubuntu 为例）
sudo apt update
sudo apt install python3 python3-pip python3-venv

# 2. 创建虚拟环境
python3 -m venv venv

# 3. 激活虚拟环境
source venv/bin/activate

# 4. 安装依赖
pip install -r requirements.txt

# 5. 启动服务
python app.py
```

### 离线环境部署（无互联网）

在有网络的机器上预先下载依赖包：

```bash
# 在有网络的机器上
pip download -r requirements.txt -d ./packages

# 将整个项目目录（含 packages 文件夹）拷贝到内网机器

# 在内网机器上
python3 -m venv venv
source venv/bin/activate   # Linux
# 或 venv\Scripts\activate.bat  # Windows

pip install --no-index --find-links=./packages -r requirements.txt
python app.py
```

## 使用方法

### Web 界面

1. 启动服务后，浏览器访问 `http://localhost:5000`
2. 两种输入方式：
   - **粘贴文本**：将公文内容直接粘贴到文本框
   - **上传文件**：点击或拖拽上传 `.txt` / `.docx` 文件
3. 点击"开始校验"按钮
4. 查看检测结果：
   - **评分卡片**：总分和等级（A-E）
   - **统计面板**：错误/警告/建议数量
   - **详细列表**：每条问题的位置、类型、修改建议
   - **筛选功能**：按类别（错别字/格式）或严重程度筛选

### API 接口

#### 文本校验

```bash
curl -X POST http://localhost:5000/api/check-text \
  -H "Content-Type: application/json" \
  -d '{"text": "关于做好2025年工作的通知\n各有关单位:\n请按照要求贯策落实。"}'
```

#### 文件上传校验

```bash
curl -X POST http://localhost:5000/api/check \
  -F "file=@公文.docx"
```

#### 返回格式

```json
{
  "success": true,
  "typo_errors": [
    {
      "line": 3,
      "column": 8,
      "wrong": "贯策",
      "correct": "贯彻",
      "type": "common_error",
      "type_label": "常见错别字",
      "severity": "error",
      "context": "...照要求贯策落实...",
      "note": "\"贯策\"应写作\"贯彻\""
    }
  ],
  "format_issues": [...],
  "summary": {
    "score": 85.0,
    "grade": "B",
    "grade_text": "良好",
    "total_issues": 5
  }
}
```

## 局域网访问

服务默认监听 `0.0.0.0:5000`，局域网内其他电脑可通过服务器 IP 访问：

```
http://服务器IP地址:5000
```

如需修改端口，编辑 `config.py` 中的 `PORT` 值。

## 自定义词典

可根据实际需要扩展词典文件（位于 `dictionaries/` 目录）：

| 文件 | 说明 | 格式 |
|------|------|------|
| `gov_terms.txt` | 政务术语词库 | 每行一个词 |
| `confusables.txt` | 易混淆字对照 | `错误词\|正确词\|说明` |
| `common_errors.txt` | 常见错误词组 | `错误\|正确` |

修改词典后重启服务即可生效。

## 项目结构

```
document-validator/
├── app.py                  # Flask 主应用
├── config.py               # 配置文件
├── requirements.txt        # Python 依赖
├── start.bat               # Windows 启动脚本
├── start.sh                # Linux 启动脚本
├── checker/
│   ├── __init__.py
│   ├── typo_checker.py     # 错别字检测模块
│   └── format_checker.py   # 格式检测模块
├── dictionaries/
│   ├── gov_terms.txt       # 政务术语词库
│   ├── confusables.txt     # 易混淆字对照表
│   └── common_errors.txt   # 常见错误词组表
├── templates/
│   └── index.html          # Web 页面
└── static/
    ├── css/style.css       # 样式
    └── js/main.js          # 前端交互
```

## 常见问题

**Q: pycorrector 安装失败怎么办？**
A: pycorrector 为可选组件，安装失败不影响核心功能（词典检测和格式检测正常工作）。如需使用，可单独安装：`pip install pycorrector`。

**Q: 如何修改监听端口？**
A: 编辑 `config.py`，修改 `PORT = 5000` 为所需端口。

**Q: 支持 .doc 格式吗？**
A: 目前仅支持 .docx 格式。.doc 为旧版 Office 格式，建议先用 WPS/Office 另存为 .docx。

**Q: 如何添加自定义敏感词检测？**
A: 在 `dictionaries/` 下新增词典文件，并在 `checker/typo_checker.py` 中加载即可。

## 技术栈

- **后端**: Python 3 + Flask
- **前端**: 原生 HTML/CSS/JS（无框架依赖）
- **分词**: jieba（离线）
- **纠错**: pycorrector（离线，可选）
- **文档解析**: python-docx
