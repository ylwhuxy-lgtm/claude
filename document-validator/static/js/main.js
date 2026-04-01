/**
 * 公文校验工具 - 前端交互逻辑
 */

document.addEventListener('DOMContentLoaded', function () {
    // ========== DOM 元素 ==========
    const tabBtns = document.querySelectorAll('.tab-btn');
    const textInput = document.getElementById('text-input');
    const charCount = document.getElementById('char-count');
    const fileInput = document.getElementById('file-input');
    const uploadArea = document.getElementById('upload-area');
    const fileInfo = document.getElementById('file-info');
    const fileName = document.getElementById('file-name');
    const btnRemoveFile = document.getElementById('btn-remove-file');
    const btnCheck = document.getElementById('btn-check');
    const emptyState = document.getElementById('empty-state');
    const resultOverview = document.getElementById('result-overview');
    const resultFilters = document.getElementById('result-filters');
    const resultList = document.getElementById('result-list');
    const filterBtns = document.querySelectorAll('.filter-btn');

    let currentFile = null;
    let currentResults = null;
    let currentTab = 'text';

    // ========== Tab 切换 ==========
    tabBtns.forEach(btn => {
        btn.addEventListener('click', function () {
            const tab = this.dataset.tab;
            currentTab = tab;
            tabBtns.forEach(b => b.classList.remove('active'));
            this.classList.add('active');
            document.querySelectorAll('.tab-content').forEach(tc => tc.classList.remove('active'));
            document.getElementById('tab-' + tab).classList.add('active');
        });
    });

    // ========== 字数统计 ==========
    textInput.addEventListener('input', function () {
        const len = this.value.length;
        charCount.textContent = len + ' 字';
    });

    // ========== 文件上传 ==========
    uploadArea.addEventListener('click', () => fileInput.click());

    uploadArea.addEventListener('dragover', function (e) {
        e.preventDefault();
        this.classList.add('dragover');
    });

    uploadArea.addEventListener('dragleave', function () {
        this.classList.remove('dragover');
    });

    uploadArea.addEventListener('drop', function (e) {
        e.preventDefault();
        this.classList.remove('dragover');
        const files = e.dataTransfer.files;
        if (files.length > 0) {
            handleFile(files[0]);
        }
    });

    fileInput.addEventListener('change', function () {
        if (this.files.length > 0) {
            handleFile(this.files[0]);
        }
    });

    btnRemoveFile.addEventListener('click', function () {
        currentFile = null;
        fileInput.value = '';
        fileInfo.style.display = 'none';
        uploadArea.style.display = 'flex';
    });

    function handleFile(file) {
        const ext = file.name.split('.').pop().toLowerCase();
        if (!['txt', 'docx'].includes(ext)) {
            alert('不支持的文件类型，请上传 .txt 或 .docx 文件');
            return;
        }
        if (file.size > 16 * 1024 * 1024) {
            alert('文件大小超过 16MB 限制');
            return;
        }
        currentFile = file;
        fileName.textContent = file.name + ' (' + formatSize(file.size) + ')';
        fileInfo.style.display = 'flex';
        uploadArea.style.display = 'none';
    }

    function formatSize(bytes) {
        if (bytes < 1024) return bytes + ' B';
        if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
        return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
    }

    // ========== 校验 ==========
    btnCheck.addEventListener('click', function () {
        if (currentTab === 'text') {
            checkText();
        } else {
            checkFile();
        }
    });

    function checkText() {
        const text = textInput.value.trim();
        if (!text) {
            alert('请输入待校验的公文内容');
            return;
        }
        setLoading(true);

        fetch('/api/check-text', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ text: text })
        })
            .then(res => res.json())
            .then(data => {
                setLoading(false);
                if (data.success) {
                    displayResults(data);
                } else {
                    alert(data.error || '校验失败');
                }
            })
            .catch(err => {
                setLoading(false);
                alert('请求失败：' + err.message);
            });
    }

    function checkFile() {
        if (!currentFile) {
            alert('请先选择文件');
            return;
        }
        setLoading(true);

        const formData = new FormData();
        formData.append('file', currentFile);

        fetch('/api/check', {
            method: 'POST',
            body: formData
        })
            .then(res => res.json())
            .then(data => {
                setLoading(false);
                if (data.success) {
                    displayResults(data);
                } else {
                    alert(data.error || '校验失败');
                }
            })
            .catch(err => {
                setLoading(false);
                alert('请求失败：' + err.message);
            });
    }

    function setLoading(loading) {
        btnCheck.disabled = loading;
        btnCheck.querySelector('.btn-text').style.display = loading ? 'none' : 'inline';
        btnCheck.querySelector('.btn-loading').style.display = loading ? 'inline-flex' : 'none';
    }

    // ========== 显示结果 ==========
    function displayResults(data) {
        currentResults = data;
        emptyState.style.display = 'none';
        resultOverview.style.display = 'flex';
        resultFilters.style.display = 'flex';

        const summary = data.summary;

        // 更新评分
        const scoreValue = document.getElementById('score-value');
        const scoreCircle = document.getElementById('score-circle');
        const scoreGrade = document.getElementById('score-grade');

        scoreValue.textContent = summary.score;
        scoreGrade.textContent = summary.grade + ' - ' + summary.grade_text;

        // 设置评分颜色
        scoreCircle.className = 'score-circle grade-' + summary.grade.toLowerCase();

        // 更新统计
        document.getElementById('stat-errors').textContent = summary.errors;
        document.getElementById('stat-warnings').textContent = summary.warnings;
        document.getElementById('stat-info').textContent = summary.info;
        document.getElementById('stat-total').textContent = summary.total_issues;

        // 渲染列表
        renderResults('all');
    }

    // ========== 筛选 ==========
    filterBtns.forEach(btn => {
        btn.addEventListener('click', function () {
            filterBtns.forEach(b => b.classList.remove('active'));
            this.classList.add('active');
            renderResults(this.dataset.filter);
        });
    });

    function renderResults(filter) {
        if (!currentResults) return;

        const typoErrors = currentResults.typo_errors || [];
        const formatIssues = currentResults.format_issues || [];
        const layoutIssues = currentResults.layout_issues || [];

        let items = [];

        // 转换错别字为统一格式
        typoErrors.forEach(e => {
            items.push({
                category: 'typo',
                severity: e.severity,
                line: e.line,
                column: e.column,
                typeLabel: e.type_label,
                wrong: e.wrong,
                correct: e.correct,
                context: e.context,
                note: e.note,
                message: null
            });
        });

        // 转换格式问题
        formatIssues.forEach(f => {
            items.push({
                category: 'format',
                severity: f.severity,
                line: f.line,
                typeLabel: f.category_label,
                wrong: null,
                correct: null,
                context: null,
                note: null,
                message: f.message
            });
        });

        // 转换排版问题
        layoutIssues.forEach(l => {
            items.push({
                category: 'format',
                severity: l.severity,
                line: l.line,
                typeLabel: l.category_label,
                wrong: null,
                correct: null,
                context: null,
                note: null,
                message: l.message
            });
        });

        // 筛选
        if (filter === 'typo') {
            items = items.filter(i => i.category === 'typo');
        } else if (filter === 'format') {
            items = items.filter(i => i.category === 'format');
        } else if (filter === 'error') {
            items = items.filter(i => i.severity === 'error');
        } else if (filter === 'warning') {
            items = items.filter(i => i.severity === 'warning');
        }

        // 排序：error > warning > info，再按行号
        const severityOrder = { error: 0, warning: 1, info: 2 };
        items.sort((a, b) => {
            const sa = severityOrder[a.severity] || 2;
            const sb = severityOrder[b.severity] || 2;
            if (sa !== sb) return sa - sb;
            return (a.line || 0) - (b.line || 0);
        });

        // 渲染
        resultList.innerHTML = '';

        if (items.length === 0) {
            resultList.innerHTML = `
                <div class="no-issues">
                    <div class="no-issues-icon">&#9989;</div>
                    <p>${filter === 'all' ? '未发现问题，公文质量良好！' : '该类别下无问题'}</p>
                </div>
            `;
            return;
        }

        items.forEach((item, index) => {
            const div = document.createElement('div');
            div.className = 'result-item severity-' + item.severity;
            div.style.animationDelay = (index * 0.03) + 's';

            const severityText = { error: '错误', warning: '警告', info: '建议' };

            let bodyHTML = '';
            if (item.wrong && item.correct) {
                bodyHTML = `
                    <span class="wrong-text">${escapeHtml(item.wrong)}</span>
                    <span class="arrow-icon">&rarr;</span>
                    <span class="correct-text">${escapeHtml(item.correct)}</span>
                `;
                if (item.context) {
                    bodyHTML += `<span class="context-text">${escapeHtml(item.context)}</span>`;
                }
                if (item.note) {
                    bodyHTML += `<span class="note-text">${escapeHtml(item.note)}</span>`;
                }
            } else if (item.message) {
                bodyHTML = `<span>${escapeHtml(item.message)}</span>`;
            }

            div.innerHTML = `
                <div class="result-item-header">
                    <span class="severity-badge ${item.severity}">${severityText[item.severity]}</span>
                    <span class="type-badge">${escapeHtml(item.typeLabel)}</span>
                    ${item.line ? `<span class="line-info">第 ${item.line} 行${item.column ? '，第 ' + item.column + ' 列' : ''}</span>` : ''}
                </div>
                <div class="result-item-body">${bodyHTML}</div>
            `;

            resultList.appendChild(div);
        });
    }

    function escapeHtml(str) {
        if (!str) return '';
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }
});
