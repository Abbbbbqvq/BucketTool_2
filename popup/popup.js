// popup 弹窗脚本
// 检测历史存储在 chrome.storage.local，格式为 [{id, url, type, vendor, time, request, response}]

const historyList = document.getElementById('history-list');
const noHistory = document.getElementById('no-history');
const clearBtn = document.getElementById('clear-history');
const modal = document.getElementById('modal');
const modalTitle = document.getElementById('modal-title');
const modalBody = document.getElementById('modal-body');
const modalClose = document.getElementById('modal-close');
const logPanel = document.getElementById('log-panel');
const clearLogsBtn = document.getElementById('clear-logs');

// 选项卡切换逻辑
const tabBtns = document.querySelectorAll('.tab-btn');
const tabContents = document.querySelectorAll('.tab-content');

tabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
        const targetTab = btn.dataset.tab;
        
        // 更新按钮状态
        tabBtns.forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        
        // 更新内容显示
        tabContents.forEach(c => c.classList.remove('active'));
        document.getElementById(`tab-${targetTab}`).classList.add('active');
    });
});

// 日志管理
let logMessages = [];
const MAX_LOGS = 500;

function appendLog(text) {
    if (!logPanel) return;
    const line = document.createElement('div');
    line.textContent = text;
    logPanel.appendChild(line);
    logPanel.scrollTop = logPanel.scrollHeight;
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message && message.type === 'log') {
        const panel = document.getElementById('log-panel');
        if (panel.textContent === '暂无日志') {
            panel.textContent = '';
        }
        logMessages.push(message.text);
        if (logMessages.length > MAX_LOGS) {
            logMessages.shift();
            // 移除 DOM 中最早的节点
            if (panel && panel.firstChild) {
                panel.removeChild(panel.firstChild);
            }
        }
        appendLog(message.text);
    }
    if (message && message.type === 'new-vul') {
        addVulToHistory(message.vul);
    }
});

// 处理清除日志按钮点击
if (clearLogsBtn) {
    clearLogsBtn.addEventListener('click', () => {
        // 1. 清空 UI
        logPanel.textContent = '暂无日志';
        logMessages = [];
        
        // 2. 通知 background 清除存储
        chrome.runtime.sendMessage({ type: 'clear-logs' });
    });
}

// 示例数据
const demoHistory = [
    // {
    //     id: 1,
    //     url: "https://oss-example-bucket.oss-cn-beijing.aliyuncs.com/secret.txt",
    //     type: "未授权读取",
    //     vendor: "阿里云",
    //     time: 1718000000000,
    //     request: `GET /secret.txt HTTP/1.1\nHost: oss-example-bucket.oss-cn-beijing.aliyuncs.com\nUser-Agent: Mozilla/5.0 ...`,
    //     response: `HTTP/1.1 200 OK\nContent-Type: text/plain\n\nsecret=flag{example}`
    // },
    // {
    //     id: 2,
    //     url: "https://mybucket-1250000000.cos.ap-shanghai.myqcloud.com/test.jpg",
    //     type: "ACL过宽",
    //     vendor: "腾讯云",
    //     time: 1718003600000,
    //     request: `GET /test.jpg HTTP/1.1\nHost: mybucket-1250000000.cos.ap-shanghai.myqcloud.com\nUser-Agent: Mozilla/5.0 ...`,
    //     response: `HTTP/1.1 200 OK\nContent-Type: image/jpeg\n\xff\xd8\xff...`
    // },
    // {
    //     id: 3,
    //     url: "https://obs-bucket.obs.cn-north-4.myhuaweicloud.com/config.json",
    //     type: "未授权写入",
    //     vendor: "华为云",
    //     time: 1718007200000,
    //     request: `PUT /config.json HTTP/1.1\nHost: obs-bucket.obs.cn-north-4.myhuaweicloud.com\nContent-Type: application/json\n\n{"test":true}`,
    //     response: `HTTP/1.1 204 No Content\n\n`
    // }
];

// 加载历史
function loadHistory() {
    chrome.storage.local.get(['bucketVulHistory'], (result) => {
        let history = result.bucketVulHistory || [];
        renderHistory(history);
    });
}

// 动态添加漏洞到历史列表顶部
function addVulToHistory(vul) {
    if (!vul) return;
    noHistory.style.display = 'none';
    
    const li = document.createElement('li');
    li.className = 'history-item vul-entry';
    // 存储完整的请求响应信息用于展示
    li.dataset.request = vul.request || '';
    li.dataset.response = vul.response || '';
    
    const seqSpan = document.createElement('span');
    seqSpan.className = 'seq';
    seqSpan.textContent = '1';
    
    const hostSpan = document.createElement('span');
    hostSpan.className = 'host';
    hostSpan.title = getHost(vul);
    hostSpan.textContent = getHost(vul);
    
    const typeSpan = document.createElement('span');
    typeSpan.className = 'type';
    typeSpan.textContent = vul.type || '未知类型';
    
    const vendorSpan = document.createElement('span');
    vendorSpan.className = 'vendor';
    vendorSpan.textContent = vul.vendor || '未知厂商';
    
    const timeSpan = document.createElement('span');
    timeSpan.className = 'time';
    timeSpan.textContent = formatTime(vul.time);
    
    const sourceTag = document.createElement('span');
    sourceTag.className = 'source-tag';
    sourceTag.style.cssText = vul.source === '主动' ? 'background:#eaf6ff;color:#2d7be5;' : 'background:#fbeee6;color:#c0392b;';
    sourceTag.textContent = vul.source || '未知';
    
    const detailBtn = document.createElement('button');
    detailBtn.className = 'reqresp-btn';
    detailBtn.textContent = '展示细节';
    
    const deleteBtn = document.createElement('button');
    deleteBtn.className = 'delete-btn';
    deleteBtn.title = '删除';
    deleteBtn.dataset.id = vul.id;
    deleteBtn.textContent = '✕';
    
    li.appendChild(seqSpan);
    li.appendChild(hostSpan);
    li.appendChild(typeSpan);
    li.appendChild(vendorSpan);
    li.appendChild(timeSpan);
    li.appendChild(sourceTag);
    li.appendChild(detailBtn);
    li.appendChild(deleteBtn);
    
    // 创建详情区域
    const detailDiv = document.createElement('div');
    detailDiv.className = 'vul-detail';
    
    // 格式化显示请求和响应
    const reqContent = vul.request || '旧版本记录，无详细请求信息';
    const respContent = vul.response || '旧版本记录，无详细响应信息';
    
    detailDiv.innerHTML = `
        <div class="probe-url">探测 URL: <span>${escapeHtml(vul.url)}</span></div>
        <div class="detail-section-container">
            <div class="detail-section">
                <div class="section-header">
                    <strong>HTTP 请求包:</strong>
                    <button class="copy-btn" data-type="request">复制</button>
                </div>
                <pre>${escapeHtml(reqContent)}</pre>
            </div>
            <div class="detail-section">
                <div class="section-header">
                    <strong>HTTP 响应包:</strong>
                    <button class="copy-btn" data-type="response">复制</button>
                </div>
                <pre>${escapeHtml(respContent)}</pre>
            </div>
        </div>
    `;
    
    // 插入到列表最前面
    if (historyList.firstChild) {
        historyList.insertBefore(li, historyList.firstChild);
        historyList.insertBefore(detailDiv, historyList.firstChild);
    } else {
        historyList.appendChild(li);
        historyList.appendChild(detailDiv);
    }
    
    // 更新序号
    updateSeqNumbers();
}

// 渲染历史
function renderHistory(history) {
    currentHistory = history; // 渲染时同步缓存
    historyList.innerHTML = '';
    if (!history.length) {
        noHistory.style.display = 'block';
        // 没有漏洞时移除红点
        if (chrome && chrome.action && chrome.action.setBadgeText) {
            chrome.action.setBadgeText({ text: '' });
        }
        return;
    }
    noHistory.style.display = 'none';
    // 有漏洞时不再设置红点，由检测逻辑控制
    history.forEach((item, idx) => {
        const li = document.createElement('li');
        li.className = 'history-item vul-entry';
        // 存储完整的请求响应信息用于展示
        li.dataset.request = item.request || '';
        li.dataset.response = item.response || '';
        
        const seqSpan = document.createElement('span');
        seqSpan.className = 'seq';
        seqSpan.textContent = idx + 1;
        
        const hostSpan = document.createElement('span');
        hostSpan.className = 'host';
        hostSpan.title = getHost(item);
        hostSpan.textContent = getHost(item);
        
        const typeSpan = document.createElement('span');
        typeSpan.className = 'type';
        typeSpan.textContent = item.type || '未知类型';
        
        const vendorSpan = document.createElement('span');
        vendorSpan.className = 'vendor';
        vendorSpan.textContent = item.vendor || '未知厂商';
        
        const timeSpan = document.createElement('span');
        timeSpan.className = 'time';
        timeSpan.textContent = formatTime(item.time);
        
        const sourceTag = document.createElement('span');
        sourceTag.className = 'source-tag';
        sourceTag.style.cssText = item.source === '主动' ? 'background:#eaf6ff;color:#2d7be5;' : 'background:#fbeee6;color:#c0392b;';
        sourceTag.textContent = item.source || '未知';
        
        const detailBtn = document.createElement('button');
        detailBtn.className = 'reqresp-btn';
        detailBtn.textContent = '展示细节';
        
        const deleteBtn = document.createElement('button');
        deleteBtn.className = 'delete-btn';
        deleteBtn.title = '删除';
        deleteBtn.dataset.id = item.id;
        deleteBtn.textContent = '✕';
        
        li.appendChild(seqSpan);
        li.appendChild(hostSpan);
        li.appendChild(typeSpan);
        li.appendChild(vendorSpan);
        li.appendChild(timeSpan);
        li.appendChild(sourceTag);
        li.appendChild(detailBtn);
        li.appendChild(deleteBtn);
        
        const detailDiv = document.createElement('div');
        detailDiv.className = 'vul-detail';
        
        // 格式化显示请求和响应
        const reqContent = item.request || '旧版本记录，无详细请求信息';
        const respContent = item.response || '旧版本记录，无详细响应信息';
        
    detailDiv.innerHTML = `
        <div class="probe-url">探测 URL: <span>${escapeHtml(item.url)}</span></div>
        <div class="detail-section-container">
            <div class="detail-section">
                <div class="section-header">
                    <strong>HTTP 请求包:</strong>
                    <button class="copy-btn" data-type="request">复制</button>
                </div>
                <pre>${escapeHtml(reqContent)}</pre>
            </div>
            <div class="detail-section">
                <div class="section-header">
                    <strong>HTTP 响应包:</strong>
                    <button class="copy-btn" data-type="response">复制</button>
                </div>
                <pre>${escapeHtml(respContent)}</pre>
            </div>
        </div>
    `;
        
        historyList.appendChild(li);
        historyList.appendChild(detailDiv);
    });
}

function updateSeqNumbers() {
    const items = historyList.querySelectorAll('.history-item');
    items.forEach((item, index) => {
        item.querySelector('.seq').textContent = index + 1;
    });
}

function updateReqRespScroll() {
    const expanded = document.querySelectorAll('.reqresp-row');
    const list = document.getElementById('history-list');
    if (expanded.length >= 3) {
        list.classList.add('show-scroll');
    } else {
        list.classList.remove('show-scroll');
    }
}

// 修改展开/收起逻辑，插入/移除时都调用 updateReqRespScroll
historyList.addEventListener('click', (e) => {
    // 处理删除按钮点击
    if (e.target.classList.contains('delete-btn')) {
        const id = e.target.getAttribute('data-id');
        chrome.storage.local.get(['bucketVulHistory'], (result) => {
            let history = result.bucketVulHistory || [];
            history = history.filter(item => String(item.id) !== String(id));
            chrome.storage.local.set({ bucketVulHistory: history }, loadHistory);
        });
        return;
    }

    // 处理展示细节按钮点击（切换显示/隐藏）
    if (e.target.classList.contains('reqresp-btn')) {
        const vulEntry = e.target.closest('.vul-entry');
        if (!vulEntry) return;
        
        // 找到紧跟在条目后面的详情 div
        const detailDiv = vulEntry.nextElementSibling;
        if (detailDiv && detailDiv.classList.contains('vul-detail')) {
            const isVisible = detailDiv.style.display === 'block';
            detailDiv.style.display = isVisible ? 'none' : 'block';
            e.target.textContent = isVisible ? '展示细节' : '隐藏细节';
        }
        return;
    }

    // 处理复制按钮点击
    if (e.target.classList.contains('copy-btn')) {
        const section = e.target.closest('.detail-section');
        const pre = section.querySelector('pre');
        const text = pre.textContent;
        const btn = e.target;
        
        navigator.clipboard.writeText(text).then(() => {
            btn.textContent = '已复制!';
            setTimeout(() => { btn.textContent = '复制'; }, 1500);
        }).catch(err => {
            console.error('Copy failed:', err);
        });
        return;
    }
});

function getHistoryByIdxAsync(idx, field, cb) {
    chrome.storage.local.get(['bucketVulHistory'], (result) => {
        let history = result.bucketVulHistory;
        // 如果没有数据，优先用 demoHistory
        if (!history || !history.length) history = demoHistory;
        const val = history[idx] && history[idx][field] ? history[idx][field] : '(无内容)';
        cb(val);
    });
}

function getHost(item) {
    try {
        const host = new URL(item.url).host;
        // 去掉云厂商后缀
        return host
            .replace(/\.oss(-[a-z0-9-]+)?\.aliyuncs\.com$/, '')
            .replace(/\.cos(-[a-z0-9-]+)?\.myqcloud\.com$/, '')
            .replace(/\.obs\.[a-z0-9-]+\.myhuaweicloud\.com$/, '');
    } catch {
        return item.url || '';
    }
}

// 弹窗相关
function showModal(title, body) {
    modalTitle.textContent = title;
    modalBody.textContent = body;
    modal.style.display = 'flex';
    // 添加复制按钮
    addCopyButton();
}

function addCopyButton() {
    let oldBtn = document.getElementById('copy-btn');
    if (oldBtn) oldBtn.remove();
    const btn = document.createElement('button');
    btn.id = 'copy-btn';
    btn.textContent = '复制';
    btn.style = 'position:absolute;right:60px;top:10px;padding:2px 10px;font-size:13px;cursor:pointer;';
    btn.onclick = function () {
        navigator.clipboard.writeText(modalBody.textContent).then(() => {
            btn.textContent = '已复制!';
            setTimeout(() => { btn.textContent = '复制'; }, 1200);
        });
    };
    modal.querySelector('.modal-content').appendChild(btn);
}
modalClose.onclick = function () {
    modal.style.display = 'none';
};
window.onclick = function (event) {
    if (event.target === modal) {
        modal.style.display = 'none';
    }
};

// 清空全部
clearBtn.addEventListener('click', () => {
    if (confirm('确定要清空所有检测历史吗？')) {
        chrome.storage.local.set({ bucketVulHistory: [] }, loadHistory);
    }
});

// 工具函数
function formatTime(ts) {
    const d = new Date(ts);
    return d.toLocaleString();
}
function escapeHtml(str) {
    return String(str).replace(/[&<>"']|'/g, s => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', '\'': '&#39;' }[s]));
}
function ellipsisUrl(url) {
    if (!url) return '';
    const max = 22;
    if (url.length <= max) return escapeHtml(url);
    return escapeHtml(url.slice(0, max - 3)) + '...';
}

// 初始化
function clearBadge() {
    if (chrome && chrome.action && chrome.action.setBadgeText) {
        chrome.action.setBadgeText({ text: '' });
    }
}

window.addEventListener('DOMContentLoaded', () => {
    // 直接清除 badge，兼容所有场景
    if (chrome && chrome.action && chrome.action.setBadgeText) {
        chrome.action.setBadgeText({ text: '' });
    }
    loadHistory();
    
    // 初始化日志面板
    chrome.storage.local.get(['bucketLogCache'], (res) => {
        const logs = res.bucketLogCache || [];
        if (logs.length === 0) {
            logPanel.textContent = '暂无日志';
        } else {
            logPanel.textContent = ''; 
            logs.forEach(log => {
                logPanel.appendChild(document.createTextNode(log.text + '\n'));
            });
            logPanel.scrollTop = logPanel.scrollHeight;
        }
    });

    // 初始化黑名单面板
    loadBlocklist();

    // 仍保留向 background 发送 clear-badge 消息，兼容 service worker
    if (chrome && chrome.runtime && chrome.runtime.sendMessage) {
        chrome.runtime.sendMessage({ type: 'clear-badge' });
    }
}); 

// 黑名单管理逻辑
const blocklistItems = document.getElementById('blocklist-items');
const noBlocklist = document.getElementById('no-blocklist');
const addBlBtn = document.getElementById('add-blocklist-btn');
const blInput = document.getElementById('blocklist-input');

function loadBlocklist() {
    chrome.storage.local.get(['bucketBlocklist'], (res) => {
        const list = res.bucketBlocklist || [];
        renderBlocklist(list);
    });
}

function renderBlocklist(list) {
    blocklistItems.innerHTML = '';
    if (!list.length) {
        noBlocklist.style.display = 'block';
        return;
    }
    noBlocklist.style.display = 'none';
    list.forEach(item => {
        const li = document.createElement('li');
        li.className = 'blocklist-item';
        li.innerHTML = `
            <span>${escapeHtml(item.pattern)}</span>
            <button class="delete-bl-btn" data-pattern="${escapeHtml(item.pattern)}">✕</button>
        `;
        blocklistItems.appendChild(li);
    });
}

addBlBtn.addEventListener('click', () => {
    const pattern = blInput.value.trim();
    if (!pattern) return;
    chrome.runtime.sendMessage({ type: 'add-blocklist-item', pattern }, () => {
        blInput.value = '';
        loadBlocklist();
    });
});

blocklistItems.addEventListener('click', (e) => {
    if (e.target.classList.contains('delete-bl-btn')) {
        const pattern = e.target.dataset.pattern;
        chrome.runtime.sendMessage({ type: 'remove-blocklist-item', pattern }, () => {
            loadBlocklist();
        });
    }
}); 