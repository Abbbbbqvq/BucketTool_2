// 浏览器扩展后台脚本基础模板
// 后续可在此添加事件监听、消息通信等逻辑 
import { detectVendor, detectBucketVul, detectBucketOpen } from '../lib/index.js';

// 漏洞类型常量
const TYPE = {
    TRAVERSABLE: '存储桶可遍历',
    UPLOAD: 'put文件上传',
    ACL_READ: 'ACL可读',
    ACL_WRITE: 'ACL可写',
    POLICY_WRITE: 'policy可写',
};

// TODO: 在此处添加全局已探测URL集合，用于去重
// const detectedUrls = new Set();
const visitedPathSet = new Set();
const requestHeadersCache = new Map();

// 请求队列与速率控制
let taskQueue = [];
let isProcessing = false;
let detectionEnabled = true; // 全局检测开关标志

async function dynamicDelay(lastDuration) {
    const delay = lastDuration ? Math.min(Math.max(lastDuration * 2, 200), 3000) : 200;
    return new Promise(r => setTimeout(r, delay));
}

async function processQueue() {
    if (isProcessing || taskQueue.length === 0) return;
    isProcessing = true;

    while (taskQueue.length > 0) {
        // 如果检测被关闭，清空队列并退出
        if (!detectionEnabled) {
            addLog('[系统] 检测已关闭，清空探测队列');
            taskQueue = [];
            break;
        }

        const { url, headers } = taskQueue.shift();
        const start = Date.now();
        
        try {
            addLog(`[探测] ${url}`);
            const result = await detectBucketOpen(url, headers);
            const duration = Date.now() - start;

            if (result.isPublic) {
                addLog(`[发现] ${url} 公开可访问 (${result.vendor})`);
                // ... (保留原有的漏洞存储逻辑)
                chrome.storage.local.get(['bucketVulHistory'], (res) => {
                    let history = res.bucketVulHistory || [];
                    const existingIndex = history.findIndex(item => item.url === url && item.vendor === result.vendor);
                    const newItem = {
                        id: Date.now() + Math.random(),
                        url: url,
                        type: '存储桶可遍历',
                        vendor: result.vendor,
                        time: Date.now(),
                        request: result.request ? formatRequest(result.request.url, result.request.method, result.request.headers, result.request.body) : '',
                        response: result.response ? formatResponse(result.response.status, result.response.statusText, result.response.headers, result.response.body) : '',
                        details: result.details,
                        source: '被动'
                    };
                    if (existingIndex !== -1) {
                        history[existingIndex] = newItem;
                    } else {
                        history.unshift(newItem);
                    }
                    chrome.storage.local.set({ bucketVulHistory: history }, () => {
                        if (chrome && chrome.action && chrome.action.setBadgeText) {
                            chrome.action.setBadgeText({ text: '●' });
                            chrome.action.setBadgeBackgroundColor && chrome.action.setBadgeBackgroundColor({ color: '#e74c3c' });
                        }
                        chrome.runtime.sendMessage({ type: 'new-vul', vul: newItem }).catch(() => {});
                    });
                });
            } else {
                addLog(`[安全] ${url} 未公开 - ${result.details}`);
            }
            
            await dynamicDelay(duration);
        } catch (e) {
            addLog(`[错误] ${url} - 检测失败: ${e.message}`);
            await dynamicDelay(1000); // 出错后也进行延迟
        }
    }
    isProcessing = false;
}

function enqueueTask(url, headers) {
    taskQueue.push({ url, headers });
    processQueue();
}

// 缓存真实请求头（剔除敏感信息）
chrome.webRequest.onSendHeaders.addListener(
    (details) => {
        if (details.tabId > 0 && details.url.startsWith('http')) {
            const headers = {};
            details.requestHeaders.forEach(h => {
                const name = h.name.toLowerCase();
                if (!['cookie', 'authorization', 'proxy-authorization'].includes(name)) {
                    headers[h.name] = h.value;
                }
            });
            // 只保留最近的 500 个记录以防内存溢出
            if (requestHeadersCache.size > 500) {
                const firstKey = requestHeadersCache.keys().next().value;
                requestHeadersCache.delete(firstKey);
            }
            requestHeadersCache.set(details.url, headers);
        }
    },
    { urls: ["<all_urls>"] },
    ['requestHeaders']
);

let logCache = [];
const MAX_LOG = 500;
let blocklist = []; // { pattern, regex }

// 恢复日志缓存和黑名单
chrome.storage.local.get(['bucketLogCache', 'bucketBlocklist'], (res) => {
    if (res.bucketLogCache && Array.isArray(res.bucketLogCache)) {
        logCache = res.bucketLogCache.slice(-MAX_LOG);
    }
    if (res.bucketBlocklist && Array.isArray(res.bucketBlocklist)) {
        blocklist = res.bucketBlocklist;
    }
});

function patternToRegex(pattern) {
    try {
        // 支持用户输入原生正则，如 /example\.com/
        if (pattern.startsWith('/') && pattern.endsWith('/')) {
            return pattern.slice(1, -1);
        }
        // 转换通配符模式
        let escaped = pattern.replace(/\./g, '\\.').replace(/\*/g, '[^.]+');
        return `^${escaped}$`;
    } catch (e) {
        console.error('Invalid blocklist pattern:', pattern);
        return null;
    }
}

function isBlocked(hostname) {
    return blocklist.some(item => {
        try {
            return new RegExp(item.regex).test(hostname);
        } catch (e) {
            return false;
        }
    });
}

function addLog(text) {
    const entry = { text, timestamp: Date.now() };
    logCache.push(entry);
    if (logCache.length > MAX_LOG) {
        logCache.shift();
    }
    chrome.storage.local.set({ bucketLogCache: logCache });
    chrome.runtime.sendMessage({ type: 'log', text }).catch(() => {});
}

function getHostFromUrl(url) {
    try {
        // 只返回完整 host，不做后缀归一化，保证不同 bucket 独立
        return new URL(url).host;
    } catch {
        return url;
    }
}

function matchBlacklistHost(host, list) {
    if (!Array.isArray(list)) return false;
    const h = String(host || '').toLowerCase();
    return list.some(item => {
        const e = String(item || '').trim().toLowerCase();
        if (!e) return false;
        if (e.startsWith('*.')) {
            return h.endsWith(e.slice(1));
        }
        return h === e || h.endsWith('.' + e);
    });
}

function formatRequest(url, method, headers, body) {
    const u = new URL(url);
    let req = `${method} ${u.pathname}${u.search} HTTP/1.1\r\n`;
    req += `Host: ${u.host}\r\n`;
    for (const [k, v] of Object.entries(headers || {})) {
        if (k.toLowerCase() !== 'host') req += `${k}: ${v}\r\n`;
    }
    req += '\r\n';
    if (body) req += body;
    return req;
}

function formatResponse(status, statusText, headers, body) {
    let resp = `HTTP/1.1 ${status} ${statusText}\r\n`;
    for (const [k, v] of Object.entries(headers || {})) {
        resp += `${k}: ${v}\r\n`;
    }
    resp += '\r\n';
    if (body) resp += body;
    return resp;
}

// 模拟检测逻辑，稍后完善
// async function detectBucketOpen(url) {
//     console.log('检测URL:', url);
//     return false;
// }

async function explodePathAndDetect(bucketBaseUrl, fullPath, originalHeaders) {
    try {
        let pathPart = '';
        try {
            const u = new URL(fullPath);
            pathPart = u.pathname;
        } catch (e) {
            return;
        }

        const segments = pathPart.split('/').filter(s => s.length > 0);
        
        // 生成探测列表
        const urlsToDetect = [];
        urlsToDetect.push(bucketBaseUrl + '/');
        
        let currentPath = '';
        const dirSegments = segments.length > 0 ? segments.slice(0, -1) : [];
        
        for (const seg of dirSegments) {
            currentPath += '/' + seg;
            urlsToDetect.push(bucketBaseUrl + currentPath + '/');
        }

        for (const url of urlsToDetect) {
            if (visitedPathSet.has(url)) continue;
            visitedPathSet.add(url);
            enqueueTask(url, originalHeaders);
        }
    } catch (e) {
        console.error('explodePathAndDetect error:', e);
    }
}

// 被动检测
chrome.webRequest.onCompleted.addListener(
    async (details) => {
        const url = details.url;
        // 跳过扩展自身和非 http/https 请求
        if (!url.startsWith('http://') && !url.startsWith('https://')) return;
        if (details.tabId < 0) return;
        
        // 如果检测未启用，直接跳过
        if (!detectionEnabled) return;
        
        chrome.storage.local.get(['bucketVulHistory', 'flagAcl', 'flagPolicy', 'detectBlacklist'], async (res) => {
            let history = res.bucketVulHistory || [];
            const aclFlag = res.flagAcl ?? true;
            const policyFlag = res.flagPolicy ?? true;
            const bl = res.detectBlacklist || [];
            const host = getHostFromUrl(url);
            if (matchBlacklistHost(host, bl) || isBlocked(host)) return;
            
            // 提取 bucketBaseUrl 和原始请求头
            let bucketBaseUrl = url;
            let originalHeaders = null;
            try {
                const u = new URL(url);
                bucketBaseUrl = u.origin;
                originalHeaders = requestHeadersCache.get(url);
            } catch (e) { /* ignore */ }

            await explodePathAndDetect(bucketBaseUrl, url, originalHeaders);
        });
    },
    { urls: ["<all_urls>"] }
);

// 注册右键菜单
chrome.runtime.onInstalled.addListener(() => {
    chrome.contextMenus.create({
        id: "bucketvul-detect",
        title: "用 BucketTool 检测",
        contexts: ["link", "selection", "page"]
    });
});

// 主动检测日志窗口管理
let logWindowId = null;
function openLogWindow() {
    return new Promise((resolve) => {
        if (logWindowId !== null) {
            // 如果窗口已打开，直接返回
            resolve(logWindowId);
            return;
        }
        chrome.windows.create({
            url: chrome.runtime.getURL('popup/log.html'),
            type: 'popup',
            width: 600,
            height: 500
        }, win => {
            logWindowId = win.id;
            resolve(win.id);
        });
    });
}
function sendLog(msg, result) {
    if (logWindowId) {
        chrome.windows.get(logWindowId, { populate: true }, win => {
            if (win && win.tabs && win.tabs.length > 0) {
                for (const tab of win.tabs) {
                    try {
                        chrome.tabs.sendMessage(tab.id, { type: 'bucketvul-log', msg, result });
                    } catch (e) {
                        // 忽略没有接收端的报错
                    }
                }
            }
        });
    }
}

// 监听日志窗口关闭，重置 logWindowId
chrome.windows.onRemoved.addListener(function (windowId) {
    if (windowId === logWindowId) {
        logWindowId = null;
    }
});

// 右键菜单点击事件只打开日志窗口
chrome.contextMenus.onClicked.addListener(async (info, tab) => {
    await openLogWindow();
    sendLog('请在日志窗口中点击“开始检测”发起检测');
});

// 新增：接收 log.html 发来的手动检测请求
chrome.runtime.onMessage.addListener(async (message, sender, sendResponse) => {
    if (message && message.type === 'manual-detect') {
        // 如果检测未启用，拒绝手动检测
        if (!detectionEnabled) {
            await openLogWindow();
            sendLog('检测已关闭，请先在 popup 中启用检测');
            return;
        }
        
        let targetUrl = message.vulUrl;
        if (!targetUrl) {
            sendLog('未输入URL，检测取消');
            return;
        }
        const host = getHostFromUrl(targetUrl);
        chrome.storage.local.get(['flagAcl', 'flagPolicy', 'bucketVulHistory', 'detectBlacklist'], async (res) => {
            const bl = res.detectBlacklist || [];
            if (matchBlacklistHost(host, bl)) {
                await openLogWindow();
                sendLog('目标在黑名单，跳过检测');
                return;
            }
            await openLogWindow();
            sendLog({ event: 'start', url: targetUrl });
            const aclFlag = res.flagAcl ?? true;
            const policyFlag = res.flagPolicy ?? true;
            sendLog({ event: 'params', acl: aclFlag, policy: policyFlag });
            try {
                const vendors = message.vendors && message.vendors.length ? message.vendors : ['aliyun', 'tencent', 'huawei'];
                let history = res.bucketVulHistory || [];
                for (const v of vendors) {
                    let vendorName =
                        v === 'aliyun' ? '阿里云' :
                            v === 'tencent' ? '腾讯云' :
                                v === 'huawei' ? '华为云' :
                                    (v === 'aws' || v === 'amazon' || v === 'amazons3' || v === 'amazonaws' || v === 'AmazonS3') ? 'AmazonS3' : v;
                    sendLog({ event: 'vendor-start', vendor: vendorName });
                    const resultArr = await detectBucketVul(targetUrl, { checkAcl: aclFlag, checkPolicy: policyFlag, vendors: [v] });
                    let foundAny = false;
                    for (const result of resultArr) {
                        let statusCode = undefined;
                        let path = '';
                        if (result.url) {
                            try { path = new URL(result.url).pathname + new URL(result.url).search; } catch { path = result.url; }
                        }
                        if (result.response) {
                            const m = result.response.match(/^HTTP\/1\.1 (\d{3})/);
                            if (m) statusCode = m[1];
                        }
                        sendLog({
                            event: 'detect',
                            vendor: result.vendor,
                            type: result.type,
                            path,
                            statusCode,
                            found: result.found,
                            detail: result.detail || '',
                            request: result.request,
                            response: result.response,
                            source: '主动'
                        });
                        if (result.found) {
                            foundAny = true;
                            const exists = history.some(item =>
                                getHostFromUrl(item.url) === getHostFromUrl(targetUrl) &&
                                item.type === result.type &&
                                item.vendor === result.vendor
                            );
                            if (!exists) {
                                const newItem = {
                                    id: Date.now() + Math.random(),
                                    url: targetUrl,
                                    type: result.type,
                                    vendor: result.vendor,
                                    time: Date.now(),
                                    request: result.request || '',
                                    response: result.response || '',
                                    source: '主动'
                                };
                                history.unshift(newItem);
                            }
                        }
                    }
                    if (!foundAny) {
                        sendLog({ event: 'vendor-result', vendor: vendorName, found: false });
                    }
                }
                chrome.storage.local.set({ bucketVulHistory: history }, () => {
                    if (history.length !== (res.bucketVulHistory || []).length && chrome && chrome.action && chrome.action.setBadgeText) {
                        chrome.action.setBadgeText({ text: '●' });
                        chrome.action.setBadgeBackgroundColor && chrome.action.setBadgeBackgroundColor({ color: '#e74c3c' });
                    }
                });
                sendLog({ event: 'finish' });
            } catch (e) {
                sendLog({ event: 'error', error: e + '' });
            }
        });
    }
    if (message && message.type === 'clear-badge') {
        if (chrome && chrome.action && chrome.action.setBadgeText) {
            chrome.action.setBadgeText({ text: '' });
        }
    }
    if (message && message.type === 'clear-logs') {
        // 清空内存中的日志缓存
        logCache = [];
        // 更新 storage
        chrome.storage.local.set({ bucketLogCache: [] }, () => {
            if (chrome.runtime.lastError) {
                console.warn('Failed to clear logs in storage:', chrome.runtime.lastError);
            }
        });
    }
    // 黑名单管理消息
    if (message && message.type === 'add-blocklist-item') {
        const pattern = message.pattern;
        const regex = patternToRegex(pattern);
        if (regex) {
            blocklist.push({ pattern, regex });
            chrome.storage.local.set({ bucketBlocklist: blocklist });
        }
    }
    if (message && message.type === 'remove-blocklist-item') {
        const pattern = message.pattern;
        blocklist = blocklist.filter(item => item.pattern !== pattern);
        chrome.storage.local.set({ bucketBlocklist: blocklist });
    }
    // 处理检测开关状态变更
    if (message && message.type === 'set-detection') {
        detectionEnabled = message.enabled;
        addLog(`[系统] 检测功能已${detectionEnabled ? '启用' : '关闭'}`);
        
        // 如果检测被关闭，清空队列
        if (!detectionEnabled && taskQueue.length > 0) {
            addLog(`[系统] 清空 ${taskQueue.length} 个待探测任务`);
            taskQueue = [];
        }
    }
});
