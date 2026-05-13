// lib/index.js
// 存储桶检测主入口，自动判断厂商并分发到对应检测逻辑
import { checkAliyun } from './aliyun.js';
import { checkTencent } from './tencent.js';
import { checkHuawei } from './huawei.js';
import { checkAWS } from './aws.js';
import BosDetector from '../src/detectors/bos.js';
import KodoDetector from '../src/detectors/kodo.js';
import JdCloudDetector from '../src/detectors/jdcloud.js';
import UCloudDetector from '../src/detectors/ucloud.js';
import Ks3Detector from '../src/detectors/ks3.js';
import QingStorDetector from '../src/detectors/qingstor.js';
import TyyunDetector from '../src/detectors/tyyun.js';
import EyunDetector from '../src/detectors/eyun.js';
import GcsDetector from '../src/detectors/gcs.js';
import AzureDetector from '../src/detectors/azure.js';
import OciDetector from '../src/detectors/oci.js';
import detectS3Compatible from '../src/detectors/s3compatible.js';

/**
 * 检测入口
 * @param {string} url 目标存储桶资源 URL
 * @param {object} options
 * @returns {Promise<Array>}  // 统一返回数组
 */
export async function detectBucketVul(url, options) {
    // 主动检测：有 options.vendors 且长度>0，按用户选择
    if (options && Array.isArray(options.vendors) && options.vendors.length > 0) {
        let results = [];
        for (const v of options.vendors) {
            if (v === 'aliyun') {
                results = results.concat(await checkAliyun(url, options));
            } else if (v === 'tencent') {
                results = results.concat(await checkTencent(url, options));
            } else if (v === 'huawei') {
                results = results.concat(await checkHuawei(url, options));
            } else if (v === 'AmazonS3') {
                results = results.concat(await checkAWS(url, options));
            } else if (v === 'baidu' || v === 'bos') {
                const detector = new BosDetector();
                const res = await detector.detect(url);
                if (res) results.push(res);
            } else if (v === 'qiniu' || v === 'kodo') {
                const detector = new KodoDetector();
                const res = await detector.detect(url);
                if (res) results.push(res);
            } else if (v === 'jdcloud' || v === 'jd') {
                const detector = new JdCloudDetector();
                const res = await detector.detect(url);
                if (res) results.push(res);
            } else if (v === 'ucloud' || v === 'ufile') {
                const detector = new UCloudDetector();
                const res = await detector.detect(url);
                if (res) results.push(res);
            } else if (v === 'ks3' || v === 'kingsoft') {
                const detector = new Ks3Detector();
                const res = await detector.detect(url);
                if (res) results.push(res);
            } else if (v === 'qingstor' || v === 'qingcloud') {
                const detector = new QingStorDetector();
                const res = await detector.detect(url);
                if (res) results.push(res);
            } else if (v === 'tianyi' || v === 'ctyun' || v === 'oos') {
                const detector = new TyyunDetector();
                const res = await detector.detect(url);
                if (res) results.push(res);
            } else if (v === 'eyun' || v === 'cmcc' || v === 'eos') {
                const detector = new EyunDetector();
                const res = await detector.detect(url);
                if (res) results.push(res);
            } else if (v === 'gcs' || v === 'google') {
                const detector = new GcsDetector();
                const res = await detector.detect(url);
                if (res) results.push(res);
            } else if (v === 'azure' || v === 'microsoft') {
                const detector = new AzureDetector();
                const res = await detector.detect(url);
                if (res) results.push(res);
            } else if (v === 'oci' || v === 'oracle') {
                const detector = new OciDetector();
                const res = await detector.detect(url);
                if (res) results.push(res);
            }
        }
        if (!Array.isArray(results)) return [];
        return results;
    }
    // 被动检测：自动判断厂商
    let vendor = detectVendor(url);
    if (vendor === '未知') {
        vendor = await detectVendorByServer(url);
    }
    let results = [];
    if (vendor === '阿里云') {
        results = await checkAliyun(url, options);
    } else if (vendor === '腾讯云') {
        results = await checkTencent(url, options);
    } else if (vendor === '华为云') {
        results = await checkHuawei(url, options);
    } else if (vendor === 'AmazonS3') {
        results = await checkAWS(url, options);
    } else if (vendor === '百度智能云') {
        const detector = new BosDetector();
        const res = await detector.detect(url);
        if (res) results.push(res);
    } else if (vendor === '七牛云') {
        const detector = new KodoDetector();
        const res = await detector.detect(url);
        if (res) results.push(res);
    } else if (vendor === '京东云') {
        const detector = new JdCloudDetector();
        const res = await detector.detect(url);
        if (res) results.push(res);
    } else if (vendor === 'UCloud') {
        const detector = new UCloudDetector();
        const res = await detector.detect(url);
        if (res) results.push(res);
    } else if (vendor === '金山云') {
        const detector = new Ks3Detector();
        const res = await detector.detect(url);
        if (res) results.push(res);
    } else if (vendor === '青云') {
        const detector = new QingStorDetector();
        const res = await detector.detect(url);
        if (res) results.push(res);
    } else if (vendor === '天翼云') {
        const detector = new TyyunDetector();
        const res = await detector.detect(url);
        if (res) results.push(res);
    } else if (vendor === '移动云') {
        const detector = new EyunDetector();
        const res = await detector.detect(url);
        if (res) results.push(res);
    } else if (vendor === 'Google Cloud') {
        const detector = new GcsDetector();
        const res = await detector.detect(url);
        if (res) results.push(res);
    } else if (vendor === 'Azure') {
        const detector = new AzureDetector();
        const res = await detector.detect(url);
        if (res) results.push(res);
    } else if (vendor === 'Oracle OCI') {
        const detector = new OciDetector();
        const res = await detector.detect(url);
        if (res) results.push(res);
    } else {
        // 兜底逻辑：如果未被任何厂商匹配，尝试通用 S3 兼容检测
        const s3Res = await detectS3Compatible(url);
        if (s3Res) results.push(s3Res);
    }
    if (!Array.isArray(results)) return [];

    return results;
}

/**
 * 简单根据域名判断厂商
 * @param {string} url
 * @returns {'阿里云'|'腾讯云'|'华为云'|'未知'}
 */
export function detectVendor(url) {
    try {
        const u = new URL(url);
        const host = u.hostname;
        if (host.includes('aliyuncs.com')) return '阿里云';
        if (host.includes('myqcloud.com')) return '腾讯云';
        if (host.includes('myhuaweicloud.com')) return '华为云';
        if (host.includes('amazonaws.com') || host.includes('s3.amazonaws.com.cn')) return 'AmazonS3';
        if (host.includes('bcebos.com')) return '百度智能云';
        if (host.includes('clouddn.com') || host.includes('qiniudn.com') || host.includes('qbox.me') || host.includes('qnssl.com')) return '七牛云';
        if (host.includes('jcloudcs.com')) return '京东云';
        if (host.includes('ufileos.com')) return 'UCloud';
        if (host.includes('ksyuncs.com')) return '金山云';
        if (host.includes('qingstor.com')) return '青云';
        if (host.includes('ctyunapi.cn') || host.includes('ctyunzos.cn')) return '天翼云';
        if (host.includes('storage.googleapis.com')) return 'Google Cloud';
        if (host.includes('blob.core.windows.net') || host.includes('blob.storage.azure.net')) return 'Azure';
        if (host.includes('oraclecloud.com')) return 'Oracle OCI';
        return '未知';
    } catch {
        return '未知';
    }
}

/**
 * 根据响应 Server 头判断厂商
 * @param {Response} resp fetch返回的Response对象
 * @returns {'阿里云'|'腾讯云'|'华为云'|null}
 */
export function detectVendorByServerHeader(resp) {
    const server = resp.headers.get('server');
    if (!server) return null;
    if (server === 'AliyunOSS') return '阿里云';
    if (server === 'tencent-cos') return '腾讯云';
    if (server === 'OBS') return '华为云';
    if (server === 'AmazonS3') return 'AmazonS3';
    // 百度 BOS 通常没有特定的 Server 头，或者返回 BWS 等，这里可以根据实际情况补充
    return null;
}

/**
 * 若域名未识别，则fetch一次用Server头判断
 * @param {string} url
 * @returns {Promise<'阿里云'|'腾讯云'|'华为云'|'未知'>}
 */
export async function detectVendorByServer(url) {
    try {
        const resp = await fetch(url, { method: 'HEAD' });
        const vendor = detectVendorByServerHeader(resp);
        return vendor || '未知';
    } catch {
        return '未知';
    }
}

/**
 * 检测存储桶是否公开可访问（简化版，用于日志面板快速探测）
 * @param {string} url 
 * @returns {Promise<{ isPublic: boolean, vendor: string, details: string }>}
 */
export async function detectBucketOpen(url, originalHeaders) {
    let vendor = detectVendor(url);
    if (vendor === '未知') {
        vendor = await detectVendorByServer(url);
    }

    const result = {
        isPublic: false,
        vendor: vendor,
        details: '',
        request: null,
        response: null
    };

    try {
        // 构造探测用的请求头：优先使用原始请求头，否则回退到普通浏览器头
        const defaultHeaders = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': '*/*'
        };
        const headers = { ...defaultHeaders, ...originalHeaders };
        
        // 确保 Host 头正确，且剔除敏感信息
        const u = new URL(url);
        headers['Host'] = u.host;
        delete headers['Cookie'];
        delete headers['Authorization'];

        let detector;
        switch (vendor) {
            case '阿里云': case '腾讯云': case '华为云': case 'AmazonS3': break;
            case '百度智能云': detector = new BosDetector(); break;
            case '七牛云': detector = new KodoDetector(); break;
            case '京东云': detector = new JdCloudDetector(); break;
            case 'UCloud': detector = new UCloudDetector(); break;
            case '金山云': detector = new Ks3Detector(); break;
            case '青云': detector = new QingStorDetector(); break;
            case '天翼云': detector = new TyyunDetector(); break;
            case '移动云': detector = new EyunDetector(); break;
            case 'Google Cloud': detector = new GcsDetector(); break;
            case 'Azure': detector = new AzureDetector(); break;
            case 'Oracle OCI': detector = new OciDetector(); break;
        }

        let isPublicTemp = false;
        if (detector) {
            const res = await detector.detect(url, headers);
            if (res && res.found) {
                isPublicTemp = true;
                result.details = res.detail || '存储桶公开可访问';
            } else {
                result.details = '未检测到公开风险或访问被拒绝';
            }
        } else {
            const resp = await fetch(url, { method: 'GET', headers, credentials: 'omit' });
            const text = await resp.text();
            if (resp.status === 200 && (text.includes('<ListBucketResult>') || text.includes('<Contents>'))) {
                isPublicTemp = true;
                result.details = '存储桶列表公开可访问';
            } else if (text.includes('AccessDenied') || text.includes('NoSuchBucket')) {
                result.details = '访问被拒绝或桶不存在';
            } else {
                result.details = `状态码: ${resp.status}`;
            }
        }

        if (isPublicTemp) {
            result.isPublic = true;
            result.request = { url, method: 'GET', headers, body: null };
            const resp = await fetch(url, { method: 'GET', headers, credentials: 'omit' });
            const bodyText = await resp.text();
            result.response = {
                status: resp.status,
                statusText: resp.statusText,
                headers: Object.fromEntries(resp.headers.entries()),
                body: bodyText // 完整存储，不再截断
            };
        }
    } catch (e) {
        result.isPublic = false;
        result.details = e.message;
    }

    return result;
} 