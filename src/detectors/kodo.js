/**
 * KodoDetector - 七牛云 Kodo 存储桶检测器
 * 
 * 继承自 BaseDetector，专门用于检测七牛云 Kodo (Qiniu Cloud Object Storage) 的公开桶漏洞。
 */
import BaseDetector from './BaseDetector.js';

class KodoDetector extends BaseDetector {
    /**
     * 七牛云 Kodo 域名正则表达式
     * 匹配格式: {bucket}.{domain} (例如: mybucket.hd-bkt.clouddn.com, mybucket.qiniudn.com 等)
     * 这里主要匹配常见的七牛云加速域名后缀
     */
    static DOMAIN_REGEX = /^([a-z0-9._-]+)\.(hd-bkt\.clouddn\.com|qiniudn\.com|qbox\.me|qnssl\.com)$/i;

    /**
     * 检测指定的 Kodo URL
     * 
     * @param {string} url - 要检测的 Kodo 存储桶 URL
     * @returns {Promise<object|null>} 如果检测到漏洞，返回结果对象；否则返回 null
     */
    async detect(url) {
        // 1. 验证是否为合法的 Kodo 域名
        const match = url.match(KodoDetector.DOMAIN_REGEX);
        if (!match) {
            console.log(`[KodoDetector] URL 不符合 Kodo 域名格式: ${url}`);
            return null;
        }

        const bucketName = match[1];
        const domainSuffix = match[2];
        console.log(`[KodoDetector] 识别到 Kodo 存储桶: ${bucketName}, 域名后缀: ${domainSuffix}`);

        // 2. 调用基类的 detect 方法进行基础检测
        // BaseDetector 会检查状态码 200 且包含 ListBucketResult 等标记
        const isVulnerable = await super.detect(url);

        // 3. 根据检测结果构建返回对象
        if (isVulnerable === true) {
            return {
                type: '存储桶可遍历', // 保持与现有项目一致的漏洞类型命名
                vendor: '七牛云',
                url: url,
                found: true,
                detail: `七牛云 Kodo 存储桶 "${bucketName}" 存在公开访问风险`,
                request: '', 
                response: '' 
            };
        } else if (isVulnerable === false) {
            // 403 或 AccessDenied 表示私有桶或权限受限
            console.log(`[KodoDetector] Kodo 存储桶 "${bucketName}" 未检测到公开漏洞 (可能为私有)`);
            return null;
        } else {
            // undefined 情况
            return null;
        }
    }
}

export default KodoDetector;
