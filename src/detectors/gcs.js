/**
 * GcsDetector - Google Cloud Storage (GCS) 存储桶检测器
 * 
 * 继承自 BaseDetector，专门用于检测 Google Cloud Storage 的公开桶漏洞。
 * 支持标准域名格式和自定义域名（CNAME 到 c.storage.googleapis.com）。
 */
import BaseDetector from './BaseDetector.js';

class GcsDetector extends BaseDetector {
    /**
     * Google Cloud Storage 标准域名正则表达式
     * 匹配格式: {bucket}.storage.googleapis.com
     */
    static STANDARD_DOMAIN_REGEX = /^([a-z0-9._-]+)\.storage\.googleapis\.com$/i;

    /**
     * Google Cloud Storage 自定义域名 CNAME 目标正则
     * 匹配格式: c.storage.googleapis.com (通常作为 CNAME 的目标)
     * 注意：由于自定义域名本身没有固定特征，此正则主要用于识别已知的 GCS 端点。
     * 对于完全自定义的域名，通常需要结合 DNS CNAME 记录或响应特征来判断。
     */
    static CNAME_TARGET_REGEX = /c\.storage\.googleapis\.com/i;

    /**
     * 检测指定的 Google Cloud Storage URL
     * 
     * @param {string} url - 要检测的 GCS 存储桶 URL
     * @returns {Promise<object|null>} 如果检测到漏洞，返回结果对象；否则返回 null
     */
    async detect(url) {
        let bucketName = '';
        let isStandardDomain = false;

        // 1. 尝试匹配标准格式: {bucket}.storage.googleapis.com
        const standardMatch = url.match(GcsDetector.STANDARD_DOMAIN_REGEX);
        if (standardMatch) {
            bucketName = standardMatch[1];
            isStandardDomain = true;
            console.log(`[GcsDetector] 识别到标准 GCS 存储桶: ${bucketName}`);
        } else {
            // 2. 检查是否为自定义域名（此处简化处理，实际生产中可能需要 DNS 查询）
            // 如果 URL 的主机名最终解析到 c.storage.googleapis.com，则视为 GCS。
            // 由于浏览器环境限制，无法直接进行 DNS CNAME 查询，这里主要依赖标准域名匹配。
            // 如果用户输入的是自定义域名，且该域名指向 GCS，BaseDetector 的 XML 特征检测依然有效。
            console.log(`[GcsDetector] 尝试检测可能的自定义域名 GCS 存储桶: ${url}`);
        }

        // 3. 调用基类的 detect 方法进行基础检测
        // BaseDetector 会检查状态码 200 且包含 ListBucketResult 等标记
        const isVulnerable = await super.detect(url);

        // 4. 根据检测结果构建返回对象
        if (isVulnerable === true) {
            return {
                type: '存储桶可遍历', // 保持与现有项目一致的漏洞类型命名
                vendor: 'Google Cloud',
                url: url,
                found: true,
                detail: `Google Cloud Storage 存储桶 "${bucketName || '未知'}" 存在公开访问风险`,
                request: '', 
                response: '' 
            };
        } else if (isVulnerable === false) {
            // 403 表示私有桶或权限不足
            console.log(`[GcsDetector] GCS 存储桶 "${bucketName || '未知'}" 未检测到公开漏洞 (可能为私有)`);
            return null;
        } else {
            // undefined 情况
            return null;
        }
    }
}

export default GcsDetector;
