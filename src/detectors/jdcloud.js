/**
 * JdCloudDetector - 京东云 OSS 存储桶检测器
 * 
 * 继承自 BaseDetector，专门用于检测京东云 OSS (JD Cloud Object Storage) 的公开桶漏洞。
 */
import BaseDetector from './BaseDetector.js';

class JdCloudDetector extends BaseDetector {
    /**
     * 京东云 OSS 域名正则表达式
     * 匹配格式: {bucket}.oss.{region}.jcloudcs.com
     * region 支持多种区域代码，如 cn-north-1, cn-east-2 等
     */
    static DOMAIN_REGEX = /^([a-z0-9.-]+)\.oss\.([a-z0-9-]+)\.jcloudcs\.com$/i;

    /**
     * 检测指定的京东云 OSS URL
     * 
     * @param {string} url - 要检测的京东云 OSS 存储桶 URL
     * @returns {Promise<object|null>} 如果检测到漏洞，返回结果对象；否则返回 null
     */
    async detect(url) {
        // 1. 验证是否为合法的京东云 OSS 域名
        const match = url.match(JdCloudDetector.DOMAIN_REGEX);
        if (!match) {
            console.log(`[JdCloudDetector] URL 不符合京东云 OSS 域名格式: ${url}`);
            return null;
        }

        const bucketName = match[1];
        const region = match[2];
        console.log(`[JdCloudDetector] 识别到京东云 OSS 存储桶: ${bucketName}, 区域: ${region}`);

        // 2. 调用基类的 detect 方法进行基础检测
        const isVulnerable = await super.detect(url);

        // 3. 根据检测结果构建返回对象
        if (isVulnerable === true) {
            return {
                type: '存储桶可遍历', // 保持与现有项目一致的漏洞类型命名
                vendor: '京东云',
                url: url,
                found: true,
                detail: `京东云 OSS 存储桶 "${bucketName}" 存在公开访问风险`,
                request: '', 
                response: '' 
            };
        } else if (isVulnerable === false) {
            // 403 表示私有桶，404 表示桶不存在
            console.log(`[JdCloudDetector] 京东云 OSS 存储桶 "${bucketName}" 未检测到公开漏洞 (可能为私有或不存在)`);
            return null;
        } else {
            // undefined 情况
            return null;
        }
    }
}

export default JdCloudDetector;
