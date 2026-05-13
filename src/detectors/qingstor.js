/**
 * QingStorDetector - 青云 QingStor 存储桶检测器
 * 
 * 继承自 BaseDetector，专门用于检测青云 QingStor (QingCloud Object Storage) 的公开桶漏洞。
 * 支持两种 URL 风格：
 * 1. Virtual-hosted 风格: {bucket}.{region}.qingstor.com
 * 2. Path 风格: {region}.qingstor.com/{bucket}
 */
import BaseDetector from './BaseDetector.js';

class QingStorDetector extends BaseDetector {
    /**
     * 青云 QingStor Virtual-hosted 风格域名正则表达式
     * 匹配格式: {bucket}.{region}.qingstor.com
     * region 支持多种区域代码，如 pek3a, sh1a, gd2a 等
     */
    static VIRTUAL_HOSTED_REGEX = /^([a-z0-9.-]+)\.([a-z0-9-]+)\.qingstor\.com$/i;

    /**
     * 青云 QingStor Path 风格域名正则表达式
     * 匹配格式: {region}.qingstor.com/{bucket}
     */
    static PATH_STYLE_REGEX = /^([a-z0-9-]+)\.qingstor\.com\/([a-z0-9._-]+)(?:\/|$)/i;

    /**
     * 检测指定的青云 QingStor URL
     * 
     * @param {string} url - 要检测的青云 QingStor 存储桶 URL
     * @returns {Promise<object|null>} 如果检测到漏洞，返回结果对象；否则返回 null
     */
    async detect(url) {
        let bucketName = '';
        let region = '';
        let normalizedUrl = url;

        // 1. 尝试匹配 Virtual-hosted 风格: {bucket}.{region}.qingstor.com
        const virtualHostedMatch = url.match(QingStorDetector.VIRTUAL_HOSTED_REGEX);
        if (virtualHostedMatch) {
            bucketName = virtualHostedMatch[1];
            region = virtualHostedMatch[2];
            console.log(`[QingStorDetector] 识别到 Virtual-hosted 风格 QingStor 存储桶: ${bucketName}, 区域: ${region}`);
        } else {
            // 2. 尝试匹配 Path 风格: {region}.qingstor.com/{bucket}
            const pathMatch = url.match(QingStorDetector.PATH_STYLE_REGEX);
            if (pathMatch) {
                region = pathMatch[1];
                bucketName = pathMatch[2];
                // 构建标准化的 Virtual-hosted 风格 URL 用于检测
                normalizedUrl = `https://${bucketName}.${region}.qingstor.com`;
                console.log(`[QingStorDetector] 识别到 Path 风格 QingStor 存储桶: ${bucketName}, 区域: ${region}`);
            } else {
                console.log(`[QingStorDetector] URL 不符合青云 QingStor 域名格式: ${url}`);
                return null;
            }
        }

        // 3. 调用基类的 detect 方法进行基础检测
        const isVulnerable = await super.detect(normalizedUrl);

        // 4. 根据检测结果构建返回对象
        if (isVulnerable === true) {
            return {
                type: '存储桶可遍历', // 保持与现有项目一致的漏洞类型命名
                vendor: '青云',
                url: normalizedUrl,
                found: true,
                detail: `青云 QingStor 存储桶 "${bucketName}" 存在公开访问风险`,
                request: '', 
                response: '' 
            };
        } else if (isVulnerable === false) {
            // 403 表示私有桶，404 表示桶不存在
            console.log(`[QingStorDetector] 青云 QingStor 存储桶 "${bucketName}" 未检测到公开漏洞 (可能为私有或不存在)`);
            return null;
        } else {
            // undefined 情况
            return null;
        }
    }
}

export default QingStorDetector;
