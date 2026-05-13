/**
 * Ks3Detector - 金山云 KS3 存储桶检测器
 * 
 * 继承自 BaseDetector，专门用于检测金山云 KS3 (Kingsoft Standard Storage Service) 的公开桶漏洞。
 */
import BaseDetector from './BaseDetector.js';

class Ks3Detector extends BaseDetector {
    /**
     * 金山云 KS3 域名正则表达式
     * 匹配格式: {bucket}.ks3-{region}.ksyuncs.com
     * region 支持多种区域代码，如 cn-beijing, cn-shanghai, cn-guangzhou 等
     */
    static DOMAIN_REGEX = /^([a-z0-9.-]+)\.ks3-([a-z0-9-]+)\.ksyuncs\.com$/i;

    /**
     * 检测指定的金山云 KS3 URL
     * 
     * @param {string} url - 要检测的金山云 KS3 存储桶 URL
     * @returns {Promise<object|null>} 如果检测到漏洞，返回结果对象；否则返回 null
     */
    async detect(url) {
        // 1. 验证是否为合法的金山云 KS3 域名
        const match = url.match(Ks3Detector.DOMAIN_REGEX);
        if (!match) {
            console.log(`[Ks3Detector] URL 不符合金山云 KS3 域名格式: ${url}`);
            return null;
        }

        const bucketName = match[1];
        const region = match[2];
        console.log(`[Ks3Detector] 识别到金山云 KS3 存储桶: ${bucketName}, 区域: ${region}`);

        // 2. 调用基类的 detect 方法进行基础检测
        const isVulnerable = await super.detect(url);

        // 3. 根据检测结果构建返回对象
        if (isVulnerable === true) {
            return {
                type: '存储桶可遍历', // 保持与现有项目一致的漏洞类型命名
                vendor: '金山云',
                url: url,
                found: true,
                detail: `金山云 KS3 存储桶 "${bucketName}" 存在公开访问风险`,
                request: '', 
                response: '' 
            };
        } else if (isVulnerable === false) {
            // 403 表示私有桶，404 表示桶不存在
            console.log(`[Ks3Detector] 金山云 KS3 存储桶 "${bucketName}" 未检测到公开漏洞 (可能为私有或不存在)`);
            return null;
        } else {
            // undefined 情况
            return null;
        }
    }
}

export default Ks3Detector;
