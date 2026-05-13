/**
 * BosDetector - 百度智能云 BOS 存储桶检测器
 * 
 * 继承自 BaseDetector，专门用于检测百度智能云 BOS (Baidu Object Storage) 的公开桶漏洞。
 */
import BaseDetector from './BaseDetector.js';

class BosDetector extends BaseDetector {
    /**
     * 百度智能云 BOS 域名正则表达式
     * 匹配格式: {bucket}.{region}.bcebos.com
     * region 支持多种缩写，如 bj, gz, su, sh, hz 等
     */
    static DOMAIN_REGEX = /^([a-z0-9.-]+)\.([a-z]{2,})\.bcebos\.com$/i;

    /**
     * 检测指定的 BOS URL
     * 
     * @param {string} url - 要检测的 BOS 存储桶 URL
     * @returns {Promise<object|null>} 如果检测到漏洞，返回结果对象；否则返回 null
     */
    async detect(url) {
        // 1. 验证是否为合法的 BOS 域名
        const match = url.match(BosDetector.DOMAIN_REGEX);
        if (!match) {
            console.log(`[BosDetector] URL 不符合 BOS 域名格式: ${url}`);
            return null;
        }

        const bucketName = match[1];
        const region = match[2];
        console.log(`[BosDetector] 识别到 BOS 存储桶: ${bucketName}, 区域: ${region}`);

        // 2. 调用基类的 detect 方法进行基础检测
        const isVulnerable = await super.detect(url);

        // 3. 根据检测结果构建返回对象
        if (isVulnerable === true) {
            return {
                type: '存储桶可遍历', // 保持与现有项目一致的漏洞类型命名
                vendor: '百度智能云',
                url: url,
                found: true,
                detail: `百度智能云 BOS 存储桶 "${bucketName}" 存在公开访问风险`,
                request: '', // 可以在这里补充具体的请求细节，如果需要的话
                response: '' // 可以在这里补充具体的响应细节，如果需要的话
            };
        } else if (isVulnerable === false) {
            console.log(`[BosDetector] BOS 存储桶 "${bucketName}" 未检测到公开漏洞`);
            return null;
        } else {
            // undefined 情况，可能需要更深入的检测或视为无漏洞
            return null;
        }
    }
}

export default BosDetector;
