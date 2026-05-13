/**
 * OciDetector - Oracle OCI Object Storage 检测器
 * 
 * 继承自 BaseDetector，专门用于检测 Oracle Cloud Infrastructure (OCI) Object Storage 的公开桶漏洞。
 * 
 * OCI 存储路径格式通常为：
 * https://objectstorage.{region}.oraclecloud.com/n/{namespace}/b/{bucket}/o/{object}
 * 
 * 检测逻辑：
 * 1. 识别域名 objectstorage.*.oraclecloud.com
 * 2. 从 URL 路径中提取 namespace 和 bucket
 * 3. 构造桶级列表请求：/n/{namespace}/b/{bucket}?limit=1
 * 4. 调用基类进行检测
 */
import BaseDetector from './BaseDetector.js';

class OciDetector extends BaseDetector {
    /**
     * Oracle OCI Object Storage 域名正则表达式
     * 匹配格式: objectstorage.{region}.oraclecloud.com
     */
    static DOMAIN_REGEX = /^objectstorage\.([a-z0-9-]+)\.oraclecloud\.com$/i;

    /**
     * OCI 路径正则表达式，用于提取 namespace 和 bucket
     * 匹配格式: /n/{namespace}/b/{bucket}...
     */
    static PATH_REGEX = /\/n\/([^/]+)\/b\/([^/]+)/i;

    /**
     * 检测指定的 Oracle OCI Object Storage URL
     * 
     * @param {string} url - 要检测的 OCI 存储桶 URL
     * @returns {Promise<object|null>} 如果检测到漏洞，返回结果对象；否则返回 null
     */
    async detect(url) {
        let region = '';
        let namespace = '';
        let bucketName = '';
        let detectionUrl = url;

        try {
            const urlObj = new URL(url);
            const host = urlObj.hostname;

            // 1. 验证域名
            const domainMatch = host.match(OciDetector.DOMAIN_REGEX);
            if (!domainMatch) {
                console.log(`[OciDetector] URL 不符合 OCI 域名格式: ${url}`);
                return null;
            }
            region = domainMatch[1];

            // 2. 提取 namespace 和 bucket
            const pathMatch = urlObj.pathname.match(OciDetector.PATH_REGEX);
            if (pathMatch) {
                namespace = pathMatch[1];
                bucketName = pathMatch[2];
                console.log(`[OciDetector] 识别到 OCI 存储桶: namespace=${namespace}, bucket=${bucketName}, region=${region}`);
                
                // 3. 构造桶级列表请求 URL
                // OCI 列出对象的 API 路径为: /n/{namespace}/b/{bucket}/o
                // 添加 limit=1 以减少响应体大小，仅用于检测是否可访问
                detectionUrl = `${urlObj.protocol}//${host}/n/${namespace}/b/${bucketName}/o?limit=1`;
            } else {
                console.log(`[OciDetector] URL 路径中未找到 namespace 或 bucket 信息: ${url}`);
                // 如果路径不完整，尝试直接检测原始 URL，但成功率可能较低
            }

        } catch (e) {
            console.error(`[OciDetector] 解析 URL 失败: ${e.message}`);
            return null;
        }

        // 4. 调用基类的 detect 方法进行基础检测
        const isVulnerable = await super.detect(detectionUrl);

        // 5. 根据检测结果构建返回对象
        if (isVulnerable === true) {
            return {
                type: '存储桶可遍历',
                vendor: 'Oracle OCI',
                url: detectionUrl,
                found: true,
                detail: `Oracle OCI 存储桶 "${bucketName}" (Namespace: ${namespace}) 存在公开访问风险`,
                request: '', 
                response: '' 
            };
        } else if (isVulnerable === false) {
            console.log(`[OciDetector] OCI 存储桶 "${bucketName}" 未检测到公开漏洞`);
            return null;
        } else {
            return null;
        }
    }
}

export default OciDetector;
