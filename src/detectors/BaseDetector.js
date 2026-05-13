/**
 * BaseDetector - 云存储桶检测基类
 * 
 * 提供基础的检测逻辑，用于判断存储桶是否公开可访问。
 * 子类可以继承此类并扩展特定的检测功能。
 */
class BaseDetector {
    /**
     * 检测指定的 URL 是否存在公开存储桶漏洞
     * 
     * @param {string} url - 要检测的存储桶 URL
     * @param {object} headers - 自定义请求头（可选）
     * @returns {Promise<boolean|undefined>} 
     *   - true: 检测到公开桶漏洞 (状态码 200 且包含特定 XML 标记)
     *   - false: 未检测到漏洞或访问被拒绝 (状态码 403 或包含 AccessDenied/NoSuchBucket)
     *   - undefined: 其他情况 (如网络错误、未知响应等)
     */
    async detect(url, headers = {}) {
        try {
            // 发起匿名 fetch 请求，不携带任何凭证 (credentials: 'omit')
            const response = await fetch(url, {
                method: 'GET',
                credentials: 'omit', // 确保不发送 cookies 或其他认证信息
                headers: headers
            });

            const statusCode = response.status;
            const bodyText = await response.text();

            // 判定为公开桶漏洞的条件：
            // 1. 响应状态码为 200 (OK)
            // 2. 响应体中包含常见的 S3/OSS 列表 XML 标记
            if (statusCode === 200) {
                if (bodyText.includes('ListBucketResult') || 
                    bodyText.includes('Contents') || 
                    bodyText.includes('CommonPrefixes')) {
                    console.log(`[BaseDetector] 检测到公开桶漏洞: ${url}`);
                    return true;
                }
            }

            // 判定为无漏洞或访问被拒绝的条件：
            // 1. 响应状态码为 403 (Forbidden)
            // 2. 或者响应体中包含 'AccessDenied' 或 'NoSuchBucket' 错误信息
            if (statusCode === 403 || 
                bodyText.includes('AccessDenied') || 
                bodyText.includes('NoSuchBucket')) {
                console.log(`[BaseDetector] 访问被拒绝或桶不存在: ${url}`);
                return false;
            }

            // 其他情况返回 undefined，表示无法确定或需要进一步检测
            console.log(`[BaseDetector] 检测结果不确定: ${url}, 状态码: ${statusCode}`);
            return undefined;

        } catch (error) {
            // 处理网络错误或其他异常
            console.error(`[BaseDetector] 检测过程中发生错误: ${url}`, error);
            return undefined;
        }
    }
}

// 导出基类供其他模块使用
export default BaseDetector;
