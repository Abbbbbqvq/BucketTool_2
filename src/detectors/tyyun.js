/**
 * TyyunDetector - 天翼云 OOS 存储桶检测器
 * 
 * 继承自 BaseDetector，专门用于检测天翼云 OOS (Tianyi Cloud Object Storage) 的公开桶漏洞。
 * 支持两种域名格式：
 * 1. 旧格式: {bucket}.oos.ctyunapi.cn
 * 2. 新格式 (2026年6月起): {bucket}.{region}.ctyunzos.cn
 */
import BaseDetector from './BaseDetector.js';

class TyyunDetector extends BaseDetector {
    /**
     * 天翼云 OOS 旧格式域名正则表达式
     * 匹配格式: {bucket}.oos.ctyunapi.cn
     */
    static OLD_DOMAIN_REGEX = /^([a-z0-9.-]+)\.oos\.ctyunapi\.cn$/i;

    /**
     * 天翼云 OOS 新格式域名正则表达式
     * 匹配格式: {bucket}.{region}.ctyunzos.cn
     * region 支持多种区域代码，如 zj, bj, sh 等
     */
    static NEW_DOMAIN_REGEX = /^([a-z0-9.-]+)\.([a-z0-9-]+)\.ctyunzos\.cn$/i;

    /**
     * 检测指定的天翼云 OOS URL
     * 
     * @param {string} url - 要检测的天翼云 OOS 存储桶 URL
     * @returns {Promise<object|null>} 如果检测到漏洞，返回结果对象；否则返回 null
     */
    async detect(url) {
        let bucketName = '';
        let region = '';
        let formatType = '';

        // 1. 尝试匹配新格式: {bucket}.{region}.ctyunzos.cn
        const newFormatMatch = url.match(TyyunDetector.NEW_DOMAIN_REGEX);
        if (newFormatMatch) {
            bucketName = newFormatMatch[1];
            region = newFormatMatch[2];
            formatType = '新格式';
            console.log(`[TyyunDetector] 识别到天翼云 OOS 存储桶 (${formatType}): ${bucketName}, 区域: ${region}`);
        } else {
            // 2. 尝试匹配旧格式: {bucket}.oos.ctyunapi.cn
            const oldFormatMatch = url.match(TyyunDetector.OLD_DOMAIN_REGEX);
            if (oldFormatMatch) {
                bucketName = oldFormatMatch[1];
                formatType = '旧格式';
                console.log(`[TyyunDetector] 识别到天翼云 OOS 存储桶 (${formatType}): ${bucketName}`);
            } else {
                console.log(`[TyyunDetector] URL 不符合天翼云 OOS 域名格式: ${url}`);
                return null;
            }
        }

        // 3. 调用基类的 detect 方法进行基础检测
        const isVulnerable = await super.detect(url);

        // 4. 根据检测结果构建返回对象
        if (isVulnerable === true) {
            return {
                type: '存储桶可遍历', // 保持与现有项目一致的漏洞类型命名
                vendor: '天翼云',
                url: url,
                found: true,
                detail: `天翼云 OOS 存储桶 "${bucketName}" (${formatType}) 存在公开访问风险`,
                request: '', 
                response: '' 
            };
        } else if (isVulnerable === false) {
            // 403 表示私有桶，404 表示桶不存在
            console.log(`[TyyunDetector] 天翼云 OOS 存储桶 "${bucketName}" 未检测到公开漏洞 (可能为私有或不存在)`);
            return null;
        } else {
            // undefined 情况
            return null;
        }
    }
}

export default TyyunDetector;
