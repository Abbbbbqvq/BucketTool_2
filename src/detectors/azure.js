/**
 * AzureDetector - Azure Blob Storage 存储检测器
 * 
 * 继承自 BaseDetector，用于检测 Microsoft Azure Blob Storage 的公开访问风险。
 * 
 * 局限性说明：
 * 1. Azure Blob Storage 的权限模型基于“存储账户 (Storage Account) -> 容器 (Container) -> Blob”。
 * 2. 与 S3 等直接以 Bucket 为根不同，Azure 的公开性通常是在容器级别设置的（如 Public Read Access）。
 * 3. 本检测器目前主要针对存储账户级别的端点进行探测。如果根路径返回了服务信息或特定的错误码，
 *    可以辅助判断账户是否存在。
 * 4. 要精确检测某个容器是否公开，通常需要知道容器名并构造 {account}.blob.core.windows.net/{container} 的 URL。
 *    目前的实现主要依赖 BaseDetector 对根路径或给定路径的通用 XML/特征检测。
 */
import BaseDetector from './BaseDetector.js';

class AzureDetector extends BaseDetector {
    /**
     * Azure Blob Storage 标准域名正则表达式
     * 匹配格式: {storageaccount}.blob.core.windows.net
     */
    static STANDARD_DOMAIN_REGEX = /^([a-z0-9]+)\.blob\.core\.windows\.net$/i;

    /**
     * Azure Blob Storage 分区/区域化域名正则表达式
     * 匹配格式: {storageaccount}.z{number}.blob.storage.azure.net 等
     */
    static REGIONAL_DOMAIN_REGEX = /^([a-z0-9]+)\.z[0-9]+\.blob\.storage\.azure\.net$/i;

    /**
     * 检测指定的 Azure Blob Storage URL
     * 
     * @param {string} url - 要检测的 Azure Blob Storage URL
     * @returns {Promise<object|null>} 如果检测到漏洞，返回结果对象；否则返回 null
     */
    async detect(url) {
        let accountName = '';
        
        // 1. 尝试匹配标准格式或分区格式
        const standardMatch = url.match(AzureDetector.STANDARD_DOMAIN_REGEX);
        const regionalMatch = url.match(AzureDetector.REGIONAL_DOMAIN_REGEX);

        if (standardMatch) {
            accountName = standardMatch[1];
            console.log(`[AzureDetector] 识别到 Azure 标准存储账户: ${accountName}`);
        } else if (regionalMatch) {
            accountName = regionalMatch[1];
            console.log(`[AzureDetector] 识别到 Azure 分区存储账户: ${accountName}`);
        } else {
            console.log(`[AzureDetector] URL 不符合 Azure Blob Storage 常见域名格式: ${url}`);
            // 即使域名不匹配，如果是自定义域名指向 Azure，仍可尝试通用检测
        }

        // 2. 调用基类的 detect 方法进行基础检测
        // 注意：Azure 的根路径通常返回 400 (InvalidQueryParameterValue) 或 XML 描述，
        // 具体的容器列表需要访问 /?comp=list
        const isVulnerable = await super.detect(url);

        // 3. 根据检测结果构建返回对象
        if (isVulnerable === true) {
            return {
                type: '存储桶可遍历', // 在 Azure 语境下通常指容器列表公开或特定 Blob 公开
                vendor: 'Azure',
                url: url,
                found: true,
                detail: `Azure Blob Storage 账户 "${accountName || '未知'}" 存在公开访问风险`,
                request: '', 
                response: '' 
            };
        } else if (isVulnerable === false) {
            console.log(`[AzureDetector] Azure 存储账户 "${accountName || '未知'}" 未检测到公开漏洞`);
            return null;
        } else {
            return null;
        }
    }
}

export default AzureDetector;
