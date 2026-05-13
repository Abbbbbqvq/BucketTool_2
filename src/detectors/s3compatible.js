/**
 * S3CompatibleDetector - 通用 S3 兼容存储桶检测器
 * 
 * 用于检测那些没有被特定厂商正则匹配，但遵循 S3 协议标准的存储桶。
 * 许多私有化部署的 OSS（如 MinIO, Ceph RGW, SeaweedFS 等）都使用此标准。
 */

/**
 * 通用 S3 兼容存储桶检测函数
 * 
 * @param {string} url - 目标存储桶 URL
 * @returns {Promise<object|null>} 检测结果对象或 null
 */
export async function detectS3Compatible(url) {
    try {
        console.log(`[S3Compatible] 正在执行通用 S3 兼容性检测: ${url}`);
        
        // 1. 发送不带签名的 GET 请求
        const response = await fetch(url, {
            method: 'GET',
            credentials: 'omit'
        });

        const text = await response.text();
        const status = response.status;

        // 2. 解析响应体特征
        
        // 判定为公开桶：包含标准的 S3 ListBucketResult 命名空间
        if (text.includes('<ListBucketResult') && text.includes('http://s3.amazonaws.com/doc/2006-03-01/')) {
            console.log(`[S3Compatible] 检测到公开 S3 兼容存储桶`);
            return {
                type: '存储桶可遍历',
                vendor: 'S3 兼容存储',
                url: url,
                found: true,
                detail: '检测到符合 S3 标准的公开存储桶列表',
                request: '',
                response: ''
            };
        }

        // 判定为私有或不存在：包含 AccessDenied
        if (text.includes('<Code>AccessDenied</Code>') || status === 403) {
            console.log(`[S3Compatible] 访问被拒绝 (AccessDenied)`);
            return null;
        }

        // 判定为不存在：NoSuchBucket 或 NoSuchKey
        if (text.includes('<Code>NoSuchBucket</Code>') || text.includes('<Code>NoSuchKey</Code>')) {
            console.log(`[S3Compatible] 存储桶或对象不存在`);
            return null;
        }

        // 其他情况返回 undefined 或 null，视具体需求而定
        // 这里返回 null 表示未检测到明确的漏洞特征
        return null;

    } catch (error) {
        console.error(`[S3Compatible] 检测过程中发生错误:`, error);
        return null;
    }
}

export default detectS3Compatible;
