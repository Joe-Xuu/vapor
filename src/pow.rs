use sha2::{Sha256, Digest};

// ⛏️ 难度设定
// 这是一个权衡：难度越高，防垃圾越强，但手机发消息越慢。
// 这里我们设定：哈希值的前 2 个字节必须全是 0 (也就是前 16 位是 0)。
// 在现代 CPU 上大概需要 100ms - 500ms。
const DIFFICULTY_PREFIX_ZEROS: usize = 2; 

/// 挖矿函数 (发送者调用)
/// 输入：加密后的数据
/// 输出：一个神奇的数字 (Nonce)，使得 SHA256(数据 + Nonce) 符合难度
pub fn mine_pow(data: &[u8]) -> u64 {
    let mut nonce = 0u64;
    let mut hasher = Sha256::new();

    loop {
        // 1. 准备哈希器
        let mut temp_hasher = hasher.clone();
        temp_hasher.update(data);
        temp_hasher.update(nonce.to_be_bytes()); // 拼上 nonce
        let result = temp_hasher.finalize();

        // 2. 检查结果是否符合难度
        if check_difficulty(&result) {
            return nonce;
        }

        // 3. 不符合？换个数字重试
        nonce += 1;
        
        // (可选) 每算 10万次打印一下，让你感觉到它在工作
        if nonce % 100_000 == 0 {
            // print!("."); 
        }
    }
}

/// 验矿函数 (接收者调用)
/// 极其快速，只需要算一次哈希
pub fn verify_pow(data: &[u8], nonce: u64) -> bool {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.update(nonce.to_be_bytes());
    let result = hasher.finalize();

    check_difficulty(&result)
}

// 辅助函数：检查哈希的前 N 个字节是不是 0
fn check_difficulty(hash: &[u8]) -> bool {
    // 检查前 DIFFICULTY_PREFIX_ZEROS 个字节是否都是 0
    hash.iter().take(DIFFICULTY_PREFIX_ZEROS).all(|&b| b == 0)
}