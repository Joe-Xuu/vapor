use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce
};
use rand::RngCore;
use sha2::{Sha256, Digest};
use std::time::{SystemTime, UNIX_EPOCH};
use x25519_dalek::{StaticSecret, PublicKey};

// ⏳ 生存时间窗口 (10秒)
const ROTATION_INTERVAL_SECONDS: u64 = 10;

// === 1. 密钥生成部分 ===

/// 生成我的临时身份 (私钥 + 公钥)
pub fn generate_ecdh_keys() -> (StaticSecret, PublicKey) {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    (secret, public)
}

/// 核心魔法：计算共享秘密
/// 输入：我的私钥 + 对方的公钥
/// 输出：一个只有我们两人知道的 32字节 秘密
pub fn compute_shared_secret(my_secret: &StaticSecret, their_public_bytes: &[u8; 32]) -> [u8; 32] {
    let their_public = PublicKey::from(*their_public_bytes);
    let shared_secret = my_secret.diffie_hellman(&their_public);
    *shared_secret.as_bytes()
}

// === 2. 加密解密部分 (结合了时间销毁) ===

/// 根据 [共享秘密] 和 [时间] 衍生出当前的会话密钥
fn derive_key(base_secret: &[u8; 32], timestamp: u64) -> aes_gcm::Key<Aes256Gcm> {
    let time_step = timestamp / ROTATION_INTERVAL_SECONDS;
    
    let mut hasher = Sha256::new();
    hasher.update(base_secret); // 混入 Diffie-Hellman 协商出的秘密
    hasher.update(time_step.to_be_bytes()); // 混入时间
    let result = hasher.finalize();

    *aes_gcm::Key::<Aes256Gcm>::from_slice(&result)
}

/// 加密：现在需要传入 [共享秘密]
pub fn encrypt_message(base_secret: &[u8; 32], plaintext: &str) -> (Vec<u8>, Vec<u8>) {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let key = derive_key(base_secret, now);
    let cipher = Aes256Gcm::new(&key);

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, plaintext.as_bytes())
        .expect("加密失败");

    (ciphertext, nonce_bytes.to_vec())
}

/// 解密：也需要传入 [共享秘密]
pub fn decrypt_message(base_secret: &[u8; 32], ciphertext: &[u8], nonce_bytes: &[u8]) -> Option<String> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let nonce = Nonce::from_slice(nonce_bytes);

    // 尝试当前窗口
    let key_now = derive_key(base_secret, now);
    let cipher_now = Aes256Gcm::new(&key_now);
    if let Ok(bytes) = cipher_now.decrypt(nonce, ciphertext) {
        return String::from_utf8(bytes).ok();
    }

    // 尝试上一窗口
    let key_prev = derive_key(base_secret, now - ROTATION_INTERVAL_SECONDS);
    let cipher_prev = Aes256Gcm::new(&key_prev);
    if let Ok(bytes) = cipher_prev.decrypt(nonce, ciphertext) {
        return String::from_utf8(bytes).ok().map(|s| s + " [延迟]");
    }

    None
}