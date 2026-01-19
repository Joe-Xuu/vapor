// 引入我们需要用到的模块
mod security; // 负责加密、解密、密钥交换
mod pow;      // 负责挖矿、验矿

use futures::stream::StreamExt;
use libp2p::{
    gossipsub, identity, noise, ping, swarm::NetworkBehaviour, swarm::SwarmEvent, tcp, yamux, Multiaddr, SwarmBuilder
};
use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::error::Error;
use std::hash::{Hash, Hasher};
use std::time::Duration;
use tokio::{io, io::AsyncBufReadExt};
use serde::{Deserialize, Serialize};
use std::io::Write; // 为了让 print! 立即显示，需要 flush

// === 📦 1. 定义数据包格式 ===
// 这是我们在网线上传输的实际内容
#[derive(Serialize, Deserialize, Debug)]
enum VaporPacket {
    // 🤝 握手包：把我的 X25519 公钥广播给所有人
    Handshake {
        pubkey: [u8; 32],
    },
    // 💬 消息包：包含加密内容和挖矿证明
    Message {
        target_peer_id: String, // 这封信是寄给谁的？
        ciphertext: Vec<u8>,    // 加密后的乱码
        nonce: Vec<u8>,         // 解密需要的随机数
        pow_proof: u64,         // ⛏️ 工作量证明 (Nonce)
    }
}

// === 🧩 2. 定义网络行为 ===
// 把 "聊天(Gossipsub)" 和 "心跳(Ping)" 捆绑在一起
#[derive(NetworkBehaviour)]
struct MyBehaviour {
    gossipsub: gossipsub::Behaviour,
    ping: ping::Behaviour,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // --- 🔑 初始化阶段 ---

    // 1. 生成 P2P 身份 (用于网络层签名)
    let local_key = identity::Keypair::generate_ed25519();
    let local_peer_id = local_key.public().to_peer_id();
    
    // 2. 生成加密身份 (用于端对端加密)
    // my_secret: 私钥，永远留在本地
    // my_public: 公钥，等会儿要发出去
    let (my_secret, my_public) = security::generate_ecdh_keys();
    
    // 3. 内存账本：记录 "PeerID -> 共享密钥" 的映射
    // 只有和我握过手的人，才会出现在这里
    let mut peer_secrets: HashMap<String, [u8; 32]> = HashMap::new();

    println!("-------------------------------------------");
    println!("🤖 Vapor 安全节点启动");
    println!("🆔 本机 Peer ID: {:?}", local_peer_id);
    println!("🔐 加密系统就绪，等待握手...");
    println!("-------------------------------------------");

    // --- 🌐 网络配置阶段 ---

    // 配置 Gossipsub (防重放、消息ID计算)
    let message_id_fn = |message: &gossipsub::Message| {
        let mut s = DefaultHasher::new();
        message.data.hash(&mut s);
        gossipsub::MessageId::from(s.finish().to_string())
    };
    let gossipsub_config = gossipsub::ConfigBuilder::default()
        .heartbeat_interval(Duration::from_secs(10))
        .validation_mode(gossipsub::ValidationMode::Strict)
        .message_id_fn(message_id_fn)
        .build()
        .expect("Gossipsub 配置失败");

    let mut gossipsub = gossipsub::Behaviour::new(
        gossipsub::MessageAuthenticity::Signed(local_key.clone()),
        gossipsub_config,
    )?;
    
    // 订阅一个公共频道
    let topic = gossipsub::IdentTopic::new("vapor-secure-room");
    gossipsub.subscribe(&topic)?;

    // 组装行为
    let behavior = MyBehaviour {
        gossipsub,
        ping: ping::Behaviour::new(ping::Config::new()),
    };

    // 构建 Swarm (管理连接的引擎)
    let mut swarm = SwarmBuilder::with_existing_identity(local_key)
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new, // 底层传输加密
            yamux::Config::default,
        )?
        .with_behaviour(|_| behavior)?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
        .build();

    // 启动监听
    swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;

    // 如果启动命令带了参数 (例如: cargo run -- /ip4/...)，就去连接对方
    if let Some(addr) = std::env::args().nth(1) {
        let remote: Multiaddr = addr.parse()?;
        swarm.dial(remote)?;
        println!("🚀 正在尝试连接远程节点...");
    }

    // 准备读取键盘输入
    let mut stdin = io::BufReader::new(io::stdin()).lines();
    println!("💬 指令: 输入 '/handshake' 交换密钥，或者直接输入内容发送");

    // --- 🔄 核心超级循环 ---
    loop {
        // tokio::select! 宏允许我们同时等待 "键盘输入" 和 "网络消息"
        tokio::select! {
            // 👉 情况 1: 键盘输入了一行字
            Ok(Some(line)) = stdin.next_line() => {
                let line = line.trim();
                
                // --- 特殊指令: 握手 ---
                if line == "/handshake" {
                    println!("👋 正在广播我的公钥...");
                    let packet = VaporPacket::Handshake { pubkey: *my_public.as_bytes() };
                    let bytes = serde_json::to_vec(&packet).unwrap();
                    // 发送给所有人
                    if let Err(e) = swarm.behaviour_mut().gossipsub.publish(topic.clone(), bytes) {
                         println!("❌ 发送失败: {:?}", e);
                    }
                } 
                // --- 普通消息: 发送加密内容 ---
                else {
                    if peer_secrets.is_empty() {
                        println!("⚠️ 警告: 你还没和任何人握手！请先输入 '/handshake'");
                    } else {
                        // 遍历所有已知的"朋友"，给每个人单独加密发一份
                        for (target_id, shared_secret) in &peer_secrets {
                            
                            // A. 加密 (使用共享密钥 + 当前时间)
                            let (ciphertext, nonce) = security::encrypt_message(shared_secret, line);
                            
                            // B. ⛏️ 挖矿 (Proof of Work)
                            // 必须算出符合难度的 Hash 才能发送，防止垃圾邮件
                            print!("⛏️ 正在挖矿(计算PoW)..."); 
                            std::io::stdout().flush().ok(); // 强制刷新显示
                            
                            let pow_proof = pow::mine_pow(&ciphertext);
                            println!(" 完成! (Nonce: {})", pow_proof);

                            // C. 打包
                            let packet = VaporPacket::Message {
                                target_peer_id: target_id.clone(),
                                ciphertext, 
                                nonce,
                                pow_proof, // 把矿石(证明)放进去
                            };
                            let bytes = serde_json::to_vec(&packet).unwrap();
                            
                            // D. 发送
                            swarm.behaviour_mut().gossipsub.publish(topic.clone(), bytes).ok();
                        }
                        println!("📨 消息已加密并广播给 {} 个节点", peer_secrets.len());
                    }
                }
            }

            // 👉 情况 2: 网络发来了事件
            event = swarm.select_next_some() => match event {
                // 处理 Gossipsub 消息
                SwarmEvent::Behaviour(MyBehaviourEvent::Gossipsub(gossipsub::Event::Message {
                    propagation_source: peer_id,
                    message,
                    ..
                })) => {
                    // 1. 尝试把字节流解析成 JSON 数据包
                    if let Ok(packet) = serde_json::from_slice::<VaporPacket>(&message.data) {
                        match packet {
                            // 情况 A: 收到别人的握手请求
                            VaporPacket::Handshake { pubkey } => {
                                // 1. 先判断: 我是不是已经认识这个人了？
                                let is_new_friend = !peer_secrets.contains_key(&peer_id.to_string());

                                if is_new_friend {
                                    println!("🤝 收到新朋友 {:?} 的握手，正在自动回礼...", peer_id);
                                    
                                    // 2. 计算并存储共享秘密
                                    let secret = security::compute_shared_secret(&my_secret, &pubkey);
                                    peer_secrets.insert(peer_id.to_string(), secret);
                                    println!("✅ 已建立与 {:?} 的安全通道", peer_id);

                                    // 3. 自动回握 (Auto-Reply)
                                    // 既然是新朋友，我也得把我的公钥给他，不然他无法加密发给我
                                    let reply_packet = VaporPacket::Handshake { pubkey: *my_public.as_bytes() };
                                    let bytes = serde_json::to_vec(&reply_packet).unwrap();
                                    
                                    // 发送！
                                    swarm.behaviour_mut().gossipsub.publish(topic.clone(), bytes).ok();
                                } else {
                                    println!("👋 收到老熟人 {:?} 的握手 (已忽略)", peer_id);
                                }
                            },
                                                        
                            // B. 收到加密消息
                            VaporPacket::Message { target_peer_id, ciphertext, nonce, pow_proof } => {
                                // 先判断: 这是发给我的吗？
                                if target_peer_id == local_peer_id.to_string() {
                                    
                                    // 🛡️ 第一道防线: 验矿 (PoW)
                                    // 如果算力证明不对，直接丢弃，不消耗 CPU 去解密
                                    if !pow::verify_pow(&ciphertext, pow_proof) {
                                        println!("⛔ 拦截到一个垃圾请求 (PoW验证失败) 来自 {:?}", peer_id);
                                        // 结束本次处理，不继续解密
                                        continue; 
                                    }

                                    // 🛡️ 第二道防线: 解密
                                    if let Some(secret) = peer_secrets.get(&peer_id.to_string()) {
                                        match security::decrypt_message(secret, &ciphertext, &nonce) {
                                            Some(text) => println!("🔓 [{:?}]: {}", peer_id, text),
                                            None => println!("🗑️ 收到 {:?} 的消息，但解密失败 (密钥过期或篡改)", peer_id),
                                        }
                                    } else {
                                        println!("❓ 收到消息，但我和 {:?} 还没握手，无法解密", peer_id);
                                    }
                                }
                                // 如果不是发给我的，直接忽略 (保护隐私)
                            }
                        }
                    }
                }
                
                // 打印监听地址
                SwarmEvent::NewListenAddr { address, .. } => println!("👂 监听地址: {:?}", address),
                
                // 忽略其他无关事件
                _ => {} 
            }
        }
    }
}