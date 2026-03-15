// 防止在 Windows 生产环境运行时弹出背后黑乎乎的命令行窗口
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod security;
mod pow;

use libp2p::{
    gossipsub, identity, noise, ping, swarm::NetworkBehaviour, swarm::SwarmEvent, tcp, yamux, Multiaddr, SwarmBuilder
};
use libp2p::futures::StreamExt; // 💡 补上刚才漏掉的流处理特质 (解决报错2)
use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::time::Duration;
use serde::{Deserialize, Serialize};
use tauri::{Manager, State, Emitter}; // 💡 加上 Emitter
use tokio::sync::mpsc; 

// === 📦 1. 数据包定义 (网线上传输的格式) ===
#[derive(Serialize, Deserialize, Debug)]
enum VaporPacket {
    Handshake { pubkey: [u8; 32] },
    Message { target_peer_id: String, ciphertext: Vec<u8>, nonce: Vec<u8>, pow_proof: u64 }
}

#[derive(Clone, Serialize)]
struct MessagePayload {
    peer_id: String,
    msg: String,
}

#[derive(NetworkBehaviour)]
struct MyBehaviour {
    gossipsub: gossipsub::Behaviour,
    ping: ping::Behaviour,
}

// === 🧩 2. 内部邮局：定义前端给后端的指令信件 ===
enum LocalCommand {
    Handshake,
    SendMsg { msg: String }, 
}

struct AppState {
    tx: mpsc::Sender<LocalCommand>,
}

// === 🌐 3. 供前端 JS 调用的接口 (Tauri Commands) ===

#[tauri::command]
async fn do_handshake(state: State<'_, AppState>) -> Result<(), String> {
    state.tx.send(LocalCommand::Handshake).await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn send_p2p_message(state: State<'_, AppState>, _target_id: String, msg: String) -> Result<(), String> {
    // 💡 _target_id 加了下划线，消除未使用变量的警告
    state.tx.send(LocalCommand::SendMsg { msg }).await.map_err(|e| e.to_string())
}

// === 🚀 4. 主程序入口 ===
fn main() {
    let (tx, mut rx) = mpsc::channel::<LocalCommand>(100);

    tauri::Builder::default()
        .manage(AppState { tx })
        .invoke_handler(tauri::generate_handler![do_handshake, send_p2p_message])
        .setup(|app| {
            // 💡 修复报错1：Tauri v2 的新版窗口获取 API
            let window = app.get_webview_window("main").unwrap();

            tauri::async_runtime::spawn(async move {
                
                let local_key = identity::Keypair::generate_ed25519();
                let local_peer_id = local_key.public().to_peer_id();
                let (my_secret, my_public) = security::generate_ecdh_keys();
                let mut peer_secrets: HashMap<String, [u8; 32]> = HashMap::new();

                println!("🤖 Vapor GUI 节点启动 | ID: {:?}", local_peer_id);
                window.emit("my-peer-id", local_peer_id.to_string()).unwrap();

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
                ).unwrap();
                
                let topic = gossipsub::IdentTopic::new("vapor-secure-room");
                gossipsub.subscribe(&topic).unwrap();

                let behavior = MyBehaviour {
                    gossipsub,
                    ping: ping::Behaviour::new(ping::Config::new()),
                };

                let mut swarm = SwarmBuilder::with_existing_identity(local_key)
                    .with_tokio()
                    .with_tcp(
                        tcp::Config::default(),
                        noise::Config::new,
                        yamux::Config::default,
                    ).unwrap()
                    .with_behaviour(|_| behavior).unwrap()
                    .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
                    .build();

                swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse().unwrap()).unwrap();

                if let Some(addr) = std::env::args().nth(1) {
                    if let Ok(remote) = addr.parse::<Multiaddr>() {
                        swarm.dial(remote).ok();
                        println!("🚀 正在尝试连接远程节点...");
                    }
                }

                loop {
                    tokio::select! {
                        Some(cmd) = rx.recv() => {
                            match cmd {
                                LocalCommand::Handshake => {
                                    println!("👋 响应前端请求：广播公钥...");
                                    let packet = VaporPacket::Handshake { pubkey: *my_public.as_bytes() };
                                    let bytes = serde_json::to_vec(&packet).unwrap();
                                    swarm.behaviour_mut().gossipsub.publish(topic.clone(), bytes).ok();
                                }
                                LocalCommand::SendMsg { msg } => {
                                    for (target_id, shared_secret) in &peer_secrets {
                                        let (ciphertext, nonce) = security::encrypt_message(shared_secret, &msg);
                                        
                                        println!("⛏️ 后台正在为界面发来的消息进行 PoW 挖矿...");
                                        let pow_proof = pow::mine_pow(&ciphertext);
                                        
                                        let packet = VaporPacket::Message {
                                            target_peer_id: target_id.clone(),
                                            ciphertext,
                                            nonce,
                                            pow_proof,
                                        };
                                        let bytes = serde_json::to_vec(&packet).unwrap();
                                        swarm.behaviour_mut().gossipsub.publish(topic.clone(), bytes).ok();
                                    }
                                }
                            }
                        }

                        event = swarm.select_next_some() => {
                            if let SwarmEvent::Behaviour(MyBehaviourEvent::Gossipsub(gossipsub::Event::Message { propagation_source: peer_id, message, .. })) = event {
                                if let Ok(packet) = serde_json::from_slice::<VaporPacket>(&message.data) {
                                    match packet {
                                        VaporPacket::Handshake { pubkey } => {
                                            if !peer_secrets.contains_key(&peer_id.to_string()) {
                                                println!("🤝 收到新朋友握手，后台自动回礼...");
                                                let secret = security::compute_shared_secret(&my_secret, &pubkey);
                                                peer_secrets.insert(peer_id.to_string(), secret);
                                                
                                                let reply_packet = VaporPacket::Handshake { pubkey: *my_public.as_bytes() };
                                                let bytes = serde_json::to_vec(&reply_packet).unwrap();
                                                swarm.behaviour_mut().gossipsub.publish(topic.clone(), bytes).ok();
                                            }
                                        }
                                        VaporPacket::Message { target_peer_id, ciphertext, nonce, pow_proof } => {
                                            if target_peer_id == local_peer_id.to_string() {
                                                if pow::verify_pow(&ciphertext, pow_proof) {
                                                    if let Some(secret) = peer_secrets.get(&peer_id.to_string()) {
                                                        if let Some(text) = security::decrypt_message(secret, &ciphertext, &nonce) {
                                                            println!("🔓 后台解密成功！正在推送给前端界面...");
                                                            window.emit("p2p-message", MessagePayload {
                                                                peer_id: peer_id.to_string(),
                                                                msg: text,
                                                            }).unwrap();
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            });
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("运行 Tauri 应用失败");
}