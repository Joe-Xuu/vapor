#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod security;
mod pow;

use libp2p::{
    gossipsub, identity, noise, ping, swarm::NetworkBehaviour, swarm::SwarmEvent, tcp, yamux, Multiaddr, SwarmBuilder
};
use libp2p::futures::StreamExt;
use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::time::Duration;
use serde::{Deserialize, Serialize};
use tauri::{Manager, State, Emitter}; // 💡 Emitter 在这里
use tokio::sync::mpsc; 

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

// 🧩 新增了 Dial (拨号) 指令
enum LocalCommand {
    Handshake,
    SendMsg { msg: String }, 
    Dial { addr: String }, 
}

struct AppState {
    tx: mpsc::Sender<LocalCommand>,
}

#[tauri::command]
async fn do_handshake(state: State<'_, AppState>) -> Result<(), String> {
    state.tx.send(LocalCommand::Handshake).await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn send_p2p_message(state: State<'_, AppState>, _target_id: String, msg: String) -> Result<(), String> {
    state.tx.send(LocalCommand::SendMsg { msg }).await.map_err(|e| e.to_string())
}

// 🧩 供前端调用的拨号 API
#[tauri::command]
async fn connect_to_node(state: State<'_, AppState>, addr: String) -> Result<(), String> {
    state.tx.send(LocalCommand::Dial { addr }).await.map_err(|e| e.to_string())
}

fn main() {
    let (tx, mut rx) = mpsc::channel::<LocalCommand>(100);

    tauri::Builder::default()
        .manage(AppState { tx })
        // 注册拨号 API
        .invoke_handler(tauri::generate_handler![do_handshake, send_p2p_message, connect_to_node])
        .setup(|app| {
            let window = app.get_webview_window("main").unwrap();

            tauri::async_runtime::spawn(async move {
                let local_key = identity::Keypair::generate_ed25519();
                let local_peer_id = local_key.public().to_peer_id();
                let (my_secret, my_public) = security::generate_ecdh_keys();
                let mut peer_secrets: HashMap<String, [u8; 32]> = HashMap::new();

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
                    .unwrap();

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
                    .with_tcp(tcp::Config::default(), noise::Config::new, yamux::Config::default).unwrap()
                    .with_behaviour(|_| behavior).unwrap()
                    .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
                    .build();

                // 💡 关键：强制把端口固定在 11223！不再随机瞎猜了！
                swarm.listen_on("/ip4/0.0.0.0/tcp/11223".parse().unwrap()).unwrap();

                loop {
                    tokio::select! {
                        Some(cmd) = rx.recv() => {
                            match cmd {
                                LocalCommand::Dial { addr } => {
                                    if let Ok(remote) = addr.parse::<Multiaddr>() {
                                        if let Err(e) = swarm.dial(remote) {
                                            window.emit("system-msg", format!("❌ 拨号失败: {:?}", e)).unwrap();
                                        }
                                    } else {
                                        window.emit("system-msg", "❌ 地址格式错误 (应类似 /ip4/192.../tcp/11223)".to_string()).unwrap();
                                    }
                                }
                                LocalCommand::Handshake => {
                                    let packet = VaporPacket::Handshake { pubkey: *my_public.as_bytes() };
                                    let bytes = serde_json::to_vec(&packet).unwrap();
                                    swarm.behaviour_mut().gossipsub.publish(topic.clone(), bytes).ok();
                                }
                                LocalCommand::SendMsg { msg } => {
                                    for (target_id, shared_secret) in &peer_secrets {
                                        let (ciphertext, nonce) = security::encrypt_message(shared_secret, &msg);
                                        let pow_proof = pow::mine_pow(&ciphertext);
                                        let packet = VaporPacket::Message { target_peer_id: target_id.clone(), ciphertext, nonce, pow_proof };
                                        let bytes = serde_json::to_vec(&packet).unwrap();
                                        swarm.behaviour_mut().gossipsub.publish(topic.clone(), bytes).ok();
                                    }
                                }
                            }
                        }

                        event = swarm.select_next_some() => {
                            match event {
                                // 💡 监听底层网络连接成功事件，并推送到 UI！
                                SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                                    window.emit("system-msg", format!("✅ 物理链路打通! 探测到节点: {}...", &peer_id.to_string()[..6])).unwrap();
                                }
                                SwarmEvent::Behaviour(MyBehaviourEvent::Gossipsub(gossipsub::Event::Message { propagation_source: peer_id, message, .. })) => {
                                    if let Ok(packet) = serde_json::from_slice::<VaporPacket>(&message.data) {
                                        match packet {
                                            VaporPacket::Handshake { pubkey } => {
                                                if !peer_secrets.contains_key(&peer_id.to_string()) {
                                                    let secret = security::compute_shared_secret(&my_secret, &pubkey);
                                                    peer_secrets.insert(peer_id.to_string(), secret);
                                                    window.emit("system-msg", "🤝 收到新朋友公钥，后台自动回礼...".to_string()).unwrap();
                                                    
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
                                                                window.emit("p2p-message", MessagePayload { peer_id: peer_id.to_string(), msg: text }).unwrap();
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                                _ => {}
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