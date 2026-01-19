## motivation: 我想做一个特别安全的开源chat工具 WIP

- 身份层,Ed25519,数字签名。基于 Edwards 曲线。比 RSA 快得多且密钥极短。保证了没人能冒充身份发消息。

- 传输层,Noise Protocol (XX Handshake),管道加密。类似于 TLS，但更轻量。这是 libp2p 底层自带的，保证了即便没有握手，节点间的 TCP 连接也是加密的。

- 密钥协商,X25519 (ECDH),密钥交换。Diffie-Hellman 的椭圆曲线版本。允许陌生人在公开信道协商出共享秘密。

- 载荷加密,AES-256-GCM,认证加密。军工级对称加密。不仅加密内容，还验证数据integrity（防篡改）。

- 密钥衍生,HKDF (Time-based),密钥回旋。SHA-256 加时间戳作为随机因子，每 10 秒生成新密钥，销毁旧密钥。

- 反垃圾,SHA-256 PoW,工作量证明。类似比特币挖矿。

## vision 我的目标
- trustless: 不需要任何中间服务器。因为根本没有服务器。

- Censorship Resistant: 只要互联网没被物理切断，节点之间就能通过 Mesh 网络绕过封锁传递消息。没有网线可以拔

- Perfect Forward Secrecy: 这是最大的卖点。即便攻击者录下了所有加密流量，并在这个月之后偷到了你的私钥，他也解不开上个月的消息。因为密钥马上就变了。

- Metadata Privacy: 配合 Gossipsub 广播，攻击者很难知道“谁在和谁说话”。因为消息是向全网广播的，只有持有私钥的人能看懂。

- Anti-Spam: 内置 PoW 机制，让发送垃圾广告变得极其昂贵。

co-created with Google Gemini, Kouzen Jo 2025