# Wi-Fi 攻击手法总览（2026 版）

> 本文档是 **Wraith Wi-Fi 渗透测试平台** 的能力地图与设计依据。
> 数据来源：GitHub 仓库检索 + 802.11 协议规范 + 公开安全研究（Vanhoef 等）。
> GitHub 星标数为 2026-10 检索快照，仅用于判断生态活跃度，不代表工具质量。
>
> ⚠️ **仅限授权测试**。对非自有网络实施下列任何操作，在绝大多数司法辖区均属违法
> （中国《网络安全法》第 27 条、《刑法》285/286 条；美国 CFAA；欧盟 NIS2 等）。
> 平台内置授权门禁与审计日志，但最终责任在使用者。

---

## 1. 攻击面模型

Wi-Fi 的攻击面可以按"协议栈层次 × 认证阶段"拆解，本平台的所有模块都落在这张图上：

```
┌──────────────────────────────────────────────────────────────────────┐
│ L7  门户/认证页面   │ 钓鱼登录页、凭证收割、MFA 转发、恶意文件        │
├─────────────────────┼───────────────────────────────────────────────┤
│ L5-6 认证隧道       │ EAP 方法降级、MSCHAPv2 抓取、EAP 中继          │
├─────────────────────┼───────────────────────────────────────────────┤
│ L3-4 网络层         │ 流氓 DHCP/DNS、网关劫持、透明代理、DNS 隧道    │
├─────────────────────┼───────────────────────────────────────────────┤
│ L2  关联/认证       │ 邪恶双胞胎、Karma/MANA、WPS、SAE 降级          │
├─────────────────────┼───────────────────────────────────────────────┤
│ L1  管理帧          │ Deauth/Disassoc、CSA、Beacon Flood、BSSID 伪造 │
├─────────────────────┼───────────────────────────────────────────────┤
│ L0  射频            │ 干扰、信道压制、射频指纹                        │
└─────────────────────┴───────────────────────────────────────────────┘
```

按目标加密类型划分的**可行路径**：

| 目标加密 | 首选路径 | 备选路径 |
|---|---|---|
| OPEN | 直接接入 → 内网横向、门户绕过 | 邪恶双胞胎（同名 AP 劫持） |
| WEP | ARP Replay / ChopChop / Fragmentation → aircrack-ng | PTW 统计攻击（少量 IV 即可） |
| WPA/WPA2-PSK | 抓 4 次握手 → 字典/规则爆破 | PMKID 无客户端捕获；WPS 取 PSK |
| WPA2/WPA3 过渡模式 | **降级为 WPA2** → 抓握手/PMKID | Dragonblood 侧信道（需大量 SAE 交互） |
| WPA3-SAE（纯） | 在线猜测（受 SAE 抗离线爆破保护）| 侧信道 + 弱口令；DoS 干扰 |
| WPA2-Enterprise | 邪恶双胞胎 + EAP 降级 → 抓 MSCHAPv2 → 爆破 | EAP 中继（wpa_sycophant）；证书校验缺陷 |
| WPS 开启 | Pixie Dust（离线，秒级） | PIN 在线爆破（约 1.1 万次） |

---

## 2. 侦察与信息收集

### 2.1 被动扫描（Beacon / Probe 监听）

无需发包，隐蔽性最好。监听 Beacon 帧获取 SSID/BSSID/信道/加密套件/WPS 状态，
监听 Probe Request 获取客户端**首选网络列表（PNL）**——这是邪恶双胞胎选 SSID 的关键情报。

- **airodump-ng**（[aircrack-ng/aircrack-ng](https://github.com/aircrack-ng/aircrack-ng) ★7.8k）
  `airodump-ng -w cap --output-format csv,pcapng wlan0mon`
- **Kismet**（[kismetwireless/kismet](https://github.com/kismetwireless/kismet) ★2.2k）带 GPS 的
  wardriving、分布式传感器、802.11 解码最全。
- **bettercap**（[bettercap/bettercap](https://github.com/bettercap/bettercap) ★20.2k）
  `wifi.recon on`，交互式 802.11 侦察与后续 MITM 一体化。

### 2.2 主动扫描（Probe Request / 关联探测）

- 发送 Probe Request 探测隐藏 SSID（`mdk4 p`、`wifite --probe`）。
- **隐藏 SSID 不等于安全**：客户端关联时会明文暴露 SSID，被动等即可。
- **Wardriving**：GPS + 扫描，生成覆盖热力图（wigle.net 生态）。

### 2.3 客户端指纹

由 Probe Request 的 IE 顺序、Supported Rates、HT/VHT/HE Capabilities 推断设备型号，
用于选择"对哪台设备下手"（例如优先攻击未打补丁的 IoT）。

---

## 3. WEP（历史协议，仍存在于老旧设备/IoT）

WEP 的 IV 只有 24 bit，RC4 密钥流复用导致统计攻击。现代工具 1~5 万包即可破。

| 手法 | 原理 | 工具 |
|---|---|---|
| **ARP Replay** | 捕获 ARP 后重放，强制 AP 快速产生新 IV | `aireplay-ng -3` |
| **ChopChop** | 逐字节截断加密包，恢复密钥流 | `aireplay-ng -4` |
| **Fragmentation** | 利用分片重组获取密钥流（PRGA） | `aireplay-ng -5` |
| **Caffe Latte** | 无客户端，基于 ARP 的客户端攻击 | `aireplay-ng -6` |
| **Hirte** | 分片 + 客户端，无需 ARP | `aireplay-ng -7` |
| **PTW** | 统计攻击，4 万包左右即可 | `aircrack-ng -z` |
| **KoreK** | 利用 802.11 头部字节猜测密钥 | `aircrack-ng -K` |

> WEP 已无任何安全价值，但仍是**授权测试中的高频发现项**（合规扫描必报）。

---

## 4. WPA/WPA2-PSK

### 4.1 四次握手捕获（4-Way Handshake）

WPA2-PSK 的密钥派生链：

```
PSK = PBKDF2-SHA1(passphrase, SSID, 4096, 256)
PMK = PSK
PTK = PRF-X(PMK, ANonce, SNonce, AP_MAC, STA_MAC)
```

抓到 **M1+M2（或 M2+M3）** 即可离线验证候选口令：用候选 PSK 重算 PTK，
校验 M2 的 MIC。**握手本身不泄露口令**，安全性完全依赖口令强度。

- 流程：锁定 BSSID/信道 → `airodump-ng -c CH --bssid XX -w cap` → `aireplay-ng --deauth`
  踢客户端触发重连 → 检测 EAPOL 中的握手完成标志。
- 工具：**wifite2**（★8.2k，全自动）、**airgeddon**（★8.1k，菜单式全流程）、
  **WiFiBroot**（★1.1k，握手+PMKID+自定义字典）、**airbash**（★371，自动化）、
  **dwpa**（★381，分布式破解）。

### 4.2 PMKID 无客户端攻击（2018，Jens Steube）

AP 在 EAPOL M1 的 RSN IE 中可能携带 PMKID：

```
PMKID = HMAC-SHA1-128(PMK, "PMK Name" || AP_MAC || STA_MAC)
```

只需向 AP 发一个关联请求并读取 M1，即可获得可离线爆破的 PMKID —— **无需客户端、
无需 deauth、单帧完成**，隐蔽性极高。但并非所有 AP 都返回 PMKID（取决于厂商实现）。

- 工具：**hcxdumptool**（★2.2k）+ **hcxtools**（★2.5k）→ `hashcat -m 22000`
- **pmkidcracker**（★236）、**ESP32-WiFi-Hash-Monster**（★1.1k，硬件化）
- 这是 WPA2 时代**性价比最高的攻击**，也是本平台的一等公民模块。

### 4.3 离线爆破

- `aircrack-ng -w rockyou.txt cap` — CPU，简单直接，支持 PMKID 22000。
- `hashcat -m 22000` — GPU，规则引擎（`-r best64.rule`）、掩码、混合攻击。
- 现代 GPU 对 WPA2 的速率约 10^6 ~ 10^7 H/s 量级；8 位以上随机口令基本不可破。
- 优化：SSID 相关词表、企业名/电话/生日组合、`hashcat --stdout` 管道。

### 4.4 WPS（Wi-Fi Protected Setup）

WPS 的 PIN 认证存在设计缺陷：PIN 分两段校验，爆破空间从 10^8 降到 **11,000** 次；
且 EAP-WSC 的 nonce 生成若熵不足，可**离线破解**（Pixie Dust）。

| 手法 | 说明 | 工具 |
|---|---|---|
| **Pixie Dust** | 利用弱随机数离线推导 PIN/PSK，通常 <10 秒 | `reaver -K 1`、`pixiewps`、`OneShot` |
| **PIN 在线爆破** | 约 11,000 次尝试，需处理锁死/限速 | `reaver`、`bully` |
| **PIN 预测** | 部分厂商 PIN 由 MAC/序列号推导 | `wpspin`、`OneShot-C` |
| **WPS 锁死绕过** | 重启 AP、MAC 轮换、等待窗口 | `reaver --no-nacks` 等 |

- **reaver-wps-fork-t6x**（★2.0k）、**bully**（★578）、**pixiewps**（★1.8k）。
- WPS 2.0 / 802.11w 之后多数新设备已默认关闭 WPS，但存量设备仍多。

---

## 5. WPA3 / SAE

WPA3-Personal 用 **SAE（Simultaneous Authentication of Equals，Dragonfly 握手）** 替代 PSK 握手，
核心价值是**抗离线字典攻击**：每次猜测都需要与 AP 实时交互。

### 5.1 Dragonblood（2019，Vanhoef & Ronen）

- **侧信道**：SAE 的 commit/confirm 时序与缓存特征泄露口令分组信息，
  可将搜索空间按组削减（password partitioning）。
- **降级攻击**：利用 **WPA2/WPA3 过渡模式**，伪造同名 WPA2-only 邪恶双胞胎，
  客户端为兼容而回落 WPA2 → 回到 §4 的握手/PMKID 攻击。
- **DoS**：大量 SAE Commit 洪泛耗尽 AP 资源。
- 仓库：[vanhoefm/dragonblood](https://github.com/vanhoefm/dragonblood) ★34（研究代码）、
  **DragonShift**(★71)、**AirBully**(★10) 自动化过渡模式降级；
  ESP32 方案 **projectZero**(★225) 甚至实现了 SAE Overflow。

### 5.2 过渡模式降级（实战主线）

1. 侦察发现 `WPA2/WPA3` 混合模式（Beacon 的 RSN IE 同时含 PSK 与 SAE AKM）。
2. 起一个 **WPA2-PSK 邪恶双胞胎**（同 SSID、更强信号）。
3. Deauth/CSA 把客户端从正牌 AP 挤走，客户端回落到 WPA2 双胞胎。
4. 客户端用 WPA2 握手 → 抓 M2 → 离线爆破（或诱导输入 PSK）。

### 5.3 WPA3 的其他面

- **SAE-PK**（Wi-Fi 6 Release 3）：用公私钥替代口令，抗离线猜测；但配置复杂，落地少。
- **H2E（Hash-to-Element）**：修复了 Hunting-and-Pecking 的侧信道，但未普及。
- **PMF 强制**：WPA3 强制 802.11w，传统 deauth 失效 → 转向 **CSA 攻击**（伪造信道切换通告）
  或利用未受保护的广播帧/驱动缺陷。
- **Wi-Fi 7 MLO**：多链路并行带来新的跨链路状态同步与降级面，学术研究阶段。
- **纯 WPA3 无捷径**：只能在线猜测（受速率限制）或依赖实现漏洞/弱口令。

---

## 6. WPA2-Enterprise（802.1X/EAP）

企业网的安全假设是"客户端会校验证书"。现实中大量客户端**不校验证书**或允许用户一键信任，
于是邪恶双胞胎可以冒充 RADIUS 服务器骗取凭证。

### 6.1 攻击链

```
伪造 AP（同 SSID） + 内置 RADIUS（EAP 服务端）
        ↓ 客户端关联
EAP 协商 → 降级到弱方法（GTC / MSCHAPv2）
        ↓
捕获 MSCHAPv2 Challenge/Response → hashcat -m 5500 爆破
或 EAP-GTC 直接拿到明文口令
或 EAP-TLS 中继到真实 AP（wpa_sycophant）
```

### 6.2 工具

- **EAPHammer**（[s0lst1c3/eaphammer](https://github.com/s0lst1c3/eaphammer) ★2.6k）：
  一条命令起企业级邪恶双胞胎，自动生成证书、hostapd-wpe 配置、捕获凭证。
- **hostapd-mana**（[sensepost/hostapd-mana](https://github.com/sensepost/hostapd-mana) ★637）：
  支持 MANA/Karma、EAP 方法降级、GTC 明文捕获。
- **wpa_sycophant**：EAP 中继——攻击者同时扮演"客户端的 AP"和"AP 的客户端"，
  把受害者认证流量转发给真实 AP，可绕过证书校验（需要受害者与真实 AP 均可达）。
- **wifipumpkin3**（★2.5k）也带企业门户与凭证收割能力。

### 6.3 证书校验绕过点

- 客户端未校验 CA → 直接冒充。
- 校验了 CA 但未校验 CN/SAN → 用任意合法证书。
- 允许"手动信任未知证书"的 UI → 社工点击。
- EAP-TTLS/PAP 内层明文 → 直接抓密码。

---

## 7. 邪恶双胞胎 / 流氓 AP / 门户钓鱼

伪造与目标**同 SSID（甚至同 BSSID）**的 AP，信号更强，诱导客户端自动关联，
再通过 DHCP/DNS/门户实施劫持。

| 变体 | 关键点 | 工具 |
|---|---|---|
| **经典 Evil Twin** | 同 SSID + 更强信号 + Deauth 助攻 | **wifiphisher**（★14.9k）、wifipumpkin3、Fluxion（★6.0k） |
| **Captive Portal 钓鱼** | 假登录页收割 Wi-Fi/邮箱/AD 密码；支持 MFA 转发 | wifiphisher、wifipumpkin3（Phishkin3） |
| **EvilQR** | 诱导扫码连入恶意热点 | wifipumpkin3 EvilQR3 |
| **Karma / MANA** | 响应**任意** Probe Request，来者不拒 | hostapd-mana、bettercap |
| **Known Beacon** | 用 PNL 中的 SSID 批量广播，精准钓特定设备 | wifiphisher、mdk4 |
| **同 BSSID 克隆** | 让客户端无法区分正牌/伪造 | hostapd + macchanger |
| **企业版 Evil Twin** | 见 §6 | eaphammer、hostapd-mana |

门户钓鱼的技术要点：

1. **强制门户检测劫持**：客户端会请求 `connectivitycheck.gstatic.com`、
   `captive.apple.com`、`www.msftconnecttest.com`，DNS 通配劫持到本地门户即可自动弹窗。
2. **凭证收集**：POST 到本地服务，落库并实时推送控制台。
3. **MFA 中转**：门户代理真实 SSO 页面（Phishkin3/Evilginx 思路），实时转发 OTP。
4. **Post-exploitation**：拿到 PSK 后可直接连回正牌网络；拿到域凭证可横向。

> 平台内置门户服务与凭证收割，但**默认模板仅做演示**，不内置真实品牌仿冒页面。

---

## 8. 管理帧与 L2 攻击

| 手法 | 说明 | 缓解 | 工具 |
|---|---|---|---|
| **Deauth / Disassoc** | 伪造解除认证帧，踢客户端下线；可定向或广播 | 802.11w (PMF) 保护单播 | `aireplay-ng --deauth`、`mdk4 d` |
| **CSA 攻击** | 伪造 Channel Switch Announcement，把客户端赶到攻击者控制的信道/AP | 较难，需驱动/固件支持 | `mdk4`、Scapy 自研 |
| **Beacon Flood** | 海量伪造 Beacon，客户端列表污染、部分设备崩溃 | 无 | `mdk4 b`、`esp8266_deauther` |
| **Auth Flood** | 大量认证请求耗尽 AP 关联表 | 无 | `mdk4 a` |
| **Probe Flood** | 伪造 Probe Request 污染 AP 日志/耗尽资源 | 无 | `mdk4 p` |
| **BSSID 伪造** | 克隆 MAC 冒充 AP | 无 | `macchanger` |
| **Evil Twin + Deauth 组合** | 先踢后钓，成功率最高 | PMF + WIDS | airgeddon / wifiphisher |
| **WIDS 规避** | 低速率、随机 MAC、信道跳变、只发必要帧 | — | 平台内置速率限制 |

---

## 9. 协议实现漏洞（研究级）

| 漏洞 | 年份 | 影响 | 说明 | 仓库 |
|---|---|---|---|---|
| **KRACK** | 2017 | WPA2 全系 | 四次握手/组密钥/FT 的密钥重装 → nonce 复用 → 解密、注入 | [vanhoefm/krackattacks-scripts](https://github.com/vanhoefm/krackattacks-scripts) ★3.5k |
| **KR00K** | 2020 | Broadcom/Cypress 芯片 | 断开关联后 TK 被清零，缓冲帧用全零密钥加密 → 解密 | 研究论文 |
| **FragAttacks** | 2021 | WPA2/WPA3 全系 | 分片缓存、混合密钥、聚合帧 → 注入明文帧 | [vanhoefm/fragattacks](https://github.com/vanhoefm/fragattacks) ★1.3k |
| **Dragonblood** | 2019 | WPA3 | 侧信道 + 降级 + DoS | 见 §5 |
| **SSID 混淆 / 剥离** | 2020+ | 部分客户端 | 同名/空 SSID 诱导误连 | 自研 |
| **FT 快速漫游** | 2017+ | 802.11r | FT-PMKID 重用、降级到非 FT | 研究 |
| **WPS 实现缺陷** | 持续 | 大量 IoT | 锁死绕过、PIN 预测、熵不足 | pixiewps |

> 这些漏洞的验证代码多为"测试脚本"而非武器化攻击，平台以**检测/验证**方式集成，
> 不内置会破坏生产网络的攻击载荷。

---

## 10. 硬件化与近源

| 平台 | 代表项目 | 能力 |
|---|---|---|
| ESP8266 | [SpacehuhnTech/esp8266_deauther](https://github.com/SpacehuhnTech/esp8266_deauther) ★15.0k | Deauth、Beacon Flood、探测 |
| ESP32 | [risinek/esp32-wifi-penetration-tool](https://github.com/risinek/esp32-wifi-penetration-tool) ★3.1k | Deauth、握手/PMKID 捕获、 Evil Twin |
| ESP32-S3/C5 | [M0M0Sec/MoMo](https://github.com/M0M0Sec/MoMo) ★33、[C5Lab/projectZero](https://github.com/C5Lab/projectZero) ★225 | WPA3 溢出、Karma、Wardriving |
| WiFi Pineapple | Hak5 | 一站式流氓 AP + 模块市场 |
| Raspberry Pi | [blackhillsinfosec/WifiForge](https://github.com/blackhillsinfosec/WifiForge) ★1.2k、[r4ulcl/WiFiChallengeLab-docker](https://github.com/r4ulcl/WiFiChallengeLab-docker) ★437 | 教学靶场、`mac80211_hwsim` 虚拟无线 |
| Flipper Zero | 社区固件 | Sub-GHz/BLE/NFC + Wi-Fi 开发板 |

近源攻击的现实意义：物理接近即可绕过边界防护；结合**定向天线**可显著提升距离。

---

## 11. 工具生态矩阵（GitHub 快照）

| 工具 | ★ | 语言 | 定位 | 本平台集成方式 |
|---|---:|---|---|---|
| bettercap | 20.2k | Go | 802.11/BLE/MITM 瑞士军刀 | 侦察参考 |
| hashcat | 27.0k | C | GPU 破解（22000/5500） | 直接调用 |
| wifiphisher | 14.9k | Python | 流氓 AP + 钓鱼 | 门户模板参考 |
| esp8266_deauther | 15.0k | C++ | 硬件 Deauth | 硬件协同 |
| wifite2 | 8.2k | Python | 全自动审计 | 流程参考 |
| airgeddon | 8.1k | Bash | 全流程菜单 | 流程参考 |
| aircrack-ng | 7.8k | C | 抓包/注入/破解套件 | 直接调用 |
| fluxion | 6.0k | Bash | Evil Twin + 门户 | 流程参考 |
| krackattacks-scripts | 3.5k | Python | KRACK 验证 | 检测模块 |
| risinek/esp32-wifi-pentest | 3.1k | C++ | ESP32 攻击平台 | 硬件协同 |
| eaphammer | 2.6k | Python | 企业级 Evil Twin | 直接调用 |
| wifipumpkin3 | 2.5k | Python | 流氓 AP 框架 | 流程参考 |
| hcxtools | 2.5k | C | 抓包转 hash | 直接调用 |
| kismet | 2.2k | C++ | 无线侦察/IDS | 数据源参考 |
| hcxdumptool | 2.2k | C | PMKID/握手捕获 | 直接调用 |
| reaver-wps-fork-t6x | 2.0k | C | WPS 攻击 | 直接调用 |
| pixiewps | 1.8k | C | Pixie Dust 离线 | 直接调用 |
| fragattacks | 1.3k | Python | FragAttacks 验证 | 检测模块 |
| WifiForge | 1.2k | Shell | Wi-Fi 靶场 | 实验环境 |
| bully | 578 | C | WPS 攻击替代 | 直接调用 |
| hostapd-mana | 637 | C | Karma/EAP 降级 | 直接调用 |
| mdk4 | 813 | C | 管理帧洪泛 | 直接调用 |
| wifijammer | 4.3k | Python | 持续 Deauth | 参考 |

---

## 12. 攻击可行性速查

| 目标条件 | 可行手法 | 预计耗时 | 成功率 |
|---|---|---|---|
| WEP | ARP Replay + PTW | 5–30 min | 极高 |
| WPA2 + 有客户端 | Deauth + 握手 + 字典 | 取决于口令 | 中（弱口令高） |
| WPA2 + 无客户端 | PMKID（若 AP 支持） | <1 min 捕获 | 中 |
| WPA2 + WPS 开 | Pixie Dust | <1 min | 高（设备相关） |
| WPA2/WPA3 过渡 | 降级 Evil Twin + 握手 | 10–30 min | 高（客户端会回落） |
| 纯 WPA3 | 在线猜测 / 侧信道 | 极长 | 低 |
| WPA2-Enterprise | Evil Twin + EAP 降级 | 10–60 min | 中高（客户端不校验证书时） |
| OPEN | 直接接入 | 即时 | 100% |
| 任意 + 物理接近 | 门户钓鱼 / 社工 | 取决于人 | 中 |

---

## 13. 检测与防御（蓝队视角）

1. **WIDS/WIPS**：Kismet、Cisco WLC、Ubiquiti 的 Rogue AP 检测；监控 Deauth 洪泛、
   Beacon 异常、BSSID 冲突、信道跳变。
2. **802.11w (PMF)**：强制开启，阻断单播 Deauth；WPA3 必须。
3. **WPA3 + SAE-PK / 强口令**：8 位以上随机，禁用过渡模式（或至少监控降级）。
4. **关闭 WPS**，或至少升级到 WPS 2.0 并启用锁死。
5. **企业网**：强制证书校验（CA + CN/SAN）、禁用 MSCHAPv2/GTC、启用 EAP-TLS、
   部署 EAP 中继检测（同一证书多地点认证）。
6. **客户端**：关闭自动连接开放网络、禁用 PNL 广播、及时打 KRACK/FragAttacks 补丁。
7. **监控指标**：同一 SSID 多 BSSID、BSSID 与 OUI 不符、异常 Deauth 速率、
   DHCP 服务器变更、DNS 劫持、门户页面证书异常。
8. **合规**：定期授权渗透测试 + 无线风险评估（PCI DSS 要求 11.2）。

---

## 14. 平台实现映射

| 模块 ID | 名称 | 对应章节 | 依赖工具 |
|---|---|---|---|
| `recon.scan` | Beacon/Probe 扫描 | §2.1 | airodump-ng / iw |
| `recon.wps` | WPS 探测 | §4.4 | wash（reaver 套件） |
| `attack.deauth` | 定向/广播 Deauth | §8 | aireplay-ng / mdk4 |
| `attack.handshake` | 四次握手捕获 | §4.1 | airodump-ng + aireplay-ng |
| `attack.pmkid` | PMKID 捕获与转换 | §4.2 | hcxdumptool + hcxpcapngtool |
| `attack.wps_pixie` | Pixie Dust | §4.4 | reaver + pixiewps |
| `attack.wps_pin` | WPS PIN 爆破 | §4.4 | reaver / bully |
| `attack.evil_twin` | 邪恶双胞胎 + 门户 | §7 | hostapd + dnsmasq |
| `attack.karma` | Karma/MANA | §7 | hostapd-mana |
| `attack.beacon_flood` | Beacon 洪泛 | §8 | mdk4 |
| `attack.wpa3_downgrade` | 过渡模式降级 | §5.2 | hostapd + aireplay-ng |
| `attack.enterprise` | 企业级 Evil Twin | §6 | eaphammer |
| `attack.wep` | WEP IV 注入 | §3 | aireplay-ng + aircrack-ng |
| `crack.wpa` | WPA/PMKID 爆破 | §4.3 | aircrack-ng / hashcat |
| `crack.wep` | WEP 破解 | §3 | aircrack-ng |
| `crack.wps` | WPS PIN/PSK | §4.4 | reaver |
| `report` | 报告生成 | — | 内置 |

---

## 15. 参考

- Vanhoef & Piessens, *Key Reinstallation Attacks* (CCS 2017) — https://www.krackattacks.com
- Vanhoef & Ronen, *Dragonblood: A Security Analysis of WPA3's SAE Handshake* (2019) — https://wpa3.mathyvanhoef.com
- Vanhoef, *Fragment and Forge: Breaking Wi-Fi Through Frame Aggregation and Fragmentation* (USENIX 2021) — https://www.fragattacks.com
- Jens Steube, *New attack on WPA/WPA2 using PMKID* (2018) — hashcat 论坛
- Dominique Bongard, *Pixie Dust attack* (2014)
- IEEE 802.11-2020 / 802.11ax / 802.11be 规范
- Wi-Fi Alliance: WPA3 Specification v3.0
- 各工具 GitHub 仓库（见 §11 链接）

> 本文档随平台迭代更新；新增模块须同步更新 §14 映射表。
