# Wraith 冒烟测试报告 · 2026-10-21

- **环境**：Kali / kernel 6.19.14 / Python 3.13 / 网卡 mt7921u（`wlan0`，支持 managed+monitor+AP）
- **目标**：`SZ078837` → `88:5a:04:b4:e9:cb`，ch6，WPA2-PSK/CCMP，信号 -22 dBm；
  补充复测 `7a:45:35:76:cc:68`（ch44，用户确认为自有设备）
- **范围**：仅上述两个用户自有 AP；扫描列表中的其他 AP 未做任何攻击操作
- **执行方式**：demo 模式进程内直跑；live 模式通过本机 root 权限的 `wraith web --live`（端口 8787）驱动

## 一、演示模式（11/11 通过）

不触碰无线硬件，验证每个模块的完整代码路径（含真实可校验的 PMKID / MIC 生成）。

| 模块 | 结果 | 耗时 | 摘要 |
|---|---|---|---|
| deauth | ✅ | 0.6s | 已发送 10 个解除认证帧（模拟） |
| handshake | ✅ | 3.1s | 握手捕获成功，生成可校验哈希 |
| pmkid | ✅ | 2.1s | PMKID 捕获成功，生成可校验哈希 |
| wps_pixie | ✅ | 1.9s | PIN=12345670，PSK 推导成功 |
| wps_pin | ✅ | 1.9s | PIN 校验通过，PSK 回填 |
| wep | ✅ | 2.5s | WEP 口令恢复 |
| evil_twin | ✅ | 32.4s | 伪 AP + 门户就绪 |
| wpa3_downgrade | ✅ | 3.1s | 降级获得 WPA2 握手 |
| karma | ✅ | 2.4s | 响应 6 个探测 SSID |
| enterprise | ✅ | 3.1s | EAP 降级就绪 |
| beacon_flood | ✅ | 1.8s | 广播 120 个伪造 SSID |

## 二、实机模式（目标 SZ078837）

| 模块 | 结果 | 耗时 | 说明 |
|---|---|---|---|
| deauth | ✅ | 23.7s | aireplay-ng 发送 10 帧，正常返回 |
| handshake | ⚠️→已修 | 19.3s | **缺陷 #1**：接续 deauth 后接口名失效 |
| pmkid | ⚠️→已修 | 71.5s | **缺陷 #2**：hcxdumptool 7.x 参数不兼容 |
| evil_twin | ⚠️ | 83.8s | hostapd + dnsmasq 正常起停，无客户端连入（链路正常，未获凭证） |
| karma | ✅ | 43.8s | hostapd-mana 运行 43s，无认证流量 |
| enterprise | ✅ | 54.6s | eaphammer 运行 52s，未捕获凭证 |
| beacon_flood | ✅ | 35.6s | mdk4 广播 60 个 SSID / 20s |
| wps_pixie / wps_pin | ⛔ | — | 前置校验拒绝：目标未标记 WPS |
| wep | ⛔ | — | 前置校验拒绝：目标非 WEP |
| wpa3_downgrade | ⛔ | — | 前置校验拒绝：目标非 WPA3/过渡模式 |

四个 ⛔ 是**符合预期的防御性拒绝**（HTTP 400 + 明确原因），不是失败；它们已在 demo 模式用匹配目标各跑通一次。

> 17:40 补充：对用户确认自有的 `7a:45:35:76:cc:68` 实机尝试了 `wep`，实测该 AP 并非 WEP，
> 并由此发现扫描器的 WEP 误判缺陷，见第七节。

## 三、发现的两个真实缺陷（均已修复 + 单测）

### 缺陷 #1：连续攻击之间网卡名失效（host 级，影响所有 monitor 模块）

`deauth` 收尾时 `airmon-ng stop wlan0mon` 返回 0，但 `wlan0` 尚未重建或 `wlan0mon` 残留；
紧接着 `handshake` 调用 `resolve()` 拿到已消失的 `wlan0mon`，`enable_monitor` 走 ip 回退分支时
报 `Cannot find device "wlan0mon"`，攻击直接失败。

修复（`wraith/system/iface.py`）：
- `enable_monitor` 遇到名字失效时轮询等待（`settle_timeout`），仍不存在则重新挑选可用网卡；
- `disable_monitor` 不再只信 `airmon-ng` 的返回码，改为确认原名真的回到 managed，否则手工恢复；
- 收尾时清理 `airmon-ng` 遗留的 monitor vif（`wlan0` 与 `wlan0mon` 并存的情况）。

### 缺陷 #2：hcxdumptool 7.x 参数不兼容（PMKID 模块 100% 失效）

`pmkid.py` 硬编码 `--enable_status=3`。本机 `hcxdumptool 7.1.2` 已把该选项改名为 `--rds=3`，
程序启动即 `unrecognized option` 退出，永远抓不到包，只报“未产生抓包”。

修复（`wraith/attacks/pmkid.py`）：
- 新增 `build_hcxdumptool_cmd()`：读 `hcxdumptool --version`，≥7 用 `--rds=3` 并给 `-c <ch><band>`
  （7.x 信道必须带频段后缀 `a`/`b`），6.x 保持原参数；
- 失败时把工具输出的关键行带进结果详情，不再只有一句笼统提示。

## 四、回归

```
72 passed（含新增 tests/test_iface_lifecycle.py 7 条：名字失效重解析、残留 vif 清理、6.x/7.x 命令构造）
```

## 五、复核方式

两个修复在**源码**中，正在运行的 `wraith web`（03:04 启动）仍是旧代码，需重启后复跑：

```bash
# 重启（需要 root）
sudo -E .venv/bin/python -m wraith web --live --iface wlan0

# 重新验证此前失败的两个模块
wraith attack handshake -b 88:5a:04:b4:e9:cb -e SZ078837 -c 6 --security WPA2 -o timeout=60
wraith attack pmkid     -b 88:5a:04:b4:e9:cb -e SZ078837 -c 6 --security WPA2 -o timeout=45
```

## 六、环境状态

测试结束后已确认：无 hostapd/dnsmasq/eaphammer/mdk4 残留进程，`wlan0` 回到 managed，
80/8080 无监听，仅保留 8787 Web 服务。

## 七、WEP 实机复测（17:40–17:44）

用户确认 `7a:45:35:76:cc:68` 为自有设备后，我把 live 授权范围收窄到该 BSSID 并执行
`wep`（timeout=240s，iv_target=20000，arp_replay=true）。

- **结果**：❌ 未恢复密钥（264s）。**不是工具链问题**——该 AP 实际不是 WEP。
- **证据**：本轮抓包 `data/run/wep-20261021-174000/wep-01.cap`（230,617 包）的 airodump
  CSV 为 `WPA3 WPA2 / CCMP / SAE PSK`；`aircrack-ng -z` 报 `WPA (0 handshake)`。
- **根因**：扫描库中该 BSSID 是 `privacy="WPA WEP"`、`beacons=0`、`data=13`——airodump
  对“只从数据帧推断出的 BSSID”写出的矛盾值。旧 `classify_security` 只要看到 `WEP`
  就判 WEP，于是 WEP 模块接受了这个 WPA3 过渡 AP。

### 新缺陷 #3：WPA3 过渡 AP 被误判为 WEP，导致攻击空跑

- 影响：`wep` 会对非 WEP 的 WPA2/WPA3 AP 启动 airodump + ARP Replay，跑满超时，
  报告里留下“未恢复密钥”的假阴性。
- 修复（`wraith/models.py`）：仅当 `privacy` 含 `WEP` 且**不含** `WPA` 时才判 WEP；
  `WPA WEP` 归入 WPA 系列。修复后该行分类为 `WPA`，WEP 模块前置校验返回
  「目标不是 WEP 网络」。
- 回归：`tests/test_models.py` 新增 `("WPA WEP", "WEP", "WPA")`，全套 **73 passed**。

### 链路验证

密钥不可能恢复，但 WEP 模块的 live 链路本次完整走通：

```
airmon-ng start wlan0 → 设 ch44 → airodump 写 8.1MB 抓包
→ aircrack-ng -z 每 5s 轮询（47 次）→ 注册 capture #10
→ airmon-ng stop，wlan0 回 managed
```

收尾后无 airodump/aireplay 残留进程。缺的是真实 WEP 目标。

## 八、剩余模块结论（截至 17:50）

| 模块 | 结论 | 还缺什么 |
|---|---|---|
| wps_pixie / wps_pin | 无法实机跑 | 100 个 AP 中 0 个广播 WPS；需在可控 AP 上手动开启 WPS |
| wep | 未完成 | 唯一候选是误判的 WPA3 过渡 AP；需真实 WEP 设备（老路由器） |
| wpa3_downgrade | 无法实机跑 | `7a:45:35:76:cc:68` 是合法过渡模式且扫描到 1 个客户端，但本机只有一块射频（phy5）；需第二块支持 monitor 的网卡 |

> 17:47 对 `7a:45:35:76:cc:68` 实跑了一次 `wpa3_downgrade`（timeout=30），模块在
> `_second_radio()` 处按预期失败：「降级攻击需要第二块支持监听模式的网卡：同一块射频
> 无法同时承载伪 AP、抓包与 Deauth 助攻」，未对目标发出任何帧。

> 缺陷 #3 的修复在源码中，运行中的 `wraith web`（17:23 启动）仍加载旧代码，重启后生效。

## 九、mac80211_hwsim 虚拟实验台复测（18:12–18:41）

为补齐剩余模块，用 `mac80211_hwsim radios=4` 建了 `wlan1`–`wlan4` 的纯软件实验台
（不触碰任何真实 AP），hostapd 2.10 造目标，reaver 1.6.6 / pixiewps 1.4 /
aircrack-ng 1.7 走真实命令链。

| 模块 | 结果 | 说明 |
|---|---|---|
| wps_pin | ✅ | hostapd WPS AP（`ap_pin=12345670`），reaver 完整 M1–M7，2s 得到 PIN=12345670 / PSK=WraithLab2024 |
| wps_pixie | ✅（链路） | 完整 M1/M2 → pixiewps 1.4 返回 `WPS pin not found`；hostapd 使用强随机数，符合预期，不是模块缺陷 |
| wpa3_downgrade | ✅ | WPA2/WPA3 过渡 AP + 客户端；伪 AP 捕获握手，生成 22000（2 条），aircrack-ng 以 WraithLab2024 验证 `KEY FOUND!` |
| wep | ⚠️ 链路通、无 IV | airodump/aireplay/aircrack 全链路跑满 150s；客户端 WEP 帧可被 airdecap-ng 正确解密，但 hwsim 上 AP 不回 ARP，0 IV，无法恢复密钥 |

### 实验台关键点（复现用）

1. **监听口必须是主接口**：`iw dev wlanX set type monitor`，不能只用
   `iw dev wlanX interface add monX type monitor`。后者能收包，但注入的 auth/EAPOL
   不会被 ACK，hostapd 会回 `Class 3 frame received from nonassociated STA`，
   reaver 卡在 `EAPOL START`。
2. **必须开 active monitor**：`iw dev wlanX set monitor active`（需先 down 接口），
   否则 AP 的 assoc response 收不到 ACK。
3. hostapd 默认会随机化 BSSID；要稳定复现需显式 `bssid=02:11:22:33:44:55`。
4. WPS 配置：`wps_state=2`、`eap_server=1`、`ap_pin=12345670`；`wps_version2`
   不是本机 hostapd 2.10 的合法配置项。
5. `wpa3_downgrade` 必须 `spoof_bssid=true`：airodump 按目标 BSSID 过滤，伪 AP
   换 BSSID 就抓不到握手。
6. hwsim 的 WEP 数据面不完整：客户端加密帧正常，AP 不回 ARP（同主机路由 +
   hostapd WEP 数据路径），因此 WEP 仍建议用真实老路由器验证。

### 结论

四个模块的真实命令链均已在虚拟实验台跑过：WPS PIN 与 WPA3 降级拿到可验证结果，
WPS Pixie 得到符合预期的失败，WEP 仅差真实数据面。结合第七节，WEP 在真实环境
还缺一台真正的 WEP AP。

实验台已拆除：hwsim 卸载，仅剩 `wlan0` managed，无 hostapd/reaver/airodump 残留。
