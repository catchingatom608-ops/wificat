# 🐱 WifiCat — an open-source 802.11 toolkit for the BW16

**WifiCat** is a free, fully open-source dual-band WiFi research toolkit for the
**Ai-Thinker BW16 (RTL8720DN)**, driven from a **Flipper Zero**.

Unlike most "WiFi gadget" firmwares — closed blobs, paywalled, or locked to one
vendor — **WifiCat is 100% open**. Every line of the BW16 firmware and the Flipper
app is in this package. Read it, change it, rebuild it. Nothing is hidden, nothing
phones home, nothing is for sale. It was made as a student project to actually
*understand* 802.11, and the code is commented so you can learn from it.

---

## ✨ Modules

| | Module | What it does |
|---|---|---|
| 📡 | **Scan + Deauth** | Lists 2.4 **and** 5 GHz APs with signal, channel, encryption, precise PMF status (capable/required) and WPA3 detection. OK on an AP = sustained, **PMF-aware** deauth (tells you when a target is 802.11w/WPA3 = deauth-immune). |
| 📊 | **Channel Map** | Congestion view across both bands; highlights the least-busy channel. |
| 🤝 | **Capture Handshake** | Forces a reconnect and grabs the WPA/WPA2 4-way handshake, saved as a standard **PCAP on the Flipper SD** — drop straight into `hashcat -m 22000` or aircrack-ng. |
| 💥 | **Deauth All** | Channel-hops 2.4 GHz and hammers **every** scanned AP at once. |
| 📶 | **Create AP · Beacon** | Stand up a soft-AP, or flood custom / random / **Rickroll** beacons. |
| 🐈 | **Pwnagotchi** | Fully-auto handshake hunter with a moody ASCII face. **Quad-click OK** = SMART mode (passive, no deauth — stealthy). **Hold OK** = emotion debug screen. Every caught handshake is **auto-saved to SD** as PCAP. |
| 📱 | **Probe Sniffer** | Captures probe-requests — the network names nearby phones are *searching* for — revealing devices around you and their saved-network history. |
| 📷 | **Camera Detector** | Channel-hops and flags any device whose MAC **vendor (OUI)** is a known WiFi-camera maker (Hikvision, Dahua, Wyze, Ring, Nest, Tuya, Reolink, Amcrest, ESP32-cam…). Great for spotting hidden WiFi cams in a room. *Heuristic — see limits.* |
| 🖥️ | **Live Log** | Marauder-style scrolling terminal of every event (APs, clients, logins, handshakes, deauths, probes, cameras). |
| 🪤 | **Evil Portal** | *Coming soon — currently broken (`x_x`). The code is here if you want to finish it.* |

---

## 🔌 Works on **every** BW16

WifiCat targets the stock **Realtek AmebaD Arduino SDK (3.1.9)** and the
`Ai-Thinker_BW16` board. If your BW16 flashes with the standard `upload_image.exe`,
WifiCat runs on it — no special bootloader, no patched SDK, no soldering. One UART
line (BW16 TX → Flipper RX/GPIO 14) and a common ground is all the wiring it needs.

---

## ⚖️ How it compares

| | **WifiCat (BW16)** | **Marauder (ESP32)** | **Typical BW16 firmwares** |
|---|---|---|---|
| Bands | **2.4 + 5 GHz** | 2.4 GHz only | usually 2.4 only |
| Open source | **Yes, all of it** | Yes | often partial / closed |
| Handshake → PCAP on SD | **Yes** | yes (SD mod) | rare |
| PMF / WPA3 awareness | **Yes** | limited | rare |
| Pwnagotchi auto + SD save | **Yes** | no | no |
| Probe sniffer | **Yes** | yes | rare |
| WiFi camera detector | **Yes** | no | no |
| Live terminal log | **Yes** | yes | varies |
| Hardware cost | ~$5 | ~$8 | ~$5 |

The ESP32 + Marauder is the classic combo, but the ESP32 is **2.4 GHz only**. The
BW16's RTL8720DN is genuinely **dual-band**, so WifiCat sees the 5 GHz world that
ESP32 tools can't — and adds a camera detector on top.

---

## ⚠️ Limits / honest caveats

- **Camera Detector is a heuristic.** It only finds cameras that (a) are on WiFi,
  (b) are transmitting while we're on their channel, and (c) use a MAC from a vendor
  in our built-in list. It **cannot** find analog/coax cams, cellular cams, cams with
  randomized/unknown MACs, or ones that are powered off. A match means "probably a
  camera by vendor," not a guarantee — and a non-match doesn't mean the room is clean.
- **5 GHz monitor mode on the RTL8720DN is flaky.** 5 GHz *scanning* is solid;
  *capturing* handshakes works most reliably on 2.4 GHz.
- **Deauth depends on the chip** and is weaker than an ESP32. PMF/802.11w (WPA3)
  targets are immune by design.
- **Evil Portal is unfinished.**
- One Flipper ↔ one BW16. No device mesh.

---

## 🧾 Legal

WifiCat is provided **for education and authorized security testing only.**

Transmitting deauth/disassoc frames, beacon floods, and operating rogue APs **may be
illegal** in your country and is illegal against networks/devices you do **not** own
or have **explicit written permission** to test. Capturing handshakes or credentials
from third parties is illegal in most jurisdictions. The camera detector is a privacy
tool — use it to check your *own* space.

**You** are solely responsible for how you use this. Only use it on your own lab,
your own AP, and your own devices — or within a sanctioned, written-authorization
engagement. The authors accept **no liability** for misuse. Provided **as-is, no
warranty.** Open source — modify and share freely.

---

## 📂 What's in this package

```
wificat/
├── README.md                 ← this file
├── flasher/                  ← BW16 firmware + upload_image.exe + INSTRUCTIONS.txt
│   ├── upload_image.exe
│   ├── flash_bw16.bat        ← flash_bw16.bat COM5
│   └── bins/                 ← the 4 firmware images
└── app/
    ├── wificat.fap           ← ready-to-install Flipper app
    ├── BUILD.txt             ← how to rebuild app + firmware
    ├── wifi_study/           ← full Flipper app source (+ bundled portals)
    └── bw16_firmware_src/    ← the BW16 .ino + headers
```

Flash the BW16 (see `flasher/INSTRUCTIONS.txt`) and copy `app/wificat.fap`
to your Flipper at `SD/apps/Tools/`.

Happy (responsible) hacking. 🐾
