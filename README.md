# 🐱 WifiCat — an open-source 802.11 toolkit for the BW16

**WifiCat** is a free, fully open-source WiFi research toolkit for the
**Ai-Thinker BW16 (RTL8720DN)** dual-band module, driven from a **Flipper Zero**.

Unlike most "WiFi gadget" firmwares that are closed blobs, paywalled, or locked to
one vendor's hardware, **WifiCat is 100% open**: every line of the BW16 firmware and
the Flipper app is in this package. Read it, change it, rip it apart, rebuild it.
Nothing is hidden, nothing phones home, nothing is for sale.

> Made as a student project to actually *understand* how 802.11 works — not just
> push buttons. The code is commented so you can learn from it.

---

## ✨ What it does

| Module | What it does |
|---|---|
| 📡 **Dual-band Scan** | Lists 2.4 **and** 5 GHz APs with signal, channel, encryption and precise PMF status (capable / required), WPA3 detection. |
| 📊 **Channel Map** | Congestion view across both bands; highlights the least-busy channel. |
| 🤝 **Capture Handshake** | Forces a reconnect and grabs the WPA/WPA2 4-way handshake, written as a standard **PCAP to the Flipper SD** — drop straight into `hashcat -m 22000` or aircrack-ng. |
| 🚫 **Deauth** | Sustained, PMF-aware deauth of a chosen AP — tells you when a target is 802.11w / WPA3 protected (deauth-immune) instead of failing silently. |
| 💥 **Deauth All** | Deauth every AP the Flipper has scanned, in one pass, channel-hopping across both bands. |
| 📶 **Create AP · Beacon** | Stand up a soft-AP, or flood custom / random / **Rickroll** beacons. |
| 🐈 **Pwnagotchi mode** | Auto channel-hop + deauth + handshake hunting with a moody ASCII face. Hold OK for the emotion debug screen. |
| 🖥️ **Live Log** | Marauder-style scrolling terminal of every event (APs, clients, logins, handshakes, deauths). |
| 🪤 **Evil Portal** | *Coming soon — currently broken. PRs welcome.* |

---

## 🔌 Works on **every** BW16

WifiCat targets the stock **Realtek AmebaD Arduino SDK (3.1.9)** and the
`Ai-Thinker_BW16` board definition. If your BW16 flashes with the standard
`upload_image.exe` tool, WifiCat runs on it — no special bootloader, no patched
SDK, no soldering. One UART line (BW16 TX → Flipper RX/GPIO 14) and a common
ground is all the wiring it needs.

---

## ⚖️ How it compares

| | **WifiCat (BW16)** | **Marauder (ESP32)** | **Typical BW16 firmwares** |
|---|---|---|---|
| Bands | **2.4 + 5 GHz** | 2.4 GHz only | usually 2.4 only |
| Open source | **Yes, all of it** | Yes | often partial / closed |
| Handshake → PCAP on SD | **Yes (Flipper SD)** | Yes (needs SD mod) | rare |
| PMF / WPA3 awareness | **Yes (capable/required)** | limited | rare |
| Pwnagotchi-style auto mode | **Yes** | no | no |
| Live terminal log | **Yes** | Yes | varies |
| Hardware cost | ~$5 BW16 | ~$8 ESP32 | ~$5 |
| Host | Flipper Zero | Flipper / phone / standalone | varies |

The ESP32 + Marauder is the classic combo, but the ESP32 is **2.4 GHz only**.
The BW16's RTL8720DN is genuinely **dual-band**, so WifiCat sees and works the
5 GHz world that ESP32 tools simply can't.

---

## ⚠️ Limits / honest caveats

- **5 GHz monitor mode on the RTL8720DN is flaky.** Scanning 5 GHz is solid;
  *capturing* handshakes works most reliably on 2.4 GHz.
- **Deauth depends on the chip.** Raw injection on the RTL8720DN is less robust
  than on an ESP32; PMF/802.11w (WPA3) targets are immune by design.
- **Evil Portal is unfinished** (the soft-AP DHCP/captive flow is not reliable on
  this SDK yet). It ships as a "coming soon" placeholder — the code is here if you
  want to finish it.
- One Flipper ↔ one BW16. No mesh of devices.

---

## 🧾 Legal

WifiCat is provided **for education and authorized security testing only.**

Transmitting deauthentication/disassociation frames, beacon floods, and operating
rogue access points **may be illegal** in your country and is illegal against
networks and devices you do **not** own or have **explicit written permission**
to test. Capturing handshakes and credentials from third parties is illegal in
most jurisdictions.

**You** are solely responsible for how you use this. Only use it on your own lab,
your own AP, and your own devices — or within a sanctioned, written-authorization
engagement. The authors accept **no liability** for misuse.

Provided **as-is, with no warranty.** Open source — modify and share freely.

---

## 📂 What's in this package

```
wificat/
├── flasher/   → BW16 firmware + upload_image.exe + flashing instructions
├── app/       → Flipper app source + the ready-to-install wificat.fap
└── README.md  → this file
```

See `flasher/INSTRUCTIONS.txt` to flash the BW16, and copy `app/wificat.fap`
to your Flipper at `SD/apps/Tools/`.

Happy (responsible) hacking. 🐾
