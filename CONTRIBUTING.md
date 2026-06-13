# Contributing to WifiCat 🐱

Thanks for wanting to help! WifiCat is a learning-first, fully open project — PRs,
issues, and ideas are all welcome.

## Project layout
```
flasher/                 BW16 firmware images + upload_image.exe
app/wifi_study/          Flipper app source (C)
  ├── wifi_study_app.c   entry, view-dispatcher, timer, menu
  ├── uart_handler.c     BW16 <-> Flipper line protocol parser
  └── views/             one file per screen/module
app/bw16_firmware_src/   the BW16 Arduino sketch (.ino + headers)
```

## How the two halves talk
A simple newline-terminated ASCII protocol over UART (115200). The BW16 sends
`S,` (scan) `H,` (eapol) `G,` (handshake) `D,` (deauth) `Q,` (probe) `M,` (camera)
`T,` (station) `O,` (portal) etc.; the Flipper sends `CMD,...`. See `protocol.h`
and the `handle_cmd()` / `parse_line()` functions — adding a feature is usually:
1. a new BW16 `MODE_*` + `CMD,` handler + an `emit(...)` line,
2. a parser `case` in `uart_handler.c`,
3. a new `views/<name>_view.c` + wiring in `wifi_study_app.c`.

## Building
- **Flipper app:** `pip install ufbt`, then `ufbt` in `app/wifi_study/` (→ `dist/`),
  `ufbt launch` to flash over USB.
- **BW16 firmware:** Arduino + Realtek AmebaD SDK 3.1.9, board `Ai-Thinker_BW16`.

## Good first issues
- **Finish the Evil Portal** (the soft-AP/DHCP/captive flow — see `start_portal`).
- More camera-vendor OUIs in `CAM_OUIS`.
- Beacon SSIDs loaded from an SD file.
- A Foxhunt/RSSI signal-locator screen.

## Ground rules
- Keep it **honest** — if something is flaky on the hardware, say so in the README.
- **Education / authorized testing only.** Don't add features whose only purpose is
  harming networks/devices you don't own. See LICENSE.
