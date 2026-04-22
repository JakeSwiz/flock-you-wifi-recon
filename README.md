<p align="center">
  <img src="assets/swiz-security.png" alt="Swiz Security" width="480">
</p>

# flock-you-wifi-recon

Passive WiFi recon firmware for ESP32-WROVER that detects Flock Safety ALPR cameras by their STA-mode probe requests. Works even when the camera's hotspot is off, which is basically always in my neighborhood.

## The story

Started with [colonelpanichacks/flock-you](https://github.com/colonelpanichacks/flock-you) thinking I could just flash it up and detect the Flocks in my area via BLE. Flashed `esp32_wrover_promisc` mode, walked right up to a confirmed Flock ALPR ([OSM node 12962132155](https://www.openstreetmap.org/node/12962132155), St. Pete FL), captured for minutes. `flock-matches: 0` across every attempt. BLE channel was dead silent on that pole. Flock-you's BLE detection was never going to catch this thing.

Dug into Jon Gaines' writeups at [gainsec.com](https://gainsec.com) and his Part 2 confirmed Ravens (gunshot detectors) do BLE but Falcon/Sparrow ALPR cameras do NOT. They use WiFi. Part 7 "Button Presses to Wireless RCE" showed they broadcast `Flock-XXXXXX` hotspots, but only after a physical button sequence. Checked WiGLE for my metro, zero `Flock-*` SSIDs logged across a 3.5mi x 3.5mi bbox with 249K networks mapped. So the Flocks around here keep their hotspots off by default.

Look at how they handled security at the jump. Default hotspot password `security`, devkit SSIDs baked into production firmware (CVE-2025-59409), unauthenticated APIs open on the hotspot interface, ADB one unauthenticated HTTP request away. You already know the follow-up mitigations are gonna be just as trash.

So I said fuck flock-you, wrote my own detection. Flipped from BLE-passive recon on the ESP32 and actively drove around in my car around the known Flock spots, waited for other cars to get ALPR'd, and sat right under the ALPR to gather probes.

The results? 12 probe requests from a single MAC across a span of 50 seconds from a KNOWN Flock OUI: `E4:AA:EA` (Liteon Technology Corporation, Taiwan).

```
[+00:07:20.845] frames_seen:16595 matches:0  hidden_flagged:64 ch:10     ← baseline: 0 matches
[+00:07:23.948] MATCH(oui_flock) PROBE_REQ src:e4:aa:ea:80:a1:9b ssid:"<hidden>" rssi:-82 ch:5 hits:1
[+00:07:24.461] MATCH(oui_flock) PROBE_REQ src:e4:aa:ea:80:a1:9b ssid:"<hidden>" rssi:-80 ch:6 hits:2
[+00:07:24.975] MATCH(oui_flock) PROBE_REQ src:e4:aa:ea:80:a1:9b ssid:"<hidden>" rssi:-81 ch:7 hits:3
[+00:07:30.851] frames_seen:16781 matches:3  hidden_flagged:64 ch:6      ← matches climbing
[+00:07:41.219] MATCH(oui_flock) PROBE_REQ src:e4:aa:ea:80:a1:9b ssid:"<hidden>" rssi:-73 ch:3 hits:4
[+00:07:41.732] MATCH(oui_flock) PROBE_REQ src:e4:aa:ea:80:a1:9b ssid:"<hidden>" rssi:-72 ch:4 hits:5
[+00:07:49.434] MATCH(oui_flock) PROBE_REQ src:e4:aa:ea:80:a1:9b ssid:"<hidden>" rssi:-75 ch:6 hits:6
[+00:07:50.860] frames_seen:17329 matches:6  hidden_flagged:64 ch:9
[+00:07:57.602] MATCH(oui_flock) PROBE_REQ src:e4:aa:ea:80:a1:9b ssid:"<hidden>" rssi:-72 ch:1 hits:7
[+00:07:58.116] MATCH(oui_flock) PROBE_REQ src:e4:aa:ea:80:a1:9b ssid:"<hidden>" rssi:-70 ch:2 hits:8   ← peak RSSI, closest
[+00:08:00.902] frames_seen:17633 matches:8  hidden_flagged:64 ch:7
[+00:08:06.502] MATCH(oui_flock) PROBE_REQ src:e4:aa:ea:80:a1:9b ssid:"<hidden>" rssi:-78 ch:7 hits:9
[+00:08:07.017] MATCH(oui_flock) PROBE_REQ src:e4:aa:ea:80:a1:9b ssid:"<hidden>" rssi:-76 ch:8 hits:10
[+00:08:10.908] frames_seen:17953 matches:10 hidden_flagged:64 ch:4
[+00:08:14.565] MATCH(oui_flock) PROBE_REQ src:e4:aa:ea:80:a1:9b ssid:"<hidden>" rssi:-72 ch:1 hits:11
[+00:08:15.079] MATCH(oui_flock) PROBE_REQ src:e4:aa:ea:80:a1:9b ssid:"<hidden>" rssi:-73 ch:2 hits:12  ← last hit pulling away
[+00:08:20.912] frames_seen:18249 matches:12 hidden_flagged:64 ch:2      ← final count
```

Here's where it gets interesting. Examining the frames some more, I see the frame type is `PROBE_REQ`, meaning the Flock ALPR was in STA mode (not broadcasting its SSID). In other words HIDDEN FUCKING SSID. Security through obscurity. This aligns with flock-you's OUI list on their repo (`E4:AA:EA` is already in `flock_mac_prefixes` under the "Flock WiFi devices" comment).

The probes really shot up shortly after seeing the IR strobe from the ALPR (confirmed with my camera), which means it was searching for its uplink network. That's what a Falcon/Sparrow does when it's trying to phone home with plate data.

So Flock ALPRs (at least in my neighborhood) do NOT need their hotspot on to be detectable. This one didn't advertise any `Flock-*` AP SSIDs, it was silent on all beacons from my scans. But it was continuously probing for its uplink hidden SSID in STA mode. That's an always-on signature right there brotha.

## How it works

The firmware flashes the ESP32-WROVER in `WIFI_SCAN_MODE`, which:

- Disables BLE and the dashboard AP (needed radio time for passive monitor mode)
- Puts the WiFi radio in promiscuous monitor mode
- Hops channels 1 through 11 every 400ms
- Parses every 802.11 management frame (beacons, probe requests, probe responses)
- Matches on:
  - SSID patterns (`Flock-XXXXXX` per Gaines, `test_flck` per CVE-2025-59409, any SSID containing "flock" or "flck")
  - Source MAC OUI against the upstream flock-you `flock_mac_prefixes` list (`B4:1E:52` Flock Safety direct, plus contract manufacturer OUIs like `E4:AA:EA` Liteon)
- Flags hidden SSIDs separately so you can review them manually
- Beeps the onboard piezo on any detection

When a hit fires you get lines like:

```
[FLOCK-WIFI] [+00:07:58.116] MATCH(oui_flock) PROBE_REQ src:e4:aa:ea:80:a1:9b ssid:"<hidden>" rssi:-70 ch:2 hits:8
```

## Hunting procedure

1. Pull up [DeFlock](https://deflock.me) and find known Flock poles near you.
2. Flash the firmware:
   ```
   pio run -e esp32_wrover_wifi_scan -t upload
   ```
3. Monitor and capture:
   ```
   pio device monitor -e esp32_wrover_wifi_scan | tee wifi-$(date +%Y%m%d-%H%M%S).log
   ```
4. Drive by or park under the pole.
5. Wait for another car to trigger the ALPR (IR strobe is the tell). The camera will start probing harder as it phones home.
6. Watch for `MATCH(oui_flock)` lines with a persistent source MAC.

Rely on known or detected OUIs. RSSI shows proximity. Get close to the ALPR and wait for it to capture data and phone home with LP data. The OUI list in `src/main.cpp` lines 64 through 73 is the hit list. Expand it as new contract manufacturers surface.

## Hardware

Espressif ESP32-DevKitC v4 with WROVER-E module (N8R8, 8MB flash + 8MB PSRAM). Any ESP32 WROVER should work. Onboard CP2102N USB-UART handles flashing automatically, no BOOT/EN button mashing needed.

## Builds

| env | purpose |
|-----|---------|
| `esp32_wrover` | original flock-you BLE detection with dashboard AP |
| `esp32_wrover_field` | BLE-only field mode, no dashboard |
| `esp32_wrover_promisc` | verbose BLE log mode for OUI discovery |
| `esp32_wrover_wifi_scan` | **the WiFi recon mode this repo is about** |
| `esp32_wrover_wifi_scan_verbose` | WiFi recon with all SSIDs logged, not just matches |

## Credits

- **Jon Gaines / GainSec** for the Flock Safety security research and WiFi SSID signatures. Series: <https://gainsec.com/2025/11/05/formalizing-my-flock-safety-security-research/>. Part 4 "Trap Shooter" inspired this direction: <https://gainsec.com/2025/06/30/trap-shooter-tiny-flock-safety-sniffer-alarm/>
- **colonelpanichacks/flock-you** for the original ESP32 firmware, BLE detection, and the curated Flock OUI list that the WiFi OUI match path reuses: <https://github.com/colonelpanichacks/flock-you>
- **wgreenberg/flock-you** for the BLE manufacturer ID research (XUNTONG `0x09C8`): <https://github.com/wgreenberg/flock-you>
- **DeFlock** for crowdsourced Flock pole locations: <https://deflock.me>

## Disclaimer

Passive BLE and WiFi reception is legal in most US jurisdictions. This tool does not transmit, deauthenticate, jam, or associate. It reads public-facing radio traffic that any device in range receives anyway. Don't use it for stalking, harassment, or anything illegal, obviously.
