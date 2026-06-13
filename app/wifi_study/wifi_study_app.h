#pragma once
#include <furi.h>
#include <gui/gui.h>
#include <gui/view.h>
#include <gui/view_dispatcher.h>
#include <gui/modules/submenu.h>
#include <gui/modules/text_input.h>
#include <notification/notification_messages.h>
#include <furi_hal_serial.h>
#include <furi_hal_serial_control.h>

typedef enum {
    ViewSplash   = 0,
    ViewMain     = 1,
    ViewScanner  = 2,
    ViewChanMap  = 3,
    ViewProtocol = 4,
    ViewCapture  = 5,
    ViewPortal   = 6,
    ViewAttack   = 7,
    ViewPSsid    = 8,   /* portal wizard: enter SSID   */
    ViewPHtml    = 9,   /* portal wizard: choose HTML  */
    ViewPSec     = 10,  /* portal wizard: security     */
    ViewPPass    = 11,  /* portal wizard: AP password  */
    ViewPwn      = 12,  /* pwnagotchi auto mode        */
    ViewDeauthAll= 13,  /* deauth-all module           */
    ViewTerminal = 14,  /* marauder-style live log     */
    ViewComingSoon=15,  /* evil portal placeholder     */
    ViewProbe    = 16,  /* probe-request sniffer       */
    ViewCam      = 17,  /* wifi camera detector        */
    ViewEgg      = 18,  /* secret easter egg           */
    ViewDeauthDet= 19,  /* deauth-attack detector      */
    ViewStation  = 20,  /* station / client list       */
} AppView;

static const char* const SEC_LABEL[] = {
    "OPEN","WEP","WPA","WPA2","WPA3","MIX"
};
static const char* const PMF_LABEL[] = { "", "PMF?", "PMF!" };

#define PMF_NONE     0
#define PMF_OPTIONAL 1
#define PMF_REQUIRED 2

#define MAX_APS      32
#define SSID_LEN     33
#define MAC_LEN      18
#define MAX_DEAUTH   16
#define MAX_CH24     13
#define MAX_CH5      24

/* 5 GHz channel list (matches BW16 firmware) */
static const uint8_t CH5_TABLE[MAX_CH5] = {
    36,40,44,48,52,56,60,64,
    100,104,108,112,116,120,124,128,132,136,140,
    149,153,157,161,165
};

typedef struct {
    char    ssid[SSID_LEN];
    char    bssid[MAC_LEN];
    int8_t  rssi;
    uint8_t channel;
    uint8_t security;
    uint8_t pmf;       /* PMF_NONE / PMF_OPTIONAL / PMF_REQUIRED */
    bool    valid;
} ApRecord;

typedef struct {
    char    bssid[MAC_LEN];
    char    client[MAC_LEN];
    uint8_t stage;
    bool    complete;
    uint32_t ts;
} HandshakeState;

typedef struct {
    char    bssid[MAC_LEN];
    char    client[MAC_LEN];
    uint8_t stage;
} SaeState;

typedef struct {
    char    bssid[MAC_LEN];
    uint8_t pmkid[16];
    bool    valid;
} PmkidCapture;

typedef struct {
    char     bssid[MAC_LEN];
    char     client[MAC_LEN];
    uint16_t count;
    bool     is_deauth;
} DeauthEntry;

typedef struct {
    uint32_t cnt24[MAX_CH24];   /* channels 1-13 */
    uint32_t cnt5[MAX_CH5];     /* CH5_TABLE[i]  */
    uint8_t  active_ch;
} ChanMap;

typedef struct {
    char    target_bssid[MAC_LEN];
    char    target_ssid[SSID_LEN];
    uint8_t target_ch;
    uint8_t stage;     /* 0-4 EAPOL stage */
    bool    active;
    bool    complete;
    bool    saved;
    /* raw 802.11 frames forwarded from BW16, written out as PCAP */
    uint8_t  frames[8][256];
    uint16_t flen[8];
    int      nframes;
} CaptureState;

#define CAP_MAX_FRAMES 8
#define CAP_FRAME_MAX  256

typedef struct {
    char    ssid[SSID_LEN];
    char    password[33];   /* empty = open AP */
    char    html_path[128]; /* custom HTML file, empty = built-in */
    bool    use_custom;
    uint8_t channel;
    bool    active;
    uint16_t clients;
    char    last_creds[80];
    bool    got_creds;
} PortalState;

/* deauth result from W, message */
typedef struct {
    char    bssid[MAC_LEN];
    uint8_t pmf_result;  /* 0=sent 1=opt 2=req */
    bool    valid;
} DeauthResult;

typedef struct {
    Gui*             gui;
    ViewDispatcher*  view_dispatcher;
    NotificationApp* notifications;

    View*    splash_view;
    Submenu* main_menu;
    Submenu* attack_menu;
    /* Evil Portal wizard */
    TextInput* p_ssid_input;
    Submenu*   p_html_menu;
    Submenu*   p_sec_menu;
    TextInput* p_pass_input;
    /* portal-page picker: drill-down catalog of bundled + SD portals */
    char       p_category[24];      /* "" = top level */
    char       p_label[48][40];
    char       p_path[48][160];
    uint8_t    p_kind[48];          /* 0 builtin 1 category 2 file 3 back */
    int        p_count;
    View*    scanner_view;
    View*    chanmap_view;
    View*    protocol_view;
    View*    capture_view;
    View*    portal_view;
    View*    pwn_view;
    View*    deauthall_view;
    View*    terminal_view;
    View*    comingsoon_view;
    View*    probe_view;
    View*    cam_view;
    View*    egg_view;
    View*    ddet_view;
    View*    station_view;

    /* UART */
    FuriHalSerialHandle* uart_handle;
    FuriThread*          uart_thread;
    FuriStreamBuffer*    uart_buf;     /* RX bytes */
    FuriStreamBuffer*    uart_tx_buf;  /* queued TX commands */
    bool                 uart_running;

    /* Shared data – always access under data_mutex */
    FuriMutex*   data_mutex;
    ApRecord     aps[MAX_APS];
    int          ap_count;
    int          ap_scroll;

    HandshakeState hs;
    SaeState       sae;
    PmkidCapture   pmkid;
    ChanMap        chanmap;
    DeauthEntry    deauths[MAX_DEAUTH];
    int            deauth_count;
    uint32_t       total_deauths;
    DeauthResult   last_deauth_result;
    CaptureState   capture;
    PortalState    portal;

    /* BW16 connection state */
    bool     bw16_ok;
    uint32_t bw16_last_seen;
    uint32_t rx_bytes;   /* total UART bytes received (diagnostic) */

    /* haptic/sound/LED feedback flags (consumed by the timer) */
    bool     notify_hs;     /* handshake caught */
    bool     notify_cam;    /* camera found */
    bool     notify_creds;  /* portal login captured */

    /* Marauder-style live log (terminal) */
    char     log_lines[16][32];
    uint8_t  log_head;     /* next write slot (ring) */
    uint16_t log_total;    /* lines ever written */

    /* Probe-request sniffer: devices and the SSIDs they look for */
    char     probe_ssid[20][24];
    char     probe_mac[20][18];
    int      probe_count;
    int      probe_scroll;

    /* Camera detector: MACs whose vendor OUI is a known camera maker */
    char     cam_mac[16][18];
    char     cam_vendor[16][16];
    uint8_t  cam_ch[16];
    int      cam_count;
    int      cam_scroll;

    /* Station/client list: device <-> AP */
    char     sta_mac[20][18];
    char     sta_ap[20][18];
    int      sta_count;
    int      sta_scroll;
    int      ddet_scroll;

    /* Pwnagotchi */
    uint32_t pwn_handshakes;
    uint32_t pwn_last_catch;
    char     pwn_caught[24][MAC_LEN];
    int      pwn_caught_count;
    bool     pwn_smart;          /* passive (no deauth) vs aggressive */
    bool     pwn_running;        /* pwn view open -> buffer + save handshakes */
    bool     pwn_save_pending;   /* a handshake is ready to write to SD */
    char     pwn_save_bssid[MAC_LEN];

    /* Splash */
    uint8_t  splash_pct;
    bool     splash_done;
} WifiStudyApp;

int32_t wifi_study_app(void* p);
void    save_handshake_to_sd(WifiStudyApp* app);
