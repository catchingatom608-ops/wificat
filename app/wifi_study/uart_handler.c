#include "uart_handler.h"
#include <expansion/expansion.h>
#include <string.h>
#include <stdlib.h>

#define UART_ID    FuriHalSerialIdUsart
#define UART_BAUD  115200
#define LINE_BUF   200

/* ── Helpers ────────────────────────────────────────────────── */
static int32_t parse_int(const char* s) {
    if(!s) return 0;
    int32_t v=0, neg=0;
    if(*s=='-') { neg=1; s++; }
    while(*s>='0'&&*s<='9') v=v*10+(*s++-'0');
    return neg?-v:v;
}
static uint32_t parse_u32(const char* s) {
    if(!s) return 0;
    uint32_t v=0;
    while(*s>='0'&&*s<='9') v=v*10+(uint32_t)(*s++-'0');
    return v;
}

/* ── RX interrupt → stream buffer ──────────────────────────── */
static void uart_rx_cb(FuriHalSerialHandle* h,
                        FuriHalSerialRxEvent ev, void* ctx) {
    WifiStudyApp* app = ctx;
    /* RxEvent is a bitmask – drain all available bytes when the
     * data bit is set (== comparison can miss combined events). */
    if(ev & FuriHalSerialRxEventData) {
        while(furi_hal_serial_async_rx_available(h)) {
            uint8_t b = furi_hal_serial_async_rx(h);
            furi_stream_buffer_send(app->uart_buf, &b, 1, 0);
        }
    }
}

/* ── Parse one complete line ────────────────────────────────── */
/* append a line to the live log ring (caller holds data_mutex) */
static void log_add(WifiStudyApp* app, const char* s) {
    strncpy(app->log_lines[app->log_head], s, 31);
    app->log_lines[app->log_head][31] = '\0';
    app->log_head = (uint8_t)((app->log_head + 1) % 16);
    app->log_total++;
}

static void parse_line(WifiStudyApp* app, const char* line) {
    if(!line || !line[0] || line[1] != ',') return;
    char buf[LINE_BUF];
    strncpy(buf, line, LINE_BUF-1); buf[LINE_BUF-1]='\0';
    char type = buf[0];
    char* rest = buf+2;

    furi_mutex_acquire(app->data_mutex, FuriWaitForever);

    switch(type) {

    case 'R':  /* heartbeat */
        app->bw16_ok        = true;
        app->bw16_last_seen = furi_get_tick();
        break;

    case 'S': {  /* scan result */
        char* ssid  = strtok(rest,",");
        char* bssid = strtok(NULL,",");
        char* rssi  = strtok(NULL,",");
        char* ch    = strtok(NULL,",");
        char* sec   = strtok(NULL,",");
        char* pmf   = strtok(NULL,",\r\n");
        if(!ssid||!bssid||!rssi||!ch||!sec) break;
        /* find or insert */
        int slot=-1;
        for(int i=0; i<app->ap_count; i++)
            if(strncmp(app->aps[i].bssid, bssid, MAC_LEN)==0) { slot=i; break; }
        bool is_new = (slot < 0);
        if(slot<0 && app->ap_count<MAX_APS) slot=app->ap_count++;
        if(slot<0) break;
        if(is_new) {
            char ln[32]; snprintf(ln, sizeof(ln), "AP %.11s c%s", ssid, ch);
            log_add(app, ln);
        }
        strncpy(app->aps[slot].ssid,  ssid,  SSID_LEN-1);
        strncpy(app->aps[slot].bssid, bssid, MAC_LEN-1);
        app->aps[slot].rssi     = (int8_t)parse_int(rssi);
        app->aps[slot].channel  = (uint8_t)parse_u32(ch);
        app->aps[slot].security = (uint8_t)parse_u32(sec);
        app->aps[slot].pmf      = pmf ? (uint8_t)parse_u32(pmf) : 0;
        app->aps[slot].valid    = true;
        /* update chanmap count for this channel */
        uint8_t c = app->aps[slot].channel;
        if(c>=1 && c<=MAX_CH24) {
            if(app->chanmap.cnt24[c-1]==0) app->chanmap.cnt24[c-1]=1;
        }
        break;
    }

    case 'H': {  /* EAPOL stage */
        char* stage  = strtok(rest,",");
        char* bssid  = strtok(NULL,",");
        char* client = strtok(NULL,",\r\n");
        if(!stage||!bssid||!client) break;
        uint8_t s = (uint8_t)parse_u32(stage);
        /* reset if different AP/client pair */
        if(strncmp(app->hs.bssid,  bssid,  MAC_LEN)!=0 ||
           strncmp(app->hs.client, client, MAC_LEN)!=0) {
            app->hs.stage=0; app->hs.complete=false;
        }
        strncpy(app->hs.bssid,  bssid,  MAC_LEN-1);
        strncpy(app->hs.client, client, MAC_LEN-1);
        if(s > app->hs.stage) app->hs.stage=s;
        if(app->hs.stage==4)  app->hs.complete=true;
        app->hs.ts = furi_get_tick();
        /* mirror to capture state if active */
        if(app->capture.active &&
           strncmp(app->capture.target_bssid, bssid, MAC_LEN)==0) {
            if(s > app->capture.stage) app->capture.stage=s;
            if(app->capture.stage>=4)  app->capture.complete=true;
        }
        break;
    }

    case 'A': {  /* SAE stage */
        char* stage  = strtok(rest,",");
        char* bssid  = strtok(NULL,",");
        char* client = strtok(NULL,",\r\n");
        if(!stage||!bssid||!client) break;
        strncpy(app->sae.bssid,  bssid,  MAC_LEN-1);
        strncpy(app->sae.client, client, MAC_LEN-1);
        app->sae.stage = (uint8_t)parse_u32(stage);
        break;
    }

    case 'C': {  /* channel count */
        char* ch    = strtok(rest,",");
        char* count = strtok(NULL,",\r\n");
        if(!ch||!count) break;
        uint8_t  c = (uint8_t)parse_u32(ch);
        uint32_t n = parse_u32(count);
        app->chanmap.active_ch = c;
        if(c>=1 && c<=MAX_CH24) {
            app->chanmap.cnt24[c-1] = n;
        } else {
            for(int i=0; i<MAX_CH5; i++)
                if(CH5_TABLE[i]==c) { app->chanmap.cnt5[i]=n; break; }
        }
        break;
    }

    case 'D': {  /* deauth/disassoc detection */
        char* typ    = strtok(rest,",");
        char* bssid  = strtok(NULL,",");
        char* client = strtok(NULL,",\r\n");
        if(!typ||!bssid||!client) break;
        bool is_da = (parse_u32(typ)==0);
        app->total_deauths++;
        int slot=-1;
        for(int i=0; i<app->deauth_count; i++)
            if(strncmp(app->deauths[i].bssid, bssid, MAC_LEN)==0) { slot=i; break; }
        if(slot<0 && app->deauth_count<MAX_DEAUTH) slot=app->deauth_count++;
        if(slot<0) {
            /* evict lowest-count entry */
            slot=0;
            for(int i=1; i<MAX_DEAUTH; i++)
                if(app->deauths[i].count < app->deauths[slot].count) slot=i;
            app->deauths[slot].count=0;
        }
        strncpy(app->deauths[slot].bssid,  bssid,  MAC_LEN-1);
        strncpy(app->deauths[slot].client, client, MAC_LEN-1);
        app->deauths[slot].count++;
        app->deauths[slot].is_deauth = is_da;
        { char ln[32]; snprintf(ln, sizeof(ln), "Deauth seen %.8s", bssid);
          log_add(app, ln); }
        break;
    }

    case 'P': {  /* PMKID */
        char* bssid = strtok(rest,",");
        char* hex   = strtok(NULL,",\r\n");
        if(!bssid||!hex) break;
        strncpy(app->pmkid.bssid, bssid, MAC_LEN-1);
        for(int i=0; i<16 && hex[i*2] && hex[i*2+1]; i++) {
            uint8_t hi = hex[i*2]   <='9' ? (uint8_t)(hex[i*2]  -'0')
                                           : (uint8_t)((hex[i*2]  &0xDF)-'A'+10);
            uint8_t lo = hex[i*2+1] <='9' ? (uint8_t)(hex[i*2+1]-'0')
                                           : (uint8_t)((hex[i*2+1]&0xDF)-'A'+10);
            app->pmkid.pmkid[i] = (uint8_t)((hi<<4)|lo);
        }
        app->pmkid.valid = true;
        break;
    }

    case 'W': {  /* deauth result */
        char* bssid = strtok(rest,",");
        char* pmf   = strtok(NULL,",\r\n");
        if(!bssid||!pmf) break;
        strncpy(app->last_deauth_result.bssid, bssid, MAC_LEN-1);
        app->last_deauth_result.pmf_result = (uint8_t)parse_u32(pmf);
        app->last_deauth_result.valid = true;
        break;
    }

    case 'K': {  /* raw 802.11 frame hex → buffer for PCAP */
        if(!app->capture.active) break;
        if(app->capture.nframes >= CAP_MAX_FRAMES) break;
        const char* hex = rest;
        int n = 0;
        uint8_t* dst = app->capture.frames[app->capture.nframes];
        while(hex[0] && hex[1] && hex[0]!='\r' && hex[0]!='\n'
              && n < CAP_FRAME_MAX) {
            uint8_t hi = hex[0]<='9'?(hex[0]-'0'):((hex[0]&0xDF)-'A'+10);
            uint8_t lo = hex[1]<='9'?(hex[1]-'0'):((hex[1]&0xDF)-'A'+10);
            dst[n++] = (uint8_t)((hi<<4)|lo);
            hex += 2;
        }
        if(n > 0) {
            app->capture.flen[app->capture.nframes] = (uint16_t)n;
            app->capture.nframes++;
        }
        break;
    }

    case 'G': {  /* pwnagotchi: got a handshake for a BSSID */
        char* bssid = strtok(rest, ",\r\n");
        if(!bssid) break;
        bool seen = false;
        for(int i=0; i<app->pwn_caught_count; i++)
            if(strncmp(app->pwn_caught[i], bssid, MAC_LEN)==0) { seen=true; break; }
        if(!seen && app->pwn_caught_count < 24) {
            strncpy(app->pwn_caught[app->pwn_caught_count], bssid, MAC_LEN-1);
            app->pwn_caught_count++;
            app->pwn_handshakes++;
            char ln[32]; snprintf(ln, sizeof(ln), "*HANDSHAKE %.8s", bssid);
            log_add(app, ln);
            app->notify_hs = true;
            /* keep it: flag for the main thread to write a PCAP to SD */
            if(app->pwn_running && app->capture.nframes > 0
               && !app->pwn_save_pending) {
                strncpy(app->pwn_save_bssid, bssid, MAC_LEN-1);
                app->pwn_save_bssid[MAC_LEN-1] = '\0';
                app->pwn_save_pending = true;
            }
        }
        app->pwn_last_catch = furi_get_tick();
        break;
    }

    case 'Q': {  /* probe request: device <mac> looking for <ssid> */
        char* mac  = strtok(rest, ",");
        char* ssid = strtok(NULL, ",\r\n");
        if(!mac || !ssid) break;
        /* dedup by mac+ssid */
        for(int i=0; i<app->probe_count; i++)
            if(strncmp(app->probe_mac[i], mac, 18)==0 &&
               strncmp(app->probe_ssid[i], ssid, 24)==0) goto probe_done;
        {
            int slot = app->probe_count < 20 ? app->probe_count++ : 19;
            if(slot==19 && app->probe_count>=20) {
                /* shift up, keep newest at bottom */
                for(int i=0;i<19;i++){
                    strncpy(app->probe_mac[i], app->probe_mac[i+1], 18);
                    strncpy(app->probe_ssid[i], app->probe_ssid[i+1], 24);
                }
            }
            strncpy(app->probe_mac[slot], mac, 17);  app->probe_mac[slot][17]='\0';
            strncpy(app->probe_ssid[slot], ssid, 23); app->probe_ssid[slot][23]='\0';
            char ln[32]; snprintf(ln, sizeof(ln), "probe: %.18s", ssid);
            log_add(app, ln);
        }
        probe_done: break;
    }

    case 'T': {  /* station list: <station_mac>,<ap_bssid> */
        char* sta = strtok(rest, ",");
        char* ap  = strtok(NULL, ",\r\n");
        if(!sta || !ap) break;
        for(int i=0; i<app->sta_count; i++)
            if(strncmp(app->sta_mac[i], sta, 18)==0) goto sta_done;
        if(app->sta_count < 20) {
            int s = app->sta_count++;
            strncpy(app->sta_mac[s], sta, 17); app->sta_mac[s][17]='\0';
            strncpy(app->sta_ap[s],  ap,  17); app->sta_ap[s][17]='\0';
        }
        sta_done: break;
    }

    case 'M': {  /* camera detector: <mac>,<vendor>,<ch> */
        char* mac = strtok(rest, ",");
        char* ven = strtok(NULL, ",");
        char* ch  = strtok(NULL, ",\r\n");
        if(!mac || !ven) break;
        for(int i=0; i<app->cam_count; i++)
            if(strncmp(app->cam_mac[i], mac, 18)==0) goto cam_done;
        if(app->cam_count < 16) {
            int s = app->cam_count++;
            strncpy(app->cam_mac[s], mac, 17);    app->cam_mac[s][17]='\0';
            strncpy(app->cam_vendor[s], ven, 15); app->cam_vendor[s][15]='\0';
            app->cam_ch[s] = ch ? (uint8_t)parse_u32(ch) : 0;
            char ln[32]; snprintf(ln, sizeof(ln), "CAM? %.10s %.6s", ven, mac);
            log_add(app, ln);
            app->notify_cam = true;
        }
        cam_done: break;
    }

    case 'O': {  /* portal event */
        char* ev     = strtok(rest,",");
        char* detail = strtok(NULL,",\r\n");
        if(!ev) break;
        uint8_t e = (uint8_t)parse_u32(ev);
        if(e==0) {
            app->portal.active  = true;
            app->portal.clients = 0;
            log_add(app, "Portal AP up");
        } else if(e==1) {
            app->portal.clients++;
            log_add(app, ">> CLIENT CONNECTED");
        } else if(e==2 && detail) {
            strncpy(app->portal.last_creds, detail, 79);
            app->portal.got_creds = true;
            char ln[32]; snprintf(ln, sizeof(ln), "LOGIN %.24s", detail);
            log_add(app, ln);
            app->notify_creds = true;
        } else if(e==4) {
            log_add(app, "DNS query - got IP!");
        } else if(e==7) {
            log_add(app, "AP radio OK");
        } else if(e==9) {
            log_add(app, "!! AP START FAILED");
        }
        break;
    }

    default: break;
    }

    furi_mutex_release(app->data_mutex);
}

/* ── UART RX thread ─────────────────────────────────────────── */
static int32_t uart_thread_fn(void* ctx) {
    WifiStudyApp* app = ctx;

    /* Momentum/OFW run an Expansion Module service that owns the
     * USART. We MUST release it before acquiring the serial port,
     * or acquire() fails (no RX) or asserts (crash). */
    Expansion* expansion = furi_record_open(RECORD_EXPANSION);
    expansion_disable(expansion);

    app->uart_handle = furi_hal_serial_control_acquire(UART_ID);
    if(!app->uart_handle) {
        expansion_enable(expansion);
        furi_record_close(RECORD_EXPANSION);
        app->uart_running = false;
        return -1;
    }

    furi_hal_serial_init(app->uart_handle, UART_BAUD);
    furi_hal_serial_async_rx_start(app->uart_handle, uart_rx_cb, app, false);

    char line[LINE_BUF]; size_t pos=0;
    uint8_t tx[96];
    while(app->uart_running) {
        /* ── RX: assemble lines ── */
        uint8_t b;
        if(furi_stream_buffer_receive(app->uart_buf, &b, 1, furi_ms_to_ticks(20))) {
            app->rx_bytes++;
            if(b=='\n') {
                line[pos]='\0';
                if(pos>0) parse_line(app, line);
                pos=0;
            } else if(b!='\r' && pos<LINE_BUF-1) {
                line[pos++]=(char)b;
            }
        }
        /* ── TX: drain queued commands (serial only touched here) ── */
        size_t tn;
        while((tn = furi_stream_buffer_receive(app->uart_tx_buf, tx, sizeof(tx), 0)) > 0)
            furi_hal_serial_tx(app->uart_handle, tx, tn);
    }

    furi_hal_serial_async_rx_stop(app->uart_handle);
    furi_hal_serial_deinit(app->uart_handle);
    furi_hal_serial_control_release(app->uart_handle);
    app->uart_handle = NULL;

    expansion_enable(expansion);
    furi_record_close(RECORD_EXPANSION);
    return 0;
}

/* ── Public API ─────────────────────────────────────────────── */
void uart_handler_start(WifiStudyApp* app) {
    app->uart_running = true;
    app->uart_handle  = NULL;
    app->uart_buf     = furi_stream_buffer_alloc(4096, 1);
    app->uart_tx_buf  = furi_stream_buffer_alloc(1024, 1);
    app->uart_thread  = furi_thread_alloc_ex("UartRx", 2048,
                                             uart_thread_fn, app);
    furi_thread_start(app->uart_thread);
}

void uart_handler_stop(WifiStudyApp* app) {
    app->uart_running = false;
    furi_thread_join(app->uart_thread);
    furi_thread_free(app->uart_thread);
    furi_stream_buffer_free(app->uart_buf);
    furi_stream_buffer_free(app->uart_tx_buf);
}

/* Queue a command; the worker thread is the only place that
 * actually touches the serial port, avoiding cross-thread faults. */
void uart_send_cmd(WifiStudyApp* app, const char* cmd) {
    if(!cmd || !app->uart_tx_buf) return;
    size_t n = strlen(cmd);
    if(n > 180) n = 180;
    furi_stream_buffer_send(app->uart_tx_buf, cmd, n, 0);
    furi_stream_buffer_send(app->uart_tx_buf, "\n", 1, 0);
}
