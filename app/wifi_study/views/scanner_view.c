#include "scanner_view.h"
#include "../uart_handler.h"
#include <gui/elements.h>
#include <stdio.h>
#include <string.h>

/*
 * Scanner = the one place to see APs and act on them.
 *   List:   Up/Down move selection, OK opens the action hub.
 *   Detail: shows AP info + PMF status, with actions:
 *             OK    -> PMF-aware deauth (won't fire if PMF required)
 *             Right -> Capture handshake (switch to capture view)
 *             Down  -> Evil portal clone (switch to portal view)
 *             Left/Back -> back to list
 */

#define ROWS_VIS 4
#define ROW_H    12
#define HDR_H    12

typedef struct {
    WifiStudyApp* app;
    int  sel;          /* selected AP index */
    int  scroll;       /* top visible row   */
    bool detail;       /* false = list, true = action hub */
    bool deauthing;    /* sustained deauth running on this AP */
    char status[26];   /* transient action feedback */
} ScannerModel;

/* ── Signal bars ────────────────────────────────────────────── */
static uint8_t rssi_bars(int8_t r) {
    if(r >= -50) return 5;
    if(r >= -60) return 4;
    if(r >= -70) return 3;
    if(r >= -80) return 2;
    if(r >= -88) return 1;
    return 0;
}
static void draw_bars(Canvas* c, uint8_t x, uint8_t y, uint8_t bars) {
    for(uint8_t i=0; i<5; i++) {
        uint8_t h = 2+i*2, bx = x+i*3, by = y-h+1;
        if(i<bars) canvas_draw_box(c, bx, by, 2, h);
        else        canvas_draw_frame(c, bx, by, 2, h);
    }
}

/* ── List ───────────────────────────────────────────────────── */
static void draw_list(Canvas* canvas, WifiStudyApp* app, ScannerModel* sm) {
    canvas_draw_box(canvas, 0, 0, 128, HDR_H);
    canvas_set_color(canvas, ColorWhite);
    canvas_set_font(canvas, FontSecondary);  /* small font fits the hint */
    char hdr[28];
    snprintf(hdr, sizeof(hdr), "Scan: %d networks", app->ap_count);
    canvas_draw_str(canvas, 2, 9, hdr);
    if(app->bw16_ok) canvas_draw_box(canvas, 122, 3, 5, 5);
    canvas_set_color(canvas, ColorBlack);

    if(app->ap_count == 0) {
        canvas_draw_str_aligned(canvas, 64, 36, AlignCenter, AlignCenter,
                                "Searching for networks");
        canvas_draw_str_aligned(canvas, 64, 48, AlignCenter, AlignCenter,
                                "please wait...");
        return;
    }

    for(int i=0; i<ROWS_VIS && (sm->scroll+i)<app->ap_count; i++) {
        const ApRecord* ap = &app->aps[sm->scroll+i];
        uint8_t y = HDR_H + (uint8_t)i*ROW_H;
        bool sel = (sm->scroll+i == sm->sel);
        if(sel) {
            canvas_draw_box(canvas, 0, y, 128, ROW_H);
            canvas_set_color(canvas, ColorWhite);
        }
        draw_bars(canvas, 2, y+ROW_H-2, rssi_bars(ap->rssi));

        char ssid[12]; strncpy(ssid, ap->ssid, 11); ssid[11]='\0';
        canvas_draw_str(canvas, 18, y+9, ssid);

        char ch[5];
        if(ap->channel >= 36) snprintf(ch, sizeof(ch), "*%u", ap->channel);
        else                  snprintf(ch, sizeof(ch), "%u", ap->channel);
        canvas_draw_str(canvas, 80, y+9, ch);

        /* short 3-char security code, PMF marker after it */
        static const char* SC[] = {"OPN","WEP","WPA","WP2","WP3","MIX"};
        const char* sl = ap->security < 6 ? SC[ap->security] : "?";
        canvas_draw_str(canvas, 100, y+9, sl);
        if(ap->pmf == 2)      canvas_draw_str(canvas, 120, y+9, "!");
        else if(ap->pmf == 1) canvas_draw_str(canvas, 120, y+9, "?");

        if(sel) canvas_set_color(canvas, ColorBlack);
    }

    if(app->ap_count > ROWS_VIS) {
        uint8_t bh = 64-HDR_H;
        uint8_t th = (uint8_t)(bh*ROWS_VIS/app->ap_count);
        uint8_t ty = (uint8_t)(HDR_H + bh*sm->scroll/app->ap_count);
        canvas_draw_frame(canvas, 126, HDR_H, 2, bh);
        canvas_draw_box(canvas,  126, ty, 2, th>2?th:2);
    }
}

/* ── Detail / action hub ────────────────────────────────────── */
static void draw_detail(Canvas* canvas, WifiStudyApp* app, ScannerModel* sm) {
    if(sm->sel < 0 || sm->sel >= app->ap_count) { sm->detail = false; return; }
    const ApRecord* ap = &app->aps[sm->sel];

    canvas_set_font(canvas, FontPrimary);
    canvas_draw_box(canvas, 0, 0, 128, HDR_H);
    canvas_set_color(canvas, ColorWhite);
    char hdr[16]; strncpy(hdr, ap->ssid, 15); hdr[15]='\0';
    canvas_draw_str_aligned(canvas, 64, 9, AlignCenter, AlignCenter, hdr);
    canvas_set_color(canvas, ColorBlack);
    canvas_set_font(canvas, FontSecondary);

    canvas_draw_str(canvas, 2, 21, ap->bssid);

    char l2[26];
    snprintf(l2, sizeof(l2), "%ddBm CH%u %s",
             (int)ap->rssi, ap->channel, ap->channel>=36 ? "5G":"2.4G");
    canvas_draw_str(canvas, 2, 31, l2);
    draw_bars(canvas, 110, 31, rssi_bars(ap->rssi));

    char l3[26];
    const char* sl = ap->security < 6 ? SEC_LABEL[ap->security] : "?";
    const char* pf = ap->pmf==2 ? "PMF:REQ" : (ap->pmf==1 ? "PMF:opt" : "PMF:off");
    snprintf(l3, sizeof(l3), "%s  %s", sl, pf);
    canvas_draw_str(canvas, 2, 41, l3);

    canvas_draw_line(canvas, 0, 44, 127, 44);

    if(sm->deauthing) {
        canvas_draw_box(canvas, 0, 46, 128, 10);
        canvas_set_color(canvas, ColorWhite);
        canvas_set_font(canvas, FontPrimary);
        canvas_draw_str(canvas, 2, 54, "** DEAUTHING **");
        canvas_set_color(canvas, ColorBlack);
        canvas_set_font(canvas, FontSecondary);
        canvas_draw_str(canvas, 2, 63, "OK=stop   Back=stop");
    } else if(sm->status[0]) {
        canvas_set_font(canvas, FontPrimary);
        canvas_draw_str(canvas, 2, 55, sm->status);
        canvas_set_font(canvas, FontSecondary);
        canvas_draw_str(canvas, 2, 63, "Back=list");
    } else {
        canvas_set_font(canvas, FontPrimary);
        canvas_draw_str(canvas, 2, 56, "OK = Deauth");
        canvas_set_font(canvas, FontSecondary);
        canvas_draw_str(canvas, 90, 56, "Back=list");
    }
}

static void scanner_draw_cb(Canvas* canvas, void* model) {
    ScannerModel* sm = (ScannerModel*)model;
    WifiStudyApp* app = sm->app;
    canvas_clear(canvas);
    furi_mutex_acquire(app->data_mutex, FuriWaitForever);

    /* clamp selection to live AP count */
    if(sm->sel >= app->ap_count) sm->sel = app->ap_count>0 ? app->ap_count-1 : 0;
    if(sm->sel < 0) sm->sel = 0;
    if(sm->scroll > sm->sel) sm->scroll = sm->sel;
    if(sm->sel >= sm->scroll+ROWS_VIS) sm->scroll = sm->sel-ROWS_VIS+1;
    if(sm->scroll < 0) sm->scroll = 0;

    /* pick up a deauth result for the selected AP */
    if(sm->detail && app->last_deauth_result.valid &&
       sm->sel < app->ap_count &&
       strncmp(app->last_deauth_result.bssid, app->aps[sm->sel].bssid, MAC_LEN)==0) {
        switch(app->last_deauth_result.pmf_result) {
        case 0: strncpy(sm->status, "Deauth sent!",    25); break;
        case 1: strncpy(sm->status, "PMF opt-may fail", 25); break;
        case 2: strncpy(sm->status, "PMF REQ: immune", 25); break;
        }
        sm->status[25]='\0';
        app->last_deauth_result.valid = false;
    }

    if(sm->detail) draw_detail(canvas, app, sm);
    else           draw_list(canvas, app, sm);
    furi_mutex_release(app->data_mutex);
}

/* ── Input ──────────────────────────────────────────────────── */
static bool scanner_input_cb(InputEvent* ev, void* model) {
    ScannerModel* sm = (ScannerModel*)model;
    WifiStudyApp* app = sm->app;
    if(ev->type != InputTypeShort && ev->type != InputTypeRepeat
       && ev->type != InputTypeLong) return false;

    /* snapshot what we need under the lock */
    furi_mutex_acquire(app->data_mutex, FuriWaitForever);
    int total = app->ap_count;
    int sel   = sm->sel;
    char bssid[MAC_LEN] = {0};
    char ssid[SSID_LEN] = {0};
    uint8_t ch = 0, pmf = 0;
    if(sel >= 0 && sel < total) {
        strncpy(bssid, app->aps[sel].bssid, MAC_LEN-1);
        strncpy(ssid,  app->aps[sel].ssid,  SSID_LEN-1);
        ch  = app->aps[sel].channel;
        pmf = app->aps[sel].pmf;
    }
    furi_mutex_release(app->data_mutex);

    if(!sm->detail) {
        /* ── List ── */
        if(ev->key == InputKeyBack) return false;
        if(ev->type == InputTypeLong) return true;
        if(ev->key == InputKeyUp) {
            if(sm->sel > 0) sm->sel--;
        } else if(ev->key == InputKeyDown) {
            if(sm->sel+1 < total) sm->sel++;
        } else if(ev->key == InputKeyOk && total > 0) {
            sm->status[0] = '\0';
            sm->detail = true;
        }
        return true;
    }

    /* ── Detail / action hub ── */
    if(ev->key == InputKeyLeft || ev->key == InputKeyBack) {
        if(sm->deauthing) { uart_send_cmd(app, "CMD,STOP"); sm->deauthing=false; }
        sm->detail = false;
        sm->status[0] = '\0';
        return true;
    }
    if(total == 0 || sel < 0 || sel >= total) { sm->detail=false; return true; }

    UNUSED(ssid);
    if(ev->key == InputKeyOk) {
        if(sm->deauthing) {
            /* stop the sustained attack */
            uart_send_cmd(app, "CMD,STOP");
            sm->deauthing = false;
            strncpy(sm->status, "Deauth stopped", 25); sm->status[25]='\0';
        } else if(pmf == PMF_REQUIRED) {
            strncpy(sm->status, "PMF REQ: immune", 25); sm->status[25]='\0';
        } else {
            /* start sustained deauth on this AP */
            char cmd[64];
            snprintf(cmd, sizeof(cmd), "CMD,DEAUTH,%s,%u", bssid, ch);
            uart_send_cmd(app, cmd);
            sm->deauthing = true;
            sm->status[0] = '\0';
        }
    }
    return true;
}

/* Ask the BW16 for a fresh scan whenever this view opens */
static void scanner_enter_cb(void* context) {
    ScannerModel* sm = (ScannerModel*)context;
    uart_send_cmd(sm->app, "CMD,SCAN");
}

View* scanner_view_alloc(WifiStudyApp* app) {
    View* v = view_alloc();
    view_allocate_model(v, ViewModelTypeLocking, sizeof(ScannerModel));
    ScannerModel* m = view_get_model(v);
    m->app    = app;
    m->sel    = 0;
    m->scroll = 0;
    m->detail = false;
    m->status[0] = '\0';
    view_commit_model(v, false);
    /* input callback receives CONTEXT, not model — point it at the model */
    view_set_context(v, m);
    view_set_draw_callback(v, scanner_draw_cb);
    view_set_input_callback(v, scanner_input_cb);
    view_set_enter_callback(v, scanner_enter_cb);
    return v;
}

void scanner_view_free(View* v) { view_free(v); }
