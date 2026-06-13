#include "capture_view.h"
#include "../uart_handler.h"
#include <gui/elements.h>
#include <stdio.h>
#include <string.h>

/* Capture Handshake:
 *   PICK   – choose an AP from the last scan
 *   STATUS – BW16 deauths the target & we watch EAPOL 1->4,
 *            OK saves to /ext/wifi_study/, Back aborts.        */

#define ROWS  4
#define ROW_H 12
#define HDR_H 12

typedef enum { PG_PICK, PG_STATUS } CapPage;
typedef struct {
    WifiStudyApp* app;
    CapPage page;
    int     sel;
    int     scroll;
} CaptureModel;

/* ── Picker ─────────────────────────────────────────────────── */
static void draw_pick(Canvas* canvas, WifiStudyApp* app, CaptureModel* cm) {
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_box(canvas, 0, 0, 128, HDR_H);
    canvas_set_color(canvas, ColorWhite);
    canvas_draw_str(canvas, 2, 9, "Capture: pick AP");
    if(app->bw16_ok) canvas_draw_box(canvas, 118, 3, 6, 6);
    canvas_set_color(canvas, ColorBlack);
    canvas_set_font(canvas, FontSecondary);

    if(app->ap_count == 0) {
        canvas_draw_str_aligned(canvas, 64, 36, AlignCenter, AlignCenter,
            app->bw16_ok ? "No APs yet - wait" : "No BW16 link");
        canvas_draw_str_aligned(canvas, 64, 50, AlignCenter, AlignCenter,
            "Run a scan first");
        return;
    }

    for(int i=0; i<ROWS && (cm->scroll+i)<app->ap_count; i++) {
        const ApRecord* ap = &app->aps[cm->scroll+i];
        uint8_t y = HDR_H + (uint8_t)i*ROW_H;
        bool sel = (cm->scroll+i == cm->sel);
        if(sel) { canvas_draw_box(canvas, 0, y, 128, ROW_H);
                  canvas_set_color(canvas, ColorWhite); }
        char ssid[15]; strncpy(ssid, ap->ssid, 14); ssid[14]='\0';
        canvas_draw_str(canvas, 2, y+9, ssid);
        char ch[5]; snprintf(ch, sizeof(ch), "%u", ap->channel);
        canvas_draw_str(canvas, 98, y+9, ch);
        const char* sl = ap->security<6 ? SEC_LABEL[ap->security] : "?";
        canvas_draw_str(canvas, 112, y+9, sl);
        if(sel) canvas_set_color(canvas, ColorBlack);
    }
}

/* ── Status ─────────────────────────────────────────────────── */
static void draw_progress(Canvas* canvas, uint8_t stage) {
    static const char* labels[] = {"ANon","SNon","GTK","ACK"};
    for(int i=0; i<4; i++) {
        uint8_t x = (uint8_t)(2 + i*31);
        if((int)stage > i) { canvas_draw_box(canvas, x, 26, 29, 12);
                             canvas_set_color(canvas, ColorWhite); }
        else                 canvas_draw_frame(canvas, x, 26, 29, 12);
        canvas_draw_str_aligned(canvas, x+14, 35, AlignCenter, AlignBottom,
                                labels[i]);
        canvas_set_color(canvas, ColorBlack);
    }
}

static void draw_status(Canvas* canvas, WifiStudyApp* app) {
    char tgt[22]; uint8_t stage; bool complete, saved, pmkid; int nframes;
    furi_mutex_acquire(app->data_mutex, FuriWaitForever);
    strncpy(tgt, app->capture.target_ssid[0] ? app->capture.target_ssid
                                              : app->capture.target_bssid, 21);
    tgt[21]='\0';
    stage    = app->capture.stage;
    complete = app->capture.complete;
    saved    = app->capture.saved;
    nframes  = app->capture.nframes;
    pmkid    = app->pmkid.valid &&
               strncmp(app->pmkid.bssid, app->capture.target_bssid, MAC_LEN)==0;
    furi_mutex_release(app->data_mutex);

    canvas_set_font(canvas, FontPrimary);
    canvas_draw_box(canvas, 0, 0, 128, HDR_H);
    canvas_set_color(canvas, ColorWhite);
    canvas_draw_str(canvas, 2, 9, "Capturing...");
    canvas_set_color(canvas, ColorBlack);
    canvas_set_font(canvas, FontSecondary);

    canvas_draw_str(canvas, 2, 22, tgt);
    if(pmkid) canvas_draw_str(canvas, 100, 22, "PMK");

    draw_progress(canvas, stage);
    canvas_draw_line(canvas, 0, 41, 127, 41);

    if(complete && saved) {
        canvas_draw_str(canvas, 2, 52, "Saved .pcap to SD:");
        canvas_draw_str(canvas, 2, 62, "/ext/wifi_study/");
    } else if(complete) {
        char s[26];
        snprintf(s, sizeof(s), "DONE - %d frames", nframes);
        canvas_set_font(canvas, FontPrimary);
        canvas_draw_str(canvas, 2, 53, s);
        canvas_set_font(canvas, FontSecondary);
        canvas_draw_str(canvas, 2, 62, "OK=save  Back=exit");
    } else {
        char s[26]; snprintf(s, sizeof(s), "Stage %u/4  %d fr", stage, nframes);
        canvas_draw_str(canvas, 2, 52, s);
        canvas_draw_str(canvas, 2, 62, "deauth on  Back=stop");
    }
}

static void capture_draw_cb(Canvas* canvas, void* model) {
    CaptureModel* cm = (CaptureModel*)model;
    WifiStudyApp* app = cm->app;
    canvas_clear(canvas);
    if(cm->page == PG_STATUS) { draw_status(canvas, app); return; }

    furi_mutex_acquire(app->data_mutex, FuriWaitForever);
    if(cm->sel >= app->ap_count) cm->sel = app->ap_count>0?app->ap_count-1:0;
    if(cm->sel < 0) cm->sel = 0;
    if(cm->scroll > cm->sel) cm->scroll = cm->sel;
    if(cm->sel >= cm->scroll+ROWS) cm->scroll = cm->sel-ROWS+1;
    if(cm->scroll < 0) cm->scroll = 0;
    draw_pick(canvas, app, cm);
    furi_mutex_release(app->data_mutex);
}

static bool capture_input_cb(InputEvent* ev, void* model) {
    CaptureModel* cm = (CaptureModel*)model;
    WifiStudyApp* app = cm->app;
    if(ev->type != InputTypeShort && ev->type != InputTypeRepeat) return false;

    if(cm->page == PG_STATUS) {
        furi_mutex_acquire(app->data_mutex, FuriWaitForever);
        bool complete = app->capture.complete;
        bool saved    = app->capture.saved;
        furi_mutex_release(app->data_mutex);
        if(ev->key == InputKeyOk && complete && !saved) {
            save_handshake_to_sd(app); return true;
        }
        if(ev->key == InputKeyBack) {
            uart_send_cmd(app, "CMD,STOP");
            furi_mutex_acquire(app->data_mutex, FuriWaitForever);
            app->capture.active = false;
            furi_mutex_release(app->data_mutex);
            cm->page = PG_PICK;
            return true;
        }
        return true;
    }

    /* PG_PICK */
    if(ev->key == InputKeyBack) return false;

    furi_mutex_acquire(app->data_mutex, FuriWaitForever);
    int total = app->ap_count;
    char bssid[MAC_LEN]={0}, ssid[SSID_LEN]={0}; uint8_t ch=0;
    if(cm->sel>=0 && cm->sel<total) {
        strncpy(bssid, app->aps[cm->sel].bssid, MAC_LEN-1);
        strncpy(ssid,  app->aps[cm->sel].ssid,  SSID_LEN-1);
        ch = app->aps[cm->sel].channel;
    }
    furi_mutex_release(app->data_mutex);

    if(ev->key == InputKeyUp)   { if(cm->sel>0) cm->sel--; }
    else if(ev->key == InputKeyDown) { if(cm->sel+1<total) cm->sel++; }
    else if(ev->key == InputKeyOk && total>0) {
        furi_mutex_acquire(app->data_mutex, FuriWaitForever);
        memset(&app->capture, 0, sizeof(CaptureState));
        strncpy(app->capture.target_bssid, bssid, MAC_LEN-1);
        strncpy(app->capture.target_ssid,  ssid,  SSID_LEN-1);
        app->capture.target_ch = ch;
        app->capture.active    = true;
        furi_mutex_release(app->data_mutex);
        char cmd[64];
        snprintf(cmd, sizeof(cmd), "CMD,CAPTURE,%s,%u", bssid, ch);
        uart_send_cmd(app, cmd);
        cm->page = PG_STATUS;
    }
    return true;
}

View* capture_view_alloc(WifiStudyApp* app) {
    View* v = view_alloc();
    view_allocate_model(v, ViewModelTypeLocking, sizeof(CaptureModel));
    CaptureModel* m = view_get_model(v);
    m->app=app; m->page=PG_PICK; m->sel=0; m->scroll=0;
    view_commit_model(v, false);
    view_set_context(v, m);
    view_set_draw_callback(v, capture_draw_cb);
    view_set_input_callback(v, capture_input_cb);
    return v;
}

void capture_view_free(View* v) { view_free(v); }
