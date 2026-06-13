#include "probe_view.h"
#include "../uart_handler.h"
#include <gui/elements.h>
#include <stdio.h>
#include <string.h>

/* Probe Sniffer: shows nearby devices and the WiFi networks their phones
 * are actively searching for (the saved-network names they leak). */

#define ROWS 5
#define ROW_H 10
#define HDR_H 11

typedef struct { WifiStudyApp* app; } ProbeModel;

static void probe_draw_cb(Canvas* canvas, void* model) {
    ProbeModel* pm = (ProbeModel*)model;
    WifiStudyApp* app = pm->app;
    canvas_clear(canvas);

    canvas_draw_box(canvas, 0, 0, 128, HDR_H);
    canvas_set_color(canvas, ColorWhite);
    canvas_set_font(canvas, FontSecondary);
    furi_mutex_acquire(app->data_mutex, FuriWaitForever);
    char hdr[28]; snprintf(hdr, sizeof(hdr), "Probe Sniffer  %d", app->probe_count);
    canvas_draw_str(canvas, 2, 9, hdr);
    if(app->bw16_ok) canvas_draw_box(canvas, 122, 3, 5, 5);
    canvas_set_color(canvas, ColorBlack);

    if(app->probe_count == 0) {
        canvas_draw_str_aligned(canvas, 64, 36, AlignCenter, AlignCenter,
            app->bw16_ok ? "listening for phones..." : "no BW16");
    } else {
        int sc = app->probe_scroll;
        if(sc > app->probe_count - ROWS) sc = app->probe_count - ROWS;
        if(sc < 0) sc = 0;
        for(int i=0; i<ROWS && (sc+i)<app->probe_count; i++) {
            int idx = sc + i;
            uint8_t y = HDR_H + (uint8_t)i*ROW_H + 8;
            char ssid[17]; strncpy(ssid, app->probe_ssid[idx], 16); ssid[16]='\0';
            canvas_draw_str(canvas, 2, y, ssid);
            /* last 5 chars of the MAC, right aligned */
            const char* m = app->probe_mac[idx];
            size_t ml = strlen(m);
            canvas_draw_str(canvas, 92, y, ml>5 ? m+ml-5 : m);
        }
    }
    furi_mutex_release(app->data_mutex);
}

static bool probe_input_cb(InputEvent* ev, void* context) {
    ProbeModel* pm = (ProbeModel*)context;
    WifiStudyApp* app = pm->app;
    if(ev->type != InputTypeShort && ev->type != InputTypeRepeat) return false;
    if(ev->key == InputKeyBack) { uart_send_cmd(app, "CMD,STOP"); return false; }
    furi_mutex_acquire(app->data_mutex, FuriWaitForever);
    if(ev->key == InputKeyUp && app->probe_scroll > 0) app->probe_scroll--;
    if(ev->key == InputKeyDown && app->probe_scroll + ROWS < app->probe_count)
        app->probe_scroll++;
    furi_mutex_release(app->data_mutex);
    return true;
}

static void probe_enter_cb(void* context) {
    ProbeModel* pm = (ProbeModel*)context;
    furi_mutex_acquire(pm->app->data_mutex, FuriWaitForever);
    pm->app->probe_scroll = 0;
    furi_mutex_release(pm->app->data_mutex);
    uart_send_cmd(pm->app, "CMD,PROBE");
}

View* probe_view_alloc(WifiStudyApp* app) {
    View* v = view_alloc();
    view_allocate_model(v, ViewModelTypeLocking, sizeof(ProbeModel));
    ProbeModel* m = view_get_model(v);
    m->app = app;
    view_commit_model(v, false);
    view_set_context(v, m);
    view_set_draw_callback(v, probe_draw_cb);
    view_set_input_callback(v, probe_input_cb);
    view_set_enter_callback(v, probe_enter_cb);
    return v;
}

void probe_view_free(View* v) { view_free(v); }
