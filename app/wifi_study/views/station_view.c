#include "station_view.h"
#include "../uart_handler.h"
#include <gui/elements.h>
#include <stdio.h>
#include <string.h>

/* Station list: devices (clients) and which AP they're talking to. */

#define ROWS 4
#define ROW_H 11
#define HDR_H 11

typedef struct { WifiStudyApp* app; } StaModel;

static void sta_draw_cb(Canvas* canvas, void* model) {
    StaModel* sm = (StaModel*)model;
    WifiStudyApp* app = sm->app;
    canvas_clear(canvas);

    canvas_draw_box(canvas, 0, 0, 128, HDR_H);
    canvas_set_color(canvas, ColorWhite);
    canvas_set_font(canvas, FontSecondary);
    furi_mutex_acquire(app->data_mutex, FuriWaitForever);
    char hdr[28]; snprintf(hdr, sizeof(hdr), "Stations  %d", app->sta_count);
    canvas_draw_str(canvas, 2, 9, hdr);
    if(app->bw16_ok) canvas_draw_box(canvas, 122, 3, 5, 5);
    canvas_set_color(canvas, ColorBlack);

    if(app->sta_count == 0) {
        canvas_draw_str_aligned(canvas, 64, 32, AlignCenter, AlignCenter,
            app->bw16_ok ? "sniffing clients..." : "no BW16");
    } else {
        int sc = app->sta_scroll;
        if(sc > app->sta_count - ROWS) sc = app->sta_count - ROWS;
        if(sc < 0) sc = 0;
        for(int i=0; i<ROWS && (sc+i)<app->sta_count; i++) {
            int idx = sc + i;
            uint8_t y = HDR_H + (uint8_t)i*ROW_H + 8;
            /* device MAC (last 8) -> AP (last 8) */
            const char* s = app->sta_mac[idx];
            const char* a = app->sta_ap[idx];
            char r[28]; snprintf(r, sizeof(r), "%s>%s",
                                 strlen(s)>8?s+9:s, strlen(a)>8?a+9:a);
            canvas_draw_str(canvas, 2, y, r);
        }
    }
    furi_mutex_release(app->data_mutex);
}

static bool sta_input_cb(InputEvent* ev, void* context) {
    StaModel* sm = (StaModel*)context;
    WifiStudyApp* app = sm->app;
    if(ev->type != InputTypeShort && ev->type != InputTypeRepeat) return false;
    if(ev->key == InputKeyBack) { uart_send_cmd(app, "CMD,STOP"); return false; }
    furi_mutex_acquire(app->data_mutex, FuriWaitForever);
    if(ev->key == InputKeyUp && app->sta_scroll > 0) app->sta_scroll--;
    if(ev->key == InputKeyDown && app->sta_scroll + ROWS < app->sta_count)
        app->sta_scroll++;
    furi_mutex_release(app->data_mutex);
    return true;
}

static void sta_enter_cb(void* context) {
    StaModel* sm = (StaModel*)context;
    furi_mutex_acquire(sm->app->data_mutex, FuriWaitForever);
    sm->app->sta_count = 0; sm->app->sta_scroll = 0;
    furi_mutex_release(sm->app->data_mutex);
    uart_send_cmd(sm->app, "CMD,STA");
}

View* station_view_alloc(WifiStudyApp* app) {
    View* v = view_alloc();
    view_allocate_model(v, ViewModelTypeLocking, sizeof(StaModel));
    StaModel* m = view_get_model(v);
    m->app = app;
    view_commit_model(v, false);
    view_set_context(v, m);
    view_set_draw_callback(v, sta_draw_cb);
    view_set_input_callback(v, sta_input_cb);
    view_set_enter_callback(v, sta_enter_cb);
    return v;
}

void station_view_free(View* v) { view_free(v); }
