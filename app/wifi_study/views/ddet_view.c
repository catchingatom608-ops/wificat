#include "ddet_view.h"
#include "../uart_handler.h"
#include <gui/elements.h>
#include <stdio.h>
#include <string.h>

/* Deauth Detector: passive "are you being attacked?" monitor. */

#define ROWS 3
#define ROW_H 11
#define HDR_H 12

typedef struct { WifiStudyApp* app; uint32_t last_total; uint32_t flash_t; } DdetModel;

static void ddet_draw_cb(Canvas* canvas, void* model) {
    DdetModel* dm = (DdetModel*)model;
    WifiStudyApp* app = dm->app;
    canvas_clear(canvas);

    furi_mutex_acquire(app->data_mutex, FuriWaitForever);
    uint32_t total = app->total_deauths;
    int dc = app->deauth_count;
    /* detect a fresh burst -> alarm flash */
    if(total != dm->last_total) { dm->last_total = total; dm->flash_t = furi_get_tick(); }
    bool alarm = (dm->flash_t && furi_get_tick() - dm->flash_t < furi_ms_to_ticks(2500));

    canvas_set_font(canvas, FontPrimary);
    canvas_draw_box(canvas, 0, 0, 128, HDR_H);
    canvas_set_color(canvas, ColorWhite);
    canvas_draw_str(canvas, 2, 9, alarm ? "!! DEAUTH ATTACK !!" : "Deauth Detector");
    canvas_set_color(canvas, ColorBlack);
    canvas_set_font(canvas, FontSecondary);

    char l[28]; snprintf(l, sizeof(l), "Total seen: %lu", (unsigned long)total);
    canvas_draw_str(canvas, 2, 22, l);

    if(dc == 0) {
        canvas_draw_str(canvas, 2, 36, total ? "" : "no attacks yet - safe");
    } else {
        for(int i=0; i<ROWS && i<dc; i++) {
            const DeauthEntry* e = &app->deauths[i];
            uint8_t y = 24 + (uint8_t)(i+1)*ROW_H;
            char r[28]; snprintf(r, sizeof(r), "%s %.11s x%u",
                                 e->is_deauth?"DA":"DI", e->bssid, e->count);
            canvas_draw_str(canvas, 2, y, r);
        }
    }
    furi_mutex_release(app->data_mutex);
    canvas_draw_str(canvas, 2, 63, "Back=stop");
}

static bool ddet_input_cb(InputEvent* ev, void* context) {
    DdetModel* dm = (DdetModel*)context;
    if(ev->type != InputTypeShort) return false;
    if(ev->key == InputKeyBack) { uart_send_cmd(dm->app, "CMD,STOP"); return false; }
    return true;
}

static void ddet_enter_cb(void* context) {
    DdetModel* dm = (DdetModel*)context;
    furi_mutex_acquire(dm->app->data_mutex, FuriWaitForever);
    dm->app->deauth_count = 0; dm->app->total_deauths = 0;
    furi_mutex_release(dm->app->data_mutex);
    dm->last_total = 0; dm->flash_t = 0;
    uart_send_cmd(dm->app, "CMD,DDET");
}

View* ddet_view_alloc(WifiStudyApp* app) {
    View* v = view_alloc();
    view_allocate_model(v, ViewModelTypeLocking, sizeof(DdetModel));
    DdetModel* m = view_get_model(v);
    m->app = app; m->last_total = 0; m->flash_t = 0;
    view_commit_model(v, false);
    view_set_context(v, m);
    view_set_draw_callback(v, ddet_draw_cb);
    view_set_input_callback(v, ddet_input_cb);
    view_set_enter_callback(v, ddet_enter_cb);
    return v;
}

void ddet_view_free(View* v) { view_free(v); }
