#include "deauthall_view.h"
#include "../uart_handler.h"
#include <gui/elements.h>
#include <stdio.h>
#include <string.h>

/* Deauth-All module: on open, tells the BW16 to channel-hop and deauth
 * every AP it can hear; on back, stops. Shows a live "attacking" screen. */

typedef struct { WifiStudyApp* app; uint32_t enter_tick; } DAllModel;

static void dall_draw_cb(Canvas* canvas, void* model) {
    DAllModel* dm = (DAllModel*)model;
    WifiStudyApp* app = dm->app;
    canvas_clear(canvas);

    canvas_set_font(canvas, FontPrimary);
    canvas_draw_box(canvas, 0, 0, 128, 12);
    canvas_set_color(canvas, ColorWhite);
    canvas_draw_str(canvas, 2, 9, "Deauth ALL");
    canvas_set_color(canvas, ColorBlack);
    canvas_set_font(canvas, FontSecondary);

    furi_mutex_acquire(app->data_mutex, FuriWaitForever);
    int aps = app->ap_count;
    bool ok = app->bw16_ok;
    furi_mutex_release(app->data_mutex);

    /* animated radiating arcs = transmitting */
    uint32_t t = furi_get_tick() / (furi_kernel_get_tick_frequency()/4 + 1);
    for(int r = 1; r <= 3; r++) {
        if(((t + r) % 3) == 0)
            canvas_draw_circle(canvas, 64, 32, r*6);
    }
    canvas_draw_disc(canvas, 64, 32, 2);

    char l[28];
    snprintf(l, sizeof(l), "Jamming ~%d networks", aps);
    canvas_draw_str_aligned(canvas, 64, 50, AlignCenter, AlignCenter, l);

    canvas_draw_line(canvas, 0, 54, 127, 54);
    canvas_draw_str(canvas, 2, 63,
                    ok ? "TX on all ch  Back=stop" : "no BW16!  Back=stop");
}

static bool dall_input_cb(InputEvent* ev, void* context) {
    DAllModel* dm = (DAllModel*)context;
    if(ev->type != InputTypeShort) return false;
    if(ev->key == InputKeyBack) {
        uart_send_cmd(dm->app, "CMD,STOP");
        return false;
    }
    return true;
}

static void dall_enter_cb(void* context) {
    DAllModel* dm = (DAllModel*)context;
    WifiStudyApp* app = dm->app;
    dm->enter_tick = furi_get_tick();

    /* feed the BW16 every AP we already know from the scan, then start */
    uart_send_cmd(app, "CMD,DCLR");
    furi_mutex_acquire(app->data_mutex, FuriWaitForever);
    int n = app->ap_count;
    for(int i=0; i<n && i<32; i++) {
        char cmd[48];
        snprintf(cmd, sizeof(cmd), "CMD,DADD,%s,%u",
                 app->aps[i].bssid, app->aps[i].channel);
        furi_mutex_release(app->data_mutex);
        uart_send_cmd(app, cmd);
        furi_delay_ms(6);            /* don't overrun the BW16 UART */
        furi_mutex_acquire(app->data_mutex, FuriWaitForever);
    }
    furi_mutex_release(app->data_mutex);
    uart_send_cmd(app, "CMD,DALL");
}

View* deauthall_view_alloc(WifiStudyApp* app) {
    View* v = view_alloc();
    view_allocate_model(v, ViewModelTypeLocking, sizeof(DAllModel));
    DAllModel* m = view_get_model(v);
    m->app = app; m->enter_tick = 0;
    view_commit_model(v, false);
    view_set_context(v, m);
    view_set_draw_callback(v, dall_draw_cb);
    view_set_input_callback(v, dall_input_cb);
    view_set_enter_callback(v, dall_enter_cb);
    return v;
}

void deauthall_view_free(View* v) { view_free(v); }
