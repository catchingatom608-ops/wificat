#include "protocol_view.h"
#include "../uart_handler.h"
#include <gui/elements.h>
#include <stdio.h>
#include <string.h>

typedef enum { PAGE_WPA2, PAGE_WPA3 } ProtoPage;
typedef struct { WifiStudyApp* app; ProtoPage page; } ProtoModel;

/* ── WPA2 ─────────────────────────────────────────────────*/
static void draw_wpa2(Canvas* canvas, WifiStudyApp* app) {
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_box(canvas, 0, 0, 128, 12);
    canvas_set_color(canvas, ColorWhite);
    canvas_draw_str(canvas, 2, 9, "WPA2 4-Way");
    canvas_set_color(canvas, ColorBlack);
    canvas_set_font(canvas, FontSecondary);

    furi_mutex_acquire(app->data_mutex, FuriWaitForever);
    uint8_t stage    = app->hs.stage;
    bool    complete = app->hs.complete;
    char    bssid[9], client[9];
    strncpy(bssid,  app->hs.bssid,  8); bssid[8]  = '\0';
    strncpy(client, app->hs.client, 8); client[8] = '\0';

    /* PMKID */
    bool has_pmkid = app->pmkid.valid &&
                     strncmp(app->pmkid.bssid, app->hs.bssid, MAC_LEN) == 0;
    furi_mutex_release(app->data_mutex);

    /* Step rows */
    static const struct { const char* label; bool ap_src; } steps[4] = {
        { "1: ANonce      AP>STA", true  },
        { "2: SNonce+MIC  STA>AP", false },
        { "3: GTK+MIC     AP>STA", true  },
        { "4: ACK         STA>AP", false },
    };

    for(int i = 0; i < 4; i++) {
        uint8_t y = 14 + i * 10;
        bool seen = (int)stage > i;

        if(seen) {
            canvas_draw_box(canvas, 0, y, 128, 10);
            canvas_set_color(canvas, ColorWhite);
        }
        canvas_draw_str(canvas, 2, y + 8, steps[i].label);
        /* Checkmark */
        if(seen) canvas_draw_str(canvas, 116, y + 8, "\x7e");
        canvas_set_color(canvas, ColorBlack);
    }

    /* Status bar */
    canvas_draw_line(canvas, 0, 54, 127, 54);
    if(stage == 0) {
        canvas_draw_str(canvas, 2, 63, "Listening...");
    } else if(complete) {
        char s[32];
        snprintf(s, sizeof(s), "DONE  AP:%s", bssid);
        canvas_draw_str(canvas, 2, 63, s);
    } else {
        char s[32];
        snprintf(s, sizeof(s), "Stage %u  AP:%s", stage, bssid);
        canvas_draw_str(canvas, 2, 63, s);
    }

    /* PMKID indicator */
    if(has_pmkid) {
        canvas_draw_str(canvas, 90, 9, "PMKID!");
    }
    UNUSED(client);
}

/* ── WPA3 ─────────────────────────────────────────────────*/
static void draw_wpa3(Canvas* canvas, WifiStudyApp* app) {
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_box(canvas, 0, 0, 128, 12);
    canvas_set_color(canvas, ColorWhite);
    canvas_draw_str(canvas, 2, 9, "WPA3 SAE");
    canvas_set_color(canvas, ColorBlack);
    canvas_set_font(canvas, FontSecondary);

    furi_mutex_acquire(app->data_mutex, FuriWaitForever);
    uint8_t stage = app->sae.stage;
    char bssid[9]; strncpy(bssid, app->sae.bssid, 8); bssid[8] = '\0';
    furi_mutex_release(app->data_mutex);

    /* Info box */
    canvas_draw_frame(canvas, 0, 14, 128, 14);
    canvas_draw_str(canvas, 2, 23, "No PSK sent on air");

    /* SAE stages */
    static const char* const labels[] = {
        "Commit TX", "Commit RX", "Confirm TX", "Confirm RX", "Assoc"
    };
    bool active[5] = { stage>=1, stage>=1, stage>=2, stage>=2, stage>=2 };
    for(int i = 0; i < 5; i++) {
        uint8_t x = 1 + i * 25;
        uint8_t y = 30;
        if(active[i]) {
            canvas_draw_box(canvas, x, y, 23, 12);
            canvas_set_color(canvas, ColorWhite);
        } else {
            canvas_draw_frame(canvas, x, y, 23, 12);
        }
        /* Number */
        char n[2] = { '1' + i, '\0' };
        canvas_draw_str_aligned(canvas, x+11, y+9, AlignCenter, AlignBottom, n);
        canvas_set_color(canvas, ColorBlack);
        /* Arrow */
        if(i < 4) {
            canvas_draw_dot(canvas, x+24, y+5);
            canvas_draw_dot(canvas, x+24, y+6);
        }
        /* Label below */
        canvas_draw_str(canvas, x, 47, labels[i]);
    }

    canvas_draw_line(canvas, 0, 53, 127, 53);
    if(stage == 0)
        canvas_draw_str(canvas, 2, 63, "Listening for SAE...");
    else {
        char s[32];
        snprintf(s, sizeof(s), "Stage %u  AP:%s", stage, bssid);
        canvas_draw_str(canvas, 2, 63, s);
    }
}

static void proto_draw_cb(Canvas* canvas, void* model) {
    ProtoModel* pm = (ProtoModel*)model;
    canvas_clear(canvas);
    if(pm->page == PAGE_WPA2)
        draw_wpa2(canvas, pm->app);
    else
        draw_wpa3(canvas, pm->app);

    /* Page tab */
    canvas_set_font(canvas, FontSecondary);
    if(pm->page == PAGE_WPA2)
        canvas_draw_str(canvas, 100, 9, "WP2 >");
    else
        canvas_draw_str(canvas, 97, 9, "< WP3");
}

static bool proto_input_cb(InputEvent* ev, void* model) {
    ProtoModel* pm = (ProtoModel*)model;
    if(ev->type != InputTypeShort) return false;
    if(ev->key == InputKeyLeft)  { pm->page = PAGE_WPA2; return true; }
    if(ev->key == InputKeyRight) { pm->page = PAGE_WPA3; return true; }
    if(ev->key == InputKeyBack)  return false;
    return true;
}

/* Enter promiscuous monitor on the strongest AP's channel; stop on exit */
static void proto_enter_cb(void* context) {
    ProtoModel* pm = (ProtoModel*)context;
    WifiStudyApp* app = pm->app;
    uint8_t ch = 6; int8_t best = -127;
    furi_mutex_acquire(app->data_mutex, FuriWaitForever);
    for(int i=0; i<app->ap_count; i++)
        if(app->aps[i].channel < 36 && app->aps[i].rssi > best) {
            best = app->aps[i].rssi; ch = app->aps[i].channel;
        }
    furi_mutex_release(app->data_mutex);
    char cmd[24]; snprintf(cmd, sizeof(cmd), "CMD,MONITOR,%u", ch);
    uart_send_cmd(app, cmd);
}
static void proto_exit_cb(void* context) {
    ProtoModel* pm = (ProtoModel*)context;
    uart_send_cmd(pm->app, "CMD,STOP");
}

View* protocol_view_alloc(WifiStudyApp* app) {
    View* v = view_alloc();
    view_allocate_model(v, ViewModelTypeLocking, sizeof(ProtoModel));
    ProtoModel* m = view_get_model(v);
    m->app  = app;
    m->page = PAGE_WPA2;
    view_commit_model(v, false);
    view_set_context(v, m);
    view_set_draw_callback(v, proto_draw_cb);
    view_set_input_callback(v, proto_input_cb);
    view_set_enter_callback(v, proto_enter_cb);
    view_set_exit_callback(v, proto_exit_cb);
    return v;
}

void protocol_view_free(View* v) { view_free(v); }
