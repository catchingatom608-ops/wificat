#include "cam_view.h"
#include "../uart_handler.h"
#include <gui/elements.h>
#include <stdio.h>
#include <string.h>

/* WiFi Camera detector: flags devices whose MAC vendor (OUI) is a known
 * camera/surveillance maker. Heuristic — see README for the honest limits. */

#define ROWS 4
#define ROW_H 11
#define HDR_H 11

typedef struct { WifiStudyApp* app; } CamModel;

/* compact OUI list for instant flagging of already-scanned camera APs */
typedef struct { uint8_t o[3]; const char* name; } COui;
static const COui COUIS[] = {
    {{0x44,0x19,0xB6},"Hikvision"},{{0x4C,0xBD,0x8F},"Hikvision"},
    {{0x28,0x57,0xBE},"Hikvision"},{{0x3C,0xEF,0x8C},"Dahua"},
    {{0x90,0x02,0xA9},"Dahua"},    {{0x9C,0x8E,0xCD},"Amcrest"},
    {{0x2C,0xAA,0x8E},"Wyze"},     {{0x7C,0x78,0xB2},"Wyze"},
    {{0x68,0x57,0x2D},"Tuya cam"}, {{0xEC,0xFA,0xBC},"Tuya cam"},
    {{0x18,0xB4,0x30},"Nest cam"}, {{0x64,0x16,0x66},"Nest cam"},
    {{0xFC,0xA1,0x83},"Ring"},     {{0x44,0x65,0x0D},"Ring"},
    {{0x9C,0xD3,0x6D},"Arlo"},     {{0xAC,0xCC,0x8E},"Axis"},
    {{0x78,0x8A,0x20},"UniFi cam"},{{0x50,0xC7,0xBF},"Tapo cam"},
    {{0xAC,0x84,0xC6},"Tapo cam"}, {{0x04,0xCF,0x8C},"Xiaomi cam"},
    {{0xEC,0x3D,0xFD},"Reolink"},  {{0x24,0x0A,0xC4},"ESP32-cam"},
    {{0x30,0xAE,0xA4},"ESP32-cam"},{{0x7C,0x9E,0xBD},"ESP32-cam"},
};
#define COUIS_N (int)(sizeof(COUIS)/sizeof(COUIS[0]))

static uint8_t hx(char c){ return c<='9'?(uint8_t)(c-'0'):(uint8_t)((c&0xDF)-'A'+10); }

static const char* oui_match(const char* bssid) {
    if(strlen(bssid) < 8) return NULL;
    uint8_t o0=(hx(bssid[0])<<4)|hx(bssid[1]);
    uint8_t o1=(hx(bssid[3])<<4)|hx(bssid[4]);
    uint8_t o2=(hx(bssid[6])<<4)|hx(bssid[7]);
    for(int i=0;i<COUIS_N;i++)
        if(COUIS[i].o[0]==o0 && COUIS[i].o[1]==o1 && COUIS[i].o[2]==o2)
            return COUIS[i].name;
    return NULL;
}

static void cam_draw_cb(Canvas* canvas, void* model) {
    CamModel* cm = (CamModel*)model;
    WifiStudyApp* app = cm->app;
    canvas_clear(canvas);

    canvas_draw_box(canvas, 0, 0, 128, HDR_H);
    canvas_set_color(canvas, ColorWhite);
    canvas_set_font(canvas, FontSecondary);
    furi_mutex_acquire(app->data_mutex, FuriWaitForever);
    char hdr[28]; snprintf(hdr, sizeof(hdr), "Camera Detector  %d", app->cam_count);
    canvas_draw_str(canvas, 2, 9, hdr);
    if(app->bw16_ok) canvas_draw_box(canvas, 122, 3, 5, 5);
    canvas_set_color(canvas, ColorBlack);

    if(app->cam_count == 0) {
        canvas_draw_str_aligned(canvas, 64, 30, AlignCenter, AlignCenter,
            app->bw16_ok ? "scanning for cameras..." : "no BW16");
        canvas_draw_str_aligned(canvas, 64, 44, AlignCenter, AlignCenter,
            "(checks MAC vendor)");
    } else {
        int sc = app->cam_scroll;
        if(sc > app->cam_count - ROWS) sc = app->cam_count - ROWS;
        if(sc < 0) sc = 0;
        for(int i=0; i<ROWS && (sc+i)<app->cam_count; i++) {
            int idx = sc + i;
            uint8_t y = HDR_H + (uint8_t)i*ROW_H + 8;
            canvas_draw_str(canvas, 2, y, app->cam_vendor[idx]);
            char r[20]; snprintf(r, sizeof(r), "c%u %s", app->cam_ch[idx],
                                 app->cam_mac[idx] + 9); /* last 8 of mac */
            canvas_draw_str(canvas, 60, y, r);
        }
    }
    furi_mutex_release(app->data_mutex);
}

static bool cam_input_cb(InputEvent* ev, void* context) {
    CamModel* cm = (CamModel*)context;
    WifiStudyApp* app = cm->app;
    if(ev->type != InputTypeShort && ev->type != InputTypeRepeat) return false;
    if(ev->key == InputKeyBack) { uart_send_cmd(app, "CMD,STOP"); return false; }
    furi_mutex_acquire(app->data_mutex, FuriWaitForever);
    if(ev->key == InputKeyUp && app->cam_scroll > 0) app->cam_scroll--;
    if(ev->key == InputKeyDown && app->cam_scroll + ROWS < app->cam_count)
        app->cam_scroll++;
    furi_mutex_release(app->data_mutex);
    return true;
}

static void cam_enter_cb(void* context) {
    CamModel* cm = (CamModel*)context;
    WifiStudyApp* app = cm->app;
    furi_mutex_acquire(app->data_mutex, FuriWaitForever);
    app->cam_count = 0; app->cam_scroll = 0;
    /* instant: flag any already-scanned AP whose BSSID OUI is a camera */
    for(int i=0; i<app->ap_count && app->cam_count<16; i++) {
        const char* v = oui_match(app->aps[i].bssid);
        if(!v) continue;
        int s = app->cam_count++;
        strncpy(app->cam_mac[s], app->aps[i].bssid, 17); app->cam_mac[s][17]='\0';
        strncpy(app->cam_vendor[s], v, 15); app->cam_vendor[s][15]='\0';
        app->cam_ch[s] = app->aps[i].channel;
    }
    furi_mutex_release(app->data_mutex);
    uart_send_cmd(app, "CMD,CAM");   /* + live sniffing for client cams */
}

View* cam_view_alloc(WifiStudyApp* app) {
    View* v = view_alloc();
    view_allocate_model(v, ViewModelTypeLocking, sizeof(CamModel));
    CamModel* m = view_get_model(v);
    m->app = app;
    view_commit_model(v, false);
    view_set_context(v, m);
    view_set_draw_callback(v, cam_draw_cb);
    view_set_input_callback(v, cam_input_cb);
    view_set_enter_callback(v, cam_enter_cb);
    return v;
}

void cam_view_free(View* v) { view_free(v); }
