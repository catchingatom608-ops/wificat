#include "pwn_view.h"
#include "../uart_handler.h"
#include <gui/elements.h>
#include <stdio.h>
#include <string.h>

/* WifiCat — auto handshake hunter with a moody face.
 *   boot anim -> live auto face. Long-press OK = emotion debug browser. */

#define BOOT_MS 2500

typedef struct {
    WifiStudyApp* app;
    uint32_t enter_tick;
    bool     debug;
    int      dbg_idx;
    uint32_t ok_t;      /* last OK press tick (for quad-click) */
    int      ok_n;      /* consecutive fast OK presses */
} PwnModel;

/* emotion table for the debug browser */
typedef struct { const char* name; const char* face; } Emotion;
static const Emotion EMO[] = {
    {"happy",   "(^_^ )"},
    {"excited", "(>w< )"},
    {"angry",   "(o`o )"},
    {"sad",     "(;_; )"},
    {"sleepy",  "(-_- )z"},
    {"bored",   "(=_= )"},
    {"love",    "(*v* )"},
    {"cool",    "(<_< )"},
    {"looking", "(o_O )"},
    {"dead",    "(x_x )"},
    {"caught",  "(O_O )!"},
};
#define EMO_N (int)(sizeof(EMO)/sizeof(EMO[0]))

/* small wifi arc symbol at (x,y) */
static void draw_wifi(Canvas* c, uint8_t x, uint8_t y) {
    canvas_draw_dot(c, x+3, y+4);
    canvas_draw_line(c, x+1, y+2, x+5, y+2);
    canvas_draw_line(c, x,   y,   x+6, y);
}

static void draw_title(Canvas* c) {
    canvas_set_font(c, FontPrimary);
    canvas_draw_box(c, 0, 0, 128, 12);
    canvas_set_color(c, ColorWhite);
    canvas_draw_str(c, 2, 9, "Pwnagotchi");
    draw_wifi(c, 92, 3);
    canvas_set_color(c, ColorBlack);
    canvas_set_font(c, FontSecondary);
}

/* ── Boot ───────────────────────────────────────────────────── */
static void draw_boot(Canvas* canvas, uint32_t ms) {
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str_aligned(canvas, 64, 14, AlignCenter, AlignCenter, "Pwnagotchi");
    canvas_set_font(canvas, FontSecondary);
    static const char* L[] = {
        "loading brain...", "waking neurons...",
        "tuning radio...", "ready to hunt!" };
    int step = (int)(ms * 4 / BOOT_MS); if(step>3) step=3;
    for(int i=0;i<=step;i++) canvas_draw_str(canvas, 8, 27+i*9, L[i]);
    uint8_t w = (uint8_t)(ms*100/BOOT_MS); if(w>100) w=100;
    canvas_draw_frame(canvas, 14, 60, 100, 4);
    if(w) canvas_draw_box(canvas, 15, 61, w, 2);
}

/* ── Live face ──────────────────────────────────────────────── */
static void draw_auto(Canvas* canvas, WifiStudyApp* app) {
    furi_mutex_acquire(app->data_mutex, FuriWaitForever);
    int aps = app->ap_count;
    uint32_t hs = app->pwn_handshakes, last = app->pwn_last_catch;
    furi_mutex_release(app->data_mutex);

    uint32_t now = furi_get_tick();
    bool caught = (last && (now - last) < furi_ms_to_ticks(4000));

    const char* face; const char* mood;
    if(caught)        { face="(O_O )!"; mood="GOT A HANDSHAKE!"; }
    else if(aps==0)   { face="(x_x )";  mood="no networks..."; }
    else if(hs>0)     { face="(^_^ )";  mood="happy hunter"; }
    else {
        /* looking around: alternate gaze ~ each second */
        uint32_t s = now / furi_kernel_get_tick_frequency();
        face = (s & 1) ? "(o_O )" : "(O_o )";
        mood = "hunting...";
    }

    draw_title(canvas);
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str_aligned(canvas, 64, 26, AlignCenter, AlignCenter, face);
    canvas_set_font(canvas, FontSecondary);
    canvas_draw_str_aligned(canvas, 64, 38, AlignCenter, AlignCenter, mood);
    canvas_draw_line(canvas, 0, 44, 127, 44);

    char l1[20]; snprintf(l1, sizeof(l1), "PWND:%lu", (unsigned long)hs);
    canvas_draw_str(canvas, 2, 54, l1);
    char l2[16]; snprintf(l2, sizeof(l2), "AP:%d", aps);
    canvas_draw_str(canvas, 60, 54, l2);
    uint32_t secs = now / furi_kernel_get_tick_frequency();
    char up[20]; snprintf(up, sizeof(up), "up:%lum", (unsigned long)(secs/60));
    canvas_draw_str(canvas, 92, 54, up);
    /* mode + hints. quad-click OK toggles SMART (passive, no deauth) */
    if(app->pwn_smart) canvas_draw_str(canvas, 2, 63, "SMART  4xOK=auto");
    else               canvas_draw_str(canvas, 2, 63, "AUTO   4xOK=smart");
}

/* ── Debug emotion browser ──────────────────────────────────── */
static void draw_debug(Canvas* canvas, PwnModel* pm) {
    draw_title(canvas);
    const Emotion* e = &EMO[pm->dbg_idx];
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str_aligned(canvas, 64, 28, AlignCenter, AlignCenter, e->face);
    canvas_set_font(canvas, FontSecondary);
    char n[24]; snprintf(n, sizeof(n), "[%d/%d] %s", pm->dbg_idx+1, EMO_N, e->name);
    canvas_draw_str_aligned(canvas, 64, 44, AlignCenter, AlignCenter, n);
    canvas_draw_line(canvas, 0, 52, 127, 52);
    canvas_draw_str(canvas, 2, 62, "Up/Dn pick  Back=exit");
}

static void pwn_draw_cb(Canvas* canvas, void* model) {
    PwnModel* pm = (PwnModel*)model;
    canvas_clear(canvas);
    if(pm->debug) { draw_debug(canvas, pm); return; }
    uint32_t ms = (furi_get_tick() - pm->enter_tick) * 1000
                  / furi_kernel_get_tick_frequency();
    if(ms < BOOT_MS) draw_boot(canvas, ms);
    else             draw_auto(canvas, pm->app);
}

static bool pwn_input_cb(InputEvent* ev, void* context) {
    PwnModel* pm = (PwnModel*)context;

    if(pm->debug) {
        if(ev->type != InputTypeShort && ev->type != InputTypeRepeat) return false;
        if(ev->key == InputKeyBack)  { pm->debug = false; return true; }
        if(ev->key == InputKeyUp)    { if(pm->dbg_idx>0) pm->dbg_idx--; return true; }
        if(ev->key == InputKeyDown)  { if(pm->dbg_idx<EMO_N-1) pm->dbg_idx++; return true; }
        return true;
    }

    /* long-press OK -> debug emotion browser */
    if(ev->type == InputTypeLong && ev->key == InputKeyOk) {
        pm->debug = true; pm->dbg_idx = 0; return true;
    }
    /* quad-click OK -> toggle SMART (passive) mode */
    if(ev->type == InputTypeShort && ev->key == InputKeyOk) {
        uint32_t now = furi_get_tick();
        if(now - pm->ok_t < furi_ms_to_ticks(500)) pm->ok_n++;
        else                                        pm->ok_n = 1;
        pm->ok_t = now;
        if(pm->ok_n >= 4) {
            pm->ok_n = 0;
            pm->app->pwn_smart = !pm->app->pwn_smart;
            uart_send_cmd(pm->app, "CMD,PWNSMART");
        }
        return true;
    }
    if(ev->type == InputTypeShort && ev->key == InputKeyBack) {
        uart_send_cmd(pm->app, "CMD,STOP");
        furi_mutex_acquire(pm->app->data_mutex, FuriWaitForever);
        pm->app->pwn_running = false;
        pm->app->capture.active = false;
        furi_mutex_release(pm->app->data_mutex);
        return false;
    }
    return true;
}

static void pwn_enter_cb(void* context) {
    PwnModel* pm = (PwnModel*)context;
    WifiStudyApp* app = pm->app;
    pm->enter_tick = furi_get_tick();
    pm->debug = false; pm->dbg_idx = 0; pm->ok_n = 0; pm->ok_t = 0;
    furi_mutex_acquire(app->data_mutex, FuriWaitForever);
    app->pwn_handshakes = 0; app->pwn_caught_count = 0; app->pwn_last_catch = 0;
    app->pwn_smart = false;
    app->pwn_running = true;          /* buffer + save caught handshakes */
    app->pwn_save_pending = false;
    app->capture.active = true;       /* K frames buffer into capture.frames */
    app->capture.nframes = 0;
    furi_mutex_release(app->data_mutex);
    uart_send_cmd(app, "CMD,PWN");
}

View* pwn_view_alloc(WifiStudyApp* app) {
    View* v = view_alloc();
    view_allocate_model(v, ViewModelTypeLocking, sizeof(PwnModel));
    PwnModel* m = view_get_model(v);
    m->app = app; m->enter_tick = 0; m->debug = false; m->dbg_idx = 0;
    view_commit_model(v, false);
    view_set_context(v, m);
    view_set_draw_callback(v, pwn_draw_cb);
    view_set_input_callback(v, pwn_input_cb);
    view_set_enter_callback(v, pwn_enter_cb);
    return v;
}

void pwn_view_free(View* v) { view_free(v); }
