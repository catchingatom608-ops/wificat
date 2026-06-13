#include "splash_view.h"
#include <gui/elements.h>
#include <string.h>

typedef struct { WifiStudyApp* app; uint32_t ok_t; int ok_n; } SplashModel;

static void splash_draw_cb(Canvas* canvas, void* model) {
    WifiStudyApp* app = ((SplashModel*)model)->app;
    canvas_clear(canvas);

    /* Background pattern */
    for(uint8_t x=0; x<128; x+=8)
        canvas_draw_dot(canvas, x, 0);

    /* Logo area */
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str_aligned(canvas, 64, 14, AlignCenter, AlignCenter,
                            "WifiCat");

    canvas_set_font(canvas, FontSecondary);
    canvas_draw_str_aligned(canvas, 64, 28, AlignCenter, AlignCenter,
                            "( =^.^= )");

    /* Progress bar */
    uint8_t pct = app->splash_pct;
    canvas_draw_frame(canvas, 14, 40, 100, 7);
    if(pct > 0) canvas_draw_box(canvas, 15, 41, pct, 5);

    /* Status line */
    canvas_draw_str_aligned(canvas, 64, 60, AlignCenter, AlignCenter,
        app->bw16_ok ? "BW16 Connected" : "Starting up...");
}

static bool splash_input_cb(InputEvent* ev, void* model) {
    SplashModel* sm = (SplashModel*)model;
    WifiStudyApp* app = sm->app;
    if(ev->type != InputTypeShort) return true;

    /* secret: click OK 6x fast -> easter egg */
    if(ev->key == InputKeyOk) {
        uint32_t now = furi_get_tick();
        if(now - sm->ok_t < furi_ms_to_ticks(600)) sm->ok_n++;
        else                                        sm->ok_n = 1;
        sm->ok_t = now;
        if(sm->ok_n >= 6) {
            sm->ok_n = 0;
            app->splash_done = true;
            view_dispatcher_switch_to_view(app->view_dispatcher, ViewEgg);
        }
        return true;
    }

    /* any other key -> skip to the menu */
    app->splash_done = true;
    view_dispatcher_send_custom_event(app->view_dispatcher, 0 /* EVT_SPLASH */);
    return true;
}

View* splash_view_alloc(WifiStudyApp* app) {
    View* v = view_alloc();
    view_allocate_model(v, ViewModelTypeLocking, sizeof(SplashModel));
    SplashModel* m = view_get_model(v);
    m->app = app;
    view_commit_model(v, false);
    view_set_context(v, m);
    view_set_draw_callback(v, splash_draw_cb);
    view_set_input_callback(v, splash_input_cb);
    return v;
}

void splash_view_free(View* v) { view_free(v); }
