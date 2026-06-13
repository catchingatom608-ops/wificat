#include "comingsoon_view.h"
#include <gui/elements.h>

typedef struct { WifiStudyApp* app; } CsModel;

static void cs_draw_cb(Canvas* canvas, void* model) {
    UNUSED(model);
    canvas_clear(canvas);
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str_aligned(canvas, 64, 11, AlignCenter, AlignCenter, "x_x");
    canvas_set_font(canvas, FontSecondary);
    canvas_draw_str_aligned(canvas, 64, 25, AlignCenter, AlignCenter, "Evil Portal: coming soon");
    canvas_draw_str_aligned(canvas, 64, 35, AlignCenter, AlignCenter, "(currently broken)");
    canvas_draw_str_aligned(canvas, 64, 48, AlignCenter, AlignCenter, "want it? fix the code");
    canvas_draw_str_aligned(canvas, 64, 58, AlignCenter, AlignCenter, "yourself!   Back=exit");
}

static bool cs_input_cb(InputEvent* ev, void* context) {
    UNUSED(context);
    if(ev->type == InputTypeShort && ev->key == InputKeyBack) return false;
    return true;
}

View* comingsoon_view_alloc(WifiStudyApp* app) {
    View* v = view_alloc();
    view_allocate_model(v, ViewModelTypeLocking, sizeof(CsModel));
    CsModel* m = view_get_model(v);
    m->app = app;
    view_commit_model(v, false);
    view_set_context(v, m);
    view_set_draw_callback(v, cs_draw_cb);
    view_set_input_callback(v, cs_input_cb);
    return v;
}

void comingsoon_view_free(View* v) { view_free(v); }
