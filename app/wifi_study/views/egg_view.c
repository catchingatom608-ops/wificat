#include "egg_view.h"
#include <gui/elements.h>
#include <stdio.h>
#include <string.h>

/* Secret easter egg: KING -> MATRIX -> fake crash -> back to menu.
 * Triggered by clicking OK 6x fast on the WifiCat home/splash screen. */

typedef enum { EGG_KING, EGG_MATRIX, EGG_CRASH } EggStage;
typedef struct {
    WifiStudyApp* app;
    EggStage stage;
    uint32_t enter_tick;
} EggModel;

static void draw_king(Canvas* c) {
    canvas_set_font(c, FontSecondary);
    canvas_draw_str_aligned(c, 64, 8,  AlignCenter, AlignCenter, "w");
    canvas_set_font(c, FontPrimary);
    canvas_draw_str_aligned(c, 64, 22, AlignCenter, AlignCenter, "o_o");
    canvas_set_font(c, FontSecondary);
    canvas_draw_str_aligned(c, 64, 38, AlignCenter, AlignCenter, "U FOUND THE KING");
    canvas_draw_str_aligned(c, 64, 55, AlignCenter, AlignCenter, "(click OK to continue)");
}

static void draw_matrix(Canvas* c, uint32_t t) {
    canvas_set_font(c, FontSecondary);
    static const char* G = "01ABCDEF#$%&*+=<>";
    for(int x = 0; x < 128; x += 8) {
        int head = (int)((t/2 + x*5) % 72);
        for(int k = 0; k < 5; k++) {
            int y = head - k*8;
            if(y < 8 || y > 64) continue;
            char s[2] = { G[(x + y + (int)(t/3) + k) % 17], 0 };
            canvas_draw_str(c, x, y, s);
        }
    }
    /* readable overlay box */
    canvas_set_color(c, ColorWhite);
    canvas_draw_box(c, 6, 24, 116, 20);
    canvas_set_color(c, ColorBlack);
    canvas_draw_frame(c, 6, 24, 116, 20);
    canvas_draw_str_aligned(c, 64, 31, AlignCenter, AlignCenter, "YOU ESCAPED");
    canvas_draw_str_aligned(c, 64, 40, AlignCenter, AlignCenter, "THE MATRIX");
}

static void draw_crash(Canvas* c) {
    /* mimic a Flipper crash dump — totally fake/harmless */
    canvas_set_font(c, FontPrimary);
    canvas_draw_str(c, 2, 10, "[x_x]  GURU MEDITATION");
    canvas_set_font(c, FontSecondary);
    canvas_draw_str(c, 2, 22, "FURI CHECK FAILED");
    canvas_draw_str(c, 2, 31, "what append?");
    canvas_draw_str(c, 2, 41, "pc: 0xCAFEBABE  cat: 0x9");
    canvas_draw_str(c, 2, 49, "lr: 0xDEADBEEF  lives:8");
    canvas_draw_str(c, 2, 63, "...just kidding. OK=back");
}

static void egg_draw_cb(Canvas* canvas, void* model) {
    EggModel* em = (EggModel*)model;
    canvas_clear(canvas);
    if(em->stage == EGG_KING)        draw_king(canvas);
    else if(em->stage == EGG_MATRIX) draw_matrix(canvas, furi_get_tick() - em->enter_tick);
    else                             draw_crash(canvas);
}

static bool egg_input_cb(InputEvent* ev, void* context) {
    EggModel* em = (EggModel*)context;
    if(ev->type != InputTypeShort) return false;
    if(ev->key == InputKeyBack) { em->stage = EGG_KING; return false; }
    if(ev->key == InputKeyOk) {
        if(em->stage == EGG_KING) {
            em->stage = EGG_MATRIX; em->enter_tick = furi_get_tick();
        } else if(em->stage == EGG_MATRIX) {
            /* for real: trigger an actual Flipper crash screen (recoverable
             * reboot via the SDK's own crash handler). Hold Back to reboot. */
            furi_crash("what append?");
        } else {
            em->stage = EGG_KING;
            view_dispatcher_switch_to_view(em->app->view_dispatcher, ViewMain);
        }
        return true;
    }
    return true;
}

static void egg_enter_cb(void* context) {
    EggModel* em = (EggModel*)context;
    em->stage = EGG_KING;
    em->enter_tick = furi_get_tick();
}

View* egg_view_alloc(WifiStudyApp* app) {
    View* v = view_alloc();
    view_allocate_model(v, ViewModelTypeLocking, sizeof(EggModel));
    EggModel* m = view_get_model(v);
    m->app = app; m->stage = EGG_KING; m->enter_tick = 0;
    view_commit_model(v, false);
    view_set_context(v, m);
    view_set_draw_callback(v, egg_draw_cb);
    view_set_input_callback(v, egg_input_cb);
    view_set_enter_callback(v, egg_enter_cb);
    return v;
}

void egg_view_free(View* v) { view_free(v); }
