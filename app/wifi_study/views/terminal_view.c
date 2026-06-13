#include "terminal_view.h"
#include <gui/elements.h>
#include <stdio.h>
#include <string.h>

/* Marauder-style live terminal: a rolling text log of BW16 events
 * (APs found, clients connecting, logins captured, handshakes, deauths). */

#define SHOWN 6

typedef struct { WifiStudyApp* app; } TermModel;

static void term_draw_cb(Canvas* canvas, void* model) {
    TermModel* tm = (TermModel*)model;
    WifiStudyApp* app = tm->app;
    canvas_clear(canvas);

    canvas_set_font(canvas, FontSecondary);
    canvas_draw_box(canvas, 0, 0, 128, 11);
    canvas_set_color(canvas, ColorWhite);
    canvas_draw_str(canvas, 2, 9, "Live Log");
    furi_mutex_acquire(app->data_mutex, FuriWaitForever);
    char hdr[16]; snprintf(hdr, sizeof(hdr), "%u", app->log_total);
    canvas_draw_str(canvas, 108, 9, hdr);
    if(app->bw16_ok) canvas_draw_box(canvas, 100, 3, 5, 5);

    int total = app->log_total;
    int show  = total < SHOWN ? total : SHOWN;
    canvas_set_color(canvas, ColorBlack);
    if(total == 0) {
        canvas_draw_str(canvas, 2, 34, "waiting for events...");
    } else {
        for(int i=0; i<show; i++) {
            /* oldest of the shown window at top, newest at bottom */
            int idx = (app->log_head - show + i + 64) % 16;
            char ln[33]; strncpy(ln, app->log_lines[idx], 32); ln[32]='\0';
            canvas_draw_str(canvas, 2, 20 + i*8, ln);
        }
    }
    furi_mutex_release(app->data_mutex);
}

static bool term_input_cb(InputEvent* ev, void* context) {
    UNUSED(context);
    if(ev->type == InputTypeShort && ev->key == InputKeyBack) return false;
    return true;
}

View* terminal_view_alloc(WifiStudyApp* app) {
    View* v = view_alloc();
    view_allocate_model(v, ViewModelTypeLocking, sizeof(TermModel));
    TermModel* m = view_get_model(v);
    m->app = app;
    view_commit_model(v, false);
    view_set_context(v, m);
    view_set_draw_callback(v, term_draw_cb);
    view_set_input_callback(v, term_input_cb);
    return v;
}

void terminal_view_free(View* v) { view_free(v); }
