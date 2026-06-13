#include "channel_map_view.h"
#include <gui/elements.h>
#include <stdio.h>
#include <string.h>

/* Channel map built directly from scan results: how many APs sit on
 * each channel. Left/Right toggles 2.4 GHz <-> 5 GHz. */

#define HDR_H    12
#define BARS_TOP 26
#define BARS_H   26
#define LBL_Y    62

typedef struct {
    WifiStudyApp* app;
    bool show_5g;
} ChanMapModel;

/* Count APs per 2.4 GHz channel (1-13) into out[13]; returns max. */
static uint8_t hist_24(WifiStudyApp* app, uint8_t out[13]) {
    memset(out, 0, 13);
    uint8_t mx = 1;
    for(int i=0; i<app->ap_count; i++) {
        uint8_t ch = app->aps[i].channel;
        if(ch>=1 && ch<=13) { out[ch-1]++; if(out[ch-1]>mx) mx=out[ch-1]; }
    }
    return mx;
}

/* Count APs per 5 GHz channel (CH5_TABLE) into out[MAX_CH5]; returns max+total. */
static uint8_t hist_5(WifiStudyApp* app, uint8_t out[MAX_CH5], uint16_t* total) {
    memset(out, 0, MAX_CH5);
    uint8_t mx = 1; *total = 0;
    for(int i=0; i<app->ap_count; i++) {
        uint8_t ch = app->aps[i].channel;
        if(ch < 36) continue;
        for(int k=0; k<MAX_CH5; k++)
            if(CH5_TABLE[k]==ch) { out[k]++; (*total)++; if(out[k]>mx) mx=out[k]; break; }
    }
    return mx;
}

static void header(Canvas* c, const char* band) {
    canvas_set_font(c, FontPrimary);
    canvas_draw_box(c, 0, 0, 128, HDR_H);
    canvas_set_color(c, ColorWhite);
    canvas_draw_str(c, 2, 9, "Channel Map");
    canvas_draw_str(c, 96, 9, band);
    canvas_set_color(c, ColorBlack);
    canvas_set_font(c, FontSecondary);
}

static void draw_24(Canvas* canvas, WifiStudyApp* app) {
    header(canvas, "2.4G");

    uint8_t h[13]; uint8_t mx = hist_24(app, h);

    /* least-crowded of the non-overlapping channels 1/6/11 */
    uint8_t best = 1; uint8_t bestn = h[0];
    if(h[5]  < bestn) { bestn=h[5];  best=6;  }
    if(h[10] < bestn) { bestn=h[10]; best=11; }

    char info[24];
    snprintf(info, sizeof(info), "Best CH%u   <>band", best);
    canvas_draw_str(canvas, 2, 22, info);

    for(int ch=1; ch<=13; ch++) {
        uint8_t x  = (uint8_t)(5 + (ch-1)*9);
        uint8_t n  = h[ch-1];
        uint8_t bh = n ? (uint8_t)(n*BARS_H/mx) : 0;
        if(bh==0 && n>0) bh=2;
        uint8_t by = (uint8_t)(BARS_TOP + BARS_H - bh);

        if(bh>0) canvas_draw_box(canvas, x, by, 7, bh);
        canvas_draw_frame(canvas, x, BARS_TOP, 7, BARS_H);

        /* mark non-overlapping channels with a dot above the bar */
        if(ch==1||ch==6||ch==11)
            canvas_draw_disc(canvas, x+3, BARS_TOP-3, 1);

        /* count inside/above bar */
        if(n>0) {
            char cnt[4]; snprintf(cnt, sizeof(cnt), "%u", n);
            canvas_draw_str_aligned(canvas, x+3, by-1, AlignCenter, AlignBottom, cnt);
        }

        /* channel number label */
        char lbl[3]; snprintf(lbl, sizeof(lbl), "%u", ch);
        canvas_draw_str_aligned(canvas, x+3, LBL_Y, AlignCenter, AlignBottom, lbl);
    }
}

static void draw_5(Canvas* canvas, WifiStudyApp* app) {
    header(canvas, "5G");

    uint8_t h[MAX_CH5]; uint16_t total;
    uint8_t mx = hist_5(app, h, &total);

    if(total == 0) {
        canvas_draw_str_aligned(canvas, 64, 36, AlignCenter, AlignCenter,
                                "No 5 GHz APs found");
        canvas_draw_str_aligned(canvas, 64, 48, AlignCenter, AlignCenter,
                                "<  back to 2.4 GHz");
        return;
    }

    uint8_t best=0; uint8_t bestn=255;
    for(int k=0; k<MAX_CH5; k++) if(h[k] && h[k]<bestn){bestn=h[k];best=(uint8_t)k;}

    char info[24];
    snprintf(info, sizeof(info), "Best CH%u   <>band", CH5_TABLE[best]);
    canvas_draw_str(canvas, 2, 22, info);

    for(int k=0; k<MAX_CH5; k++) {
        uint8_t x  = (uint8_t)(2 + k*5);
        uint8_t n  = h[k];
        uint8_t bh = n ? (uint8_t)(n*BARS_H/mx) : 0;
        if(bh==0 && n>0) bh=2;
        uint8_t by = (uint8_t)(BARS_TOP + BARS_H - bh);
        if(bh>0) canvas_draw_box(canvas, x, by, 4, bh);
        canvas_draw_frame(canvas, x, BARS_TOP, 4, BARS_H);
    }
    /* a few reference labels along the bottom */
    canvas_draw_str(canvas, 2,   LBL_Y, "36");
    canvas_draw_str(canvas, 56,  LBL_Y, "100");
    canvas_draw_str(canvas, 104, LBL_Y, "165");
}

static void chanmap_draw_cb(Canvas* canvas, void* model) {
    ChanMapModel* cm = (ChanMapModel*)model;
    WifiStudyApp* app = cm->app;
    canvas_clear(canvas);
    furi_mutex_acquire(app->data_mutex, FuriWaitForever);
    if(cm->show_5g) draw_5(canvas, app);
    else            draw_24(canvas, app);
    furi_mutex_release(app->data_mutex);
}

static bool chanmap_input_cb(InputEvent* ev, void* context) {
    ChanMapModel* cm = (ChanMapModel*)context;
    if(ev->type != InputTypeShort) return false;
    if(ev->key == InputKeyBack)  return false;
    if(ev->key == InputKeyRight) { cm->show_5g = true;  return true; }
    if(ev->key == InputKeyLeft)  { cm->show_5g = false; return true; }
    return true;
}

View* channel_map_view_alloc(WifiStudyApp* app) {
    View* v = view_alloc();
    view_allocate_model(v, ViewModelTypeLocking, sizeof(ChanMapModel));
    ChanMapModel* m = view_get_model(v);
    m->app     = app;
    m->show_5g = false;
    view_commit_model(v, false);
    view_set_context(v, m);
    view_set_draw_callback(v, chanmap_draw_cb);
    view_set_input_callback(v, chanmap_input_cb);
    return v;
}

void channel_map_view_free(View* v) { view_free(v); }
