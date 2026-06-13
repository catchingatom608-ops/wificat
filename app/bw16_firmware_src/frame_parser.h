#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include "protocol.h"

/* ── 802.11 Frame Control ───────────────────────────────────── */
typedef struct __attribute__((packed)) {
    uint8_t version : 2;
    uint8_t type    : 2;
    uint8_t subtype : 4;
    uint8_t to_ds      : 1;
    uint8_t from_ds    : 1;
    uint8_t more_frag  : 1;
    uint8_t retry      : 1;
    uint8_t pwr_mgmt   : 1;
    uint8_t more_data  : 1;
    uint8_t protected_f: 1;
    uint8_t order      : 1;
} fc_t;

typedef struct __attribute__((packed)) {
    fc_t     fc;
    uint16_t duration;
    uint8_t  addr1[6];
    uint8_t  addr2[6];
    uint8_t  addr3[6];
    uint16_t seq_ctrl;
} dot11_hdr_t;

#define TYPE_MGMT 0
#define TYPE_DATA 2

#define SUBTYPE_ASSOC_RESP 1
#define SUBTYPE_PROBE_RESP 5
#define SUBTYPE_BEACON     8
#define SUBTYPE_DISASSOC   10
#define SUBTYPE_AUTH       11
#define SUBTYPE_DEAUTH     12

/* ── EAPOL Key ──────────────────────────────────────────────── */
typedef struct __attribute__((packed)) {
    uint8_t  version;
    uint8_t  type;
    uint16_t length;
    uint8_t  descriptor;
    uint16_t key_info;
    uint16_t key_len;
    uint8_t  replay_counter[8];
    uint8_t  nonce[32];
    uint8_t  key_iv[16];
    uint8_t  key_rsc[8];
    uint8_t  reserved[8];
    uint8_t  key_mic[16];
    uint16_t data_len;
} eapol_key_t;

static inline int eapol_msg_num(const eapol_key_t* k) {
    if(k->type != 3) return 0;
    uint16_t ki = (uint16_t)((k->key_info >> 8) | (k->key_info << 8));
    bool ack     = (ki & 0x0080) != 0;
    bool mic     = (ki & 0x0100) != 0;
    bool secure  = (ki & 0x0200) != 0;
    bool install = (ki & 0x0040) != 0;
    if( ack && !mic && !secure)              return 1;
    if(!ack &&  mic && !secure)              return 2;
    if( ack &&  mic &&  secure &&  install)  return 3;
    if(!ack &&  mic &&  secure && !install)  return 4;
    return 0;
}

/* ── SAE Auth ────────────────────────────────────────────────── */
typedef struct __attribute__((packed)) {
    uint16_t auth_alg;
    uint16_t auth_seq;
    uint16_t status;
} auth_fixed_t;

#define AUTH_ALG_SAE 3

/* ── RSN IE → security type + *pmf_out ─────────────────────── */
static inline uint8_t rsn_ie_parse(const uint8_t* ie, uint8_t ie_len,
                                    uint8_t* pmf_out) {
    if(pmf_out) *pmf_out = PMF_NONE;
    if(!ie || ie_len < 8) return 0xFF;
    const uint8_t* end = ie + ie_len;
    const uint8_t* p   = ie + 2;
    p += 4;
    if(p + 2 > end) return 0xFF;
    uint16_t pcnt = (uint16_t)(p[0] | ((uint16_t)p[1] << 8)); p += 2;
    if(p + (unsigned)(pcnt * 4) > end) return 0xFF;
    p += pcnt * 4;
    if(p + 2 > end) return 0xFF;
    uint16_t acnt = (uint16_t)(p[0] | ((uint16_t)p[1] << 8)); p += 2;
    bool has_sae = false, has_psk = false;
    for(uint16_t i = 0; i < acnt && p + 4 <= end; i++, p += 4) {
        if(p[3] == 8 || p[3] == 9 || p[3] == 18) has_sae = true;
        if(p[3] == 2 || p[3] == 6)               has_psk = true;
    }
    if(pmf_out && p + 2 <= end) {
        bool mfpc = (p[0] & 0x80) != 0;
        bool mfpr = (p[0] & 0x40) != 0;
        *pmf_out = mfpr ? PMF_REQUIRED : (mfpc ? PMF_OPTIONAL : PMF_NONE);
    }
    if(has_sae && has_psk) return SEC_MIX;
    if(has_sae)            return SEC_WPA3;
    return SEC_WPA2;
}

/* ── MAC helpers ────────────────────────────────────────────── */
static inline void mac_to_str(const uint8_t* m, char* out) {
    snprintf(out, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
             m[0], m[1], m[2], m[3], m[4], m[5]);
}

static inline bool str_to_mac(const char* s, uint8_t* out) {
    if(!s || strlen(s) < 17) return false;
    for(int i = 0; i < 6; i++) {
        char hi = s[i*3], lo = s[i*3+1];
        out[i] = (uint8_t)((((hi<='9')?(hi-'0'):((hi&0xDF)-'A'+10)) << 4) |
                             ((lo<='9')?(lo-'0'):((lo&0xDF)-'A'+10)));
    }
    return true;
}
