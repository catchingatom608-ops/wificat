#pragma once
#include "wifi_study_app.h"

void uart_handler_start(WifiStudyApp* app);
void uart_handler_stop(WifiStudyApp* app);
/* Send a command string to the BW16 (adds \n automatically) */
void uart_send_cmd(WifiStudyApp* app, const char* cmd);
