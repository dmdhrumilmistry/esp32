#pragma once

#include <stdbool.h>
#include "esp_err.h"

// Station mode with automatic reconnect.
esp_err_t p2p_wifi_start_sta(const char *ssid, const char *pass);
bool p2p_wifi_wait_ip(int timeout_ms);

// Random 12-char password for the setup AP. Call while a true entropy source is on.
void p2p_wifi_gen_setup_password(char out[13]);
// WPA2 setup access point (credentials printed on the serial console).
esp_err_t p2p_wifi_start_setup_ap(const char *password);
