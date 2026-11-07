#pragma once

#include <stdbool.h>
#include "esp_err.h"

// Serves the single-page UI and its JSON API. In setup mode only Wi-Fi/admin setup is allowed.
esp_err_t p2p_web_start(bool setup_mode);
