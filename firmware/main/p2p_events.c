#include "p2p_events.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "esp_log.h"
#include "esp_timer.h"

#define MAX_EVENTS 40
#define MSG_LEN 96

typedef struct {
    int64_t t;    // unix time, 0 if the clock wasn't set yet
    uint32_t up;  // uptime seconds
    char msg[MSG_LEN];
} event_t;

static const char *TAG = "event";
static event_t s_ring[MAX_EVENTS];
static int s_head, s_count;
static SemaphoreHandle_t s_lock;

void p2p_events_init(void)
{
    if (!s_lock) {
        s_lock = xSemaphoreCreateMutex();
    }
}

void p2p_event(const char *fmt, ...)
{
    char msg[MSG_LEN];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    ESP_LOGI(TAG, "%s", msg);
    if (!s_lock) {
        return;
    }
    time_t now = time(NULL);
    xSemaphoreTake(s_lock, portMAX_DELAY);
    event_t *e = &s_ring[s_head];
    e->t = now > 1700000000 ? (int64_t)now : 0;
    e->up = (uint32_t)(esp_timer_get_time() / 1000000);
    strlcpy(e->msg, msg, sizeof(e->msg));
    s_head = (s_head + 1) % MAX_EVENTS;
    if (s_count < MAX_EVENTS) {
        s_count++;
    }
    xSemaphoreGive(s_lock);
}

cJSON *p2p_events_json(void)
{
    cJSON *arr = cJSON_CreateArray();
    if (!s_lock || !arr) {
        return arr;
    }
    xSemaphoreTake(s_lock, portMAX_DELAY);
    for (int i = 0; i < s_count; i++) {
        const event_t *e = &s_ring[(s_head - 1 - i + MAX_EVENTS) % MAX_EVENTS];
        cJSON *o = cJSON_CreateObject();
        cJSON_AddNumberToObject(o, "t", (double)e->t);
        cJSON_AddNumberToObject(o, "up", e->up);
        cJSON_AddStringToObject(o, "m", e->msg);
        cJSON_AddItemToArray(arr, o);
    }
    xSemaphoreGive(s_lock);
    return arr;
}
