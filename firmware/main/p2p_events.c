#include "p2p_events.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "esp_log.h"
#include "esp_timer.h"

#define MAX_EVENTS 24   // per ring
#define MSG_LEN 96

typedef struct {
    int64_t t;    // unix time, 0 if the clock wasn't set yet
    uint32_t up;  // uptime seconds
    uint32_t seq; // global order
    char msg[MSG_LEN];
} event_t;

typedef struct {
    event_t e[MAX_EVENTS];
    int head, count;
} ring_t;

static const char *TAG = "event";
static ring_t s_rings[2]; // 0 = security, 1 = traffic
static uint32_t s_seq;
static SemaphoreHandle_t s_lock;

void p2p_events_init(void)
{
    if (!s_lock) {
        s_lock = xSemaphoreCreateMutex();
    }
}

static void add(int ring, const char *fmt, va_list ap)
{
    char msg[MSG_LEN];
    vsnprintf(msg, sizeof(msg), fmt, ap);
    ESP_LOGI(TAG, "%s", msg);
    if (!s_lock) {
        return;
    }
    time_t now = time(NULL);
    xSemaphoreTake(s_lock, portMAX_DELAY);
    ring_t *r = &s_rings[ring];
    event_t *e = &r->e[r->head];
    e->t = now > 1700000000 ? (int64_t)now : 0;
    e->up = (uint32_t)(esp_timer_get_time() / 1000000);
    e->seq = ++s_seq;
    strlcpy(e->msg, msg, sizeof(e->msg));
    r->head = (r->head + 1) % MAX_EVENTS;
    if (r->count < MAX_EVENTS) {
        r->count++;
    }
    xSemaphoreGive(s_lock);
}

void p2p_event(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    add(0, fmt, ap);
    va_end(ap);
}

void p2p_event_traffic(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    add(1, fmt, ap);
    va_end(ap);
}

cJSON *p2p_events_json(void)
{
    cJSON *arr = cJSON_CreateArray();
    if (!s_lock || !arr) {
        return arr;
    }
    xSemaphoreTake(s_lock, portMAX_DELAY);
    int idx[2] = {0, 0}; // how many taken from each ring (newest first)
    for (;;) {
        const event_t *pick = NULL;
        int from = -1;
        for (int r = 0; r < 2; r++) {
            if (idx[r] >= s_rings[r].count) continue;
            const event_t *e = &s_rings[r].e[(s_rings[r].head - 1 - idx[r] + MAX_EVENTS) % MAX_EVENTS];
            if (!pick || e->seq > pick->seq) {
                pick = e;
                from = r;
            }
        }
        if (!pick) break;
        idx[from]++;
        cJSON *o = cJSON_CreateObject();
        cJSON_AddNumberToObject(o, "t", (double)pick->t);
        cJSON_AddNumberToObject(o, "up", pick->up);
        cJSON_AddStringToObject(o, "m", pick->msg);
        cJSON_AddStringToObject(o, "k", from == 0 ? "sec" : "net");
        cJSON_AddItemToArray(arr, o);
    }
    xSemaphoreGive(s_lock);
    return arr;
}
