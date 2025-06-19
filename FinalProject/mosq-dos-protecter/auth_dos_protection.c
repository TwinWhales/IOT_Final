/*
 * auth_dos_protection.c - Mosquitto Plugin for DoS Protection.
 * - Limits message publishing rate per client.
 * - Restricts maximum payload size.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdbool.h>
#include <pthread.h>

#include "mosquitto.h"
#include "mosquitto_broker.h"
#include "mosquitto_plugin.h"
#include "uthash.h"

/* Default Settings */
static int MSG_RATE_COUNT = 10;      // Max 10 messages
static int MSG_RATE_SECONDS = 1;     // per 1 second
static int MAX_PAYLOAD_SIZE = 1048576; // 1 MB

/* Data structure for tracking client message rates */
typedef struct {
    char client_id[256];
    int msg_count;
    time_t last_timestamp;
    UT_hash_handle hh;
} rate_entry;

static rate_entry *rate_map = NULL;
static pthread_mutex_t rate_mtx;

static int acl_cb(int event, void *event_data, void *userdata) {
    struct mosquitto_evt_acl_check *ed = event_data;
    
    // We only care about PUBLISH attempts
    if (ed->access != MOSQ_ACL_WRITE) {
        return MOSQ_ERR_SUCCESS;
    }

    // 1. Check Payload Size
    if (ed->payloadlen > MAX_PAYLOAD_SIZE) {
        mosquitto_log_printf(MOSQ_LOG_WARNING, "[dos-protection] Denied client '%s': Payload too large (%d > %d bytes).", 
            mosquitto_client_id(ed->client), ed->payloadlen, MAX_PAYLOAD_SIZE);
        return MOSQ_ERR_ACL_DENIED;
    }

    // 2. Check Message Rate
    const char *client_id = mosquitto_client_id(ed->client);
    if (!client_id) return MOSQ_ERR_ACL_DENIED;

    pthread_mutex_lock(&rate_mtx);

    rate_entry *e;
    HASH_FIND_STR(rate_map, client_id, e);

    time_t now = time(NULL);

    if (!e) {
        e = malloc(sizeof(rate_entry));
        strncpy(e->client_id, client_id, sizeof(e->client_id) - 1);
        e->msg_count = 1;
        e->last_timestamp = now;
        HASH_ADD_STR(rate_map, client_id, e);
    } else {
        if (now - e->last_timestamp < MSG_RATE_SECONDS) {
            e->msg_count++;
        } else {
            e->msg_count = 1;
            e->last_timestamp = now;
        }
    }

    if (e->msg_count > MSG_RATE_COUNT) {
        mosquitto_log_printf(MOSQ_LOG_WARNING, "[dos-protection] Denied client '%s': Message rate exceeded (%d/%ds).", 
            client_id, e->msg_count, MSG_RATE_SECONDS);
        pthread_mutex_unlock(&rate_mtx);
        return MOSQ_ERR_ACL_DENIED;
    }

    pthread_mutex_unlock(&rate_mtx);
    return MOSQ_ERR_SUCCESS;
}

int mosquitto_plugin_version(int supported_version_count, const int *supported_versions) {
    for (int i = 0; i < supported_version_count; i++) {
        if (supported_versions[i] == 5) return 5;
    }
    return -1;
}

int mosquitto_plugin_init(mosquitto_plugin_id_t *identifier, void **user_data, struct mosquitto_opt *opts, int opt_count) {
    pthread_mutex_init(&rate_mtx, NULL);

    for (int i = 0; i < opt_count; i++) {
        if (strcmp(opts[i].key, "msg_rate_count") == 0) {
            MSG_RATE_COUNT = atoi(opts[i].value);
        } else if (strcmp(opts[i].key, "msg_rate_seconds") == 0) {
            MSG_RATE_SECONDS = atoi(opts[i].value);
        } else if (strcmp(opts[i].key, "max_payload_size") == 0) {
            MAX_PAYLOAD_SIZE = atoi(opts[i].value);
        }
    }

    mosquitto_log_printf(MOSQ_LOG_INFO, "[dos-protection] Plugin started. Rate: %d msgs / %d sec. Max Payload: %d bytes.", 
        MSG_RATE_COUNT, MSG_RATE_SECONDS, MAX_PAYLOAD_SIZE);

    return mosquitto_callback_register(identifier, MOSQ_EVT_ACL_CHECK, acl_cb, NULL, NULL);
}

int mosquitto_plugin_cleanup(void *user_data, struct mosquitto_opt *opts, int opt_count) {
    rate_entry *current_entry, *tmp;
    HASH_ITER(hh, rate_map, current_entry, tmp) {
        HASH_DEL(rate_map, current_entry);
        free(current_entry);
    }
    pthread_mutex_destroy(&rate_mtx);
    return MOSQ_ERR_SUCCESS;
}
