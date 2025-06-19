/*
 * auth_token_topic.c - Mosquitto Plugin for Topic-based Authentication.
 * - Uses topic structure for per-message auth: user/pass/timestamp/actual/topic
 * - Caches user credentials on connect to improve performance.
 * - Validates timestamp to prevent replay attacks.
 *
 * WARNING: This design assumes the client sends its password in the topic string.
 *          IT IS CRITICAL TO USE TLS FOR THE MQTT CONNECTION.
 */

 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <time.h>
 #include <stdbool.h>
 #include <pthread.h>
 #include <shadow.h>
 #include <crypt.h>
 
 #include "mosquitto.h"
 #include "mosquitto_broker.h"
 #include "mosquitto_plugin.h"
 #include "uthash.h"
 
 /* Default Settings */
 static long TIMESTAMP_WINDOW = 10; // Allow 10 seconds difference
 
 /* Cached credentials */
 typedef struct {
     char username[256];
     char pass_hash[256]; // The full hash string from /etc/shadow
     UT_hash_handle hh;
 } user_cache_entry;
 
 static user_cache_entry *user_cache = NULL;
 static pthread_mutex_t cache_mtx;
 static mosquitto_plugin_id_t *mosq_pid = NULL;
 
 /* Forward declarations */
 static int acl_cb(int event, void *event_data, void *userdata);
 static int auth_cb(int event, void *event_data, void *userdata);
 
 /* --- Password Verification & Caching --- */
 static bool check_and_cache_password(const char *username, const char *password) {
     struct spwd *sp = getspnam(username);
     if (!sp) {
         return false; // User not found
     }
 
     // IMPORTANT: crypt() is not thread-safe on all platforms without _GNU_SOURCE and -lcrypt
     // For this project, we assume it works as expected.
     char *crypted_pass = crypt(password, sp->sp_pwdp);
     if (!crypted_pass || strcmp(crypted_pass, sp->sp_pwdp) != 0) {
         return false; // Password mismatch
     }
 
     // Auth success, cache the credential
     pthread_mutex_lock(&cache_mtx);
     user_cache_entry *e;
     HASH_FIND_STR(user_cache, username, e);
     if (!e) {
         e = malloc(sizeof(user_cache_entry));
         strncpy(e->username, username, sizeof(e->username) - 1);
         strncpy(e->pass_hash, sp->sp_pwdp, sizeof(e->pass_hash) - 1);
         HASH_ADD_STR(user_cache, username, e);
         mosquitto_log_printf(MOSQ_LOG_INFO, "[token-topic] Cached credential for user '%s'.", username);
     }
     pthread_mutex_unlock(&cache_mtx);
     return true;
 }
 
 /* --- Main Plugin Callbacks --- */
 
 static int auth_cb(int event, void *event_data, void *userdata) {
     struct mosquitto_evt_basic_auth *ed = event_data;
     if (check_and_cache_password(ed->username, ed->password)) {
         return MOSQ_ERR_SUCCESS;
     }
     return MOSQ_ERR_AUTH;
 }
 
 static int acl_cb(int event, void *event_data, void *userdata) {
     struct mosquitto_evt_acl_check *ed = event_data;
 
     // This plugin only cares about PUBLISH attempts
     if (ed->access != MOSQ_ACL_WRITE) {
         return MOSQ_ERR_SUCCESS;
     }
 
     char *topic_copy = strdup(ed->topic);
     char *saveptr;
     
     // 1. Parse Username
     char *username = strtok_r(topic_copy, "/", &saveptr);
     if (!username) { free(topic_copy); return MOSQ_ERR_SUCCESS; } // Not our special format
 
     // 2. Parse Password
     char *password = strtok_r(NULL, "/", &saveptr);
     if (!password) { free(topic_copy); return MOSQ_ERR_SUCCESS; }
 
     // 3. Parse Timestamp
     char *timestamp_str = strtok_r(NULL, "/", &saveptr);
     if (!timestamp_str) { free(topic_copy); return MOSQ_ERR_SUCCESS; }
 
     // 4. Get actual topic
     char *actual_topic = strtok_r(NULL, "", &saveptr); // The rest of the string
     if (!actual_topic || strlen(actual_topic) == 0) { free(topic_copy); return MOSQ_ERR_SUCCESS; }
 
     // --- Verification --- 
 
     // A. Timestamp check
     time_t topic_time = atol(timestamp_str);
     time_t current_time = time(NULL);
     if (labs(current_time - topic_time) > TIMESTAMP_WINDOW) {
         mosquitto_log_printf(MOSQ_LOG_WARNING, "[token-topic] Denied '%s': Stale timestamp (%ld).", username, topic_time);
         free(topic_copy);
         return MOSQ_ERR_ACL_DENIED;
     }
 
     // B. Password check (using cache)
     pthread_mutex_lock(&cache_mtx);
     user_cache_entry *e;
     HASH_FIND_STR(user_cache, username, e);
     if (!e) { // Not in cache, try to auth and cache now
         pthread_mutex_unlock(&cache_mtx);
         if (!check_and_cache_password(username, password)) {
              mosquitto_log_printf(MOSQ_LOG_WARNING, "[token-topic] Denied '%s': Auth failed for uncached user.", username);
              free(topic_copy);
              return MOSQ_ERR_ACL_DENIED;
         }
         // Re-lock to get the newly cached entry
         pthread_mutex_lock(&cache_mtx);
         HASH_FIND_STR(user_cache, username, e);
     }
 
     char *crypted_pass = crypt(password, e->pass_hash);
     pthread_mutex_unlock(&cache_mtx);
 
     if (!crypted_pass || strcmp(crypted_pass, e->pass_hash) != 0) {
         mosquitto_log_printf(MOSQ_LOG_WARNING, "[token-topic] Denied '%s': Password mismatch in topic.", username);
         free(topic_copy);
         return MOSQ_ERR_ACL_DENIED;
     }
 
     // --- All checks passed --- 
     mosquitto_log_printf(MOSQ_LOG_INFO, "[token-topic] Auth OK for '%s'. Re-publishing to '%s'.", username, actual_topic);
 
     // Re-publish the message to the actual topic
     mosquitto_broker_publish_copy(
         mosquitto_client_id(ed->client),
         actual_topic,
         ed->payloadlen,
         ed->payload,
         ed->qos,
         ed->retain,
         ed->properties
     );
 
     free(topic_copy);
     // Deny the original message to the token-topic
     return MOSQ_ERR_ACL_DENIED;
 }
 
 /* --- Plugin Boilerplate --- */
 
 int mosquitto_plugin_version(int supported_version_count, const int *supported_versions) {
     for (int i = 0; i < supported_version_count; i++) {
         if (supported_versions[i] == 5) return 5;
     }
     return -1;
 }
 
 int mosquitto_plugin_init(mosquitto_plugin_id_t *identifier, void **user_data, struct mosquitto_opt *opts, int opt_count) {
     mosq_pid = identifier;
     pthread_mutex_init(&cache_mtx, NULL);
 
     for (int i = 0; i < opt_count; i++) {
         if (strcmp(opts[i].key, "timestamp_window") == 0) {
             TIMESTAMP_WINDOW = atol(opts[i].value);
         }
     }
 
     mosquitto_log_printf(MOSQ_LOG_INFO, "[token-topic] Plugin started. Timestamp window: %ld seconds.", TIMESTAMP_WINDOW);
 
     // Register both callbacks
     mosquitto_callback_register(mosq_pid, MOSQ_EVT_BASIC_AUTH, auth_cb, NULL, NULL);
     return mosquitto_callback_register(mosq_pid, MOSQ_EVT_ACL_CHECK, acl_cb, NULL, NULL);
 }
 
 int mosquitto_plugin_cleanup(void *user_data, struct mosquitto_opt *opts, int opt_count) {
     user_cache_entry *current_entry, *tmp;
     HASH_ITER(hh, user_cache, current_entry, tmp) {
         HASH_DEL(user_cache, current_entry);
         free(current_entry);
     }
     pthread_mutex_destroy(&cache_mtx);
     return MOSQ_ERR_SUCCESS;
 }