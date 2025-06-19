/*─────────────────────────────────────────────────────────────
  auth_lockout_ip.c   ―  IP별 로그인 실패 누적·지연 플러그인
  빌드 :
     gcc -fPIC -shared -Wall -Werror \
         -I/usr/include/mosquitto \
         auth_lockout_ip.c -o auth_lockout_ip.so -lpthread
─────────────────────────────────────────────────────────────*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdbool.h>
#include <unistd.h>
#include <crypt.h>
#include <shadow.h>

#ifdef _WIN32
#  include <windows.h>
#else
#  include <pthread.h>
#endif

#include "mosquitto.h"
#include "mosquitto_broker.h"
#include "mosquitto_plugin.h"
#include "uthash.h"

/* ── 기본 설정 값 ───────────────────────────────────────── */
static int THRESHOLD     = 5;
static int BASE_DELAY    = 10;
static int MAX_DELAY     = 300;
static int EVICTION_TIME = 3600;
static int CONN_RATE_COUNT = 60; // 60 connections
static int CONN_RATE_SECONDS = 60; // per 60 seconds

/* ── 실패 정보 해시 ─────────────────────────────────────── */
typedef struct {
    char ip[40];
    int  count;
    time_t last_fail;
    int  delay;
    UT_hash_handle hh;
} fail_entry;
static fail_entry *fail_map = NULL;

/* New hash map for connection rate tracking */
typedef struct {
    char ip[40];
    int conn_count;
    time_t window_start;
    UT_hash_handle hh;
} conn_rate_entry;
static conn_rate_entry *conn_rate_map = NULL;

#ifdef _WIN32
static CRITICAL_SECTION fail_mtx;
static CRITICAL_SECTION conn_rate_mtx;
#else
static pthread_mutex_t  fail_mtx;
static pthread_mutex_t  conn_rate_mtx;
#endif

/* ── 옵션 파서 ─────────────────────────────────────────── */
static int get_int_opt(const char *key,int def,struct mosquitto_opt *opts,int n)
{
    const char *val = NULL;
    for(int i=0;i<n;++i) if(!strcmp(opts[i].key,key)){ val = opts[i].value; break;}
    return val ? atoi(val) : def;
}

/* ── 비밀번호 검사 (shadow) ───────────────────────────── */
static bool check_password(const char *u,const char *p)
{
    mosquitto_log_printf(MOSQ_LOG_INFO, "[auth-lockout-ip] check_password called for user '%s'", u);

    struct spwd *sp = getspnam(u);
    if(!sp) {
        mosquitto_log_printf(MOSQ_LOG_WARNING, "[auth-lockout-ip] getspnam failed for user '%s'. User not found or permission error.", u);
        return false; /* User not found or permission error */
    }

    mosquitto_log_printf(MOSQ_LOG_INFO, "[auth-lockout-ip] Found user '%s'. Hash starts with: %.3s...", u, sp->sp_pwdp);

    if (strncmp(sp->sp_pwdp, "!", 1) == 0 || strncmp(sp->sp_pwdp, "*", 1) == 0) {
        mosquitto_log_printf(MOSQ_LOG_WARNING, "[auth-lockout-ip] User '%s' account is locked.", u);
        return false;
    }

    const char* crypted_pass = crypt(p, sp->sp_pwdp);
    if (!crypted_pass) {
        mosquitto_log_printf(MOSQ_LOG_ERR, "[auth-lockout-ip] crypt() function failed. Check library support.");
        return false;
    }

    bool match = strcmp(crypted_pass, sp->sp_pwdp) == 0;

    if (match) {
        mosquitto_log_printf(MOSQ_LOG_INFO, "[auth-lockout-ip] Password for user '%s' is CORRECT.", u);
    } else {
        mosquitto_log_printf(MOSQ_LOG_WARNING, "[auth-lockout-ip] Password for user '%s' is INCORRECT.", u);
    }

    return match;
}

/* ── Plugin API v5 스텁 및 콜백 ───────────────────────── */
static mosquitto_plugin_id_t *g_pid=NULL;
static int auth_cb(int event,void *evdata,void *ud);

mosq_plugin_EXPORT int mosquitto_plugin_version(int supported_version_count, const int *supported_versions)
{
    for (int i = 0; i < supported_version_count; i++) {
        if (supported_versions[i] == 5) {
            return 5;
        }
    }
    return -1;
}
mosq_plugin_EXPORT int mosquitto_auth_plugin_version(void){ return 5; }

/* ── 초기화 ───────────────────────────────────────────── */
mosq_plugin_EXPORT
int mosquitto_plugin_init(mosquitto_plugin_id_t *id,void **ud,
                          struct mosquitto_opt *opts,int n_opts)
{
    g_pid=id;
    THRESHOLD     = get_int_opt("threshold",THRESHOLD,opts,n_opts);
    BASE_DELAY    = get_int_opt("base_delay",BASE_DELAY,opts,n_opts);
    MAX_DELAY     = get_int_opt("max_delay",MAX_DELAY,opts,n_opts);
    EVICTION_TIME = get_int_opt("eviction_time",EVICTION_TIME,opts,n_opts);
    CONN_RATE_COUNT = get_int_opt("conn_rate_count", CONN_RATE_COUNT, opts, n_opts);
    CONN_RATE_SECONDS = get_int_opt("conn_rate_seconds", CONN_RATE_SECONDS, opts, n_opts);

#ifdef _WIN32
    InitializeCriticalSection(&fail_mtx);
    InitializeCriticalSection(&conn_rate_mtx);
#else
    if(pthread_mutex_init(&fail_mtx,NULL)) return MOSQ_ERR_UNKNOWN;
    if(pthread_mutex_init(&conn_rate_mtx,NULL)) return MOSQ_ERR_UNKNOWN;
#endif
    mosquitto_log_printf(MOSQ_LOG_INFO,
        "[auth-lockout-ip] Init (shadow auth) thr=%d base=%d max=%d evict=%d rate_limit=%d/%ds",
        THRESHOLD,BASE_DELAY,MAX_DELAY,EVICTION_TIME, CONN_RATE_COUNT, CONN_RATE_SECONDS);

    return mosquitto_callback_register(g_pid,
                                       MOSQ_EVT_BASIC_AUTH,
                                       auth_cb,NULL,NULL);
}

/* ── 정리 ─────────────────────────────────────────────── */
mosq_plugin_EXPORT
int mosquitto_plugin_cleanup(void *ud,struct mosquitto_opt *o,int n)
{
    mosquitto_callback_unregister(g_pid,MOSQ_EVT_BASIC_AUTH,auth_cb,NULL);

    fail_entry *fe,*ft;
    HASH_ITER(hh,fail_map,fe,ft){ HASH_DEL(fail_map,fe); free(fe);}

    conn_rate_entry *ce, *ct;
    HASH_ITER(hh, conn_rate_map, ce, ct) { HASH_DEL(conn_rate_map, ce); free(ce); }

#ifdef _WIN32
    DeleteCriticalSection(&fail_mtx);
    DeleteCriticalSection(&conn_rate_mtx);
#else
    pthread_mutex_destroy(&fail_mtx);
    pthread_mutex_destroy(&conn_rate_mtx);
#endif
    mosquitto_log_printf(MOSQ_LOG_INFO,"[auth-lockout-ip] Cleanup done.");
    return MOSQ_ERR_SUCCESS;
}

/* ── 인증 콜백 ─────────────────────────────────────────── */
static int auth_cb(int event,void *evdata,void *ud)
{
    struct mosquitto_evt_basic_auth *ev = evdata;
    const char *ip = mosquitto_client_address(ev->client);
    if(!ip) return MOSQ_ERR_AUTH;

    time_t now=time(NULL);

    /* --- Connection Rate Limiting --- */
#ifdef _WIN32
    EnterCriticalSection(&conn_rate_mtx);
#else
    pthread_mutex_lock(&conn_rate_mtx);
#endif
    conn_rate_entry *ce = NULL;
    HASH_FIND_STR(conn_rate_map, ip, ce);
    if (!ce) {
        ce = malloc(sizeof *ce);
        strncpy(ce->ip, ip, sizeof(ce->ip)-1); ce->ip[sizeof(ce->ip)-1]='\0';
        ce->conn_count = 1;
        ce->window_start = now;
        HASH_ADD_STR(conn_rate_map, ip, ce);
    } else {
        if (now - ce->window_start <= CONN_RATE_SECONDS) {
            ce->conn_count++;
        } else {
            ce->conn_count = 1;
            ce->window_start = now;
        }
    }
    if (ce->conn_count > CONN_RATE_COUNT) {
        mosquitto_log_printf(MOSQ_LOG_WARNING, "[auth-lockout-ip] Deny %s: Connection rate exceeded (%d/%ds)", ip, ce->conn_count, CONN_RATE_SECONDS);
#ifdef _WIN32
        LeaveCriticalSection(&conn_rate_mtx);
#else
        pthread_mutex_unlock(&conn_rate_mtx);
#endif
        return MOSQ_ERR_AUTH;
    }
#ifdef _WIN32
    LeaveCriticalSection(&conn_rate_mtx);
#else
    pthread_mutex_unlock(&conn_rate_mtx);
#endif

    /* --- Login Failure Backoff Logic (Original) --- */
    fail_entry *e=NULL;

#ifdef _WIN32
    EnterCriticalSection(&fail_mtx);
#else
    pthread_mutex_lock(&fail_mtx);
#endif
    HASH_FIND_STR(fail_map,ip,e);

    if(e && now-e->last_fail>EVICTION_TIME){ HASH_DEL(fail_map,e); free(e); e=NULL; }

    if(e && now<e->last_fail+e->delay){
#ifdef _WIN32
        LeaveCriticalSection(&fail_mtx);
#else
        pthread_mutex_unlock(&fail_mtx);
#endif
        mosquitto_log_printf(MOSQ_LOG_NOTICE,
            "[auth-lockout-ip] deny %s@%s (cool %ds)",ev->username,ip,e->delay);
        return MOSQ_ERR_AUTH;
    }

    if(check_password(ev->username,ev->password)){
        if(e){ HASH_DEL(fail_map,e); free(e); }
#ifdef _WIN32
        LeaveCriticalSection(&fail_mtx);
#else
        pthread_mutex_unlock(&fail_mtx);
#endif
        return MOSQ_ERR_SUCCESS;
    }

    if(!e){
        e=malloc(sizeof *e);
        strncpy(e->ip,ip,sizeof(e->ip)-1); e->ip[sizeof(e->ip)-1]='\0';
        e->count=0; e->delay=0;
        HASH_ADD_STR(fail_map,ip,e);
    }
    e->count++; e->last_fail=now;

    if(e->count>=THRESHOLD){
        e->delay = e->delay ? e->delay*2 : BASE_DELAY;
        if(e->delay>MAX_DELAY) e->delay=MAX_DELAY;
        mosquitto_log_printf(MOSQ_LOG_WARNING,
            "[auth-lockout-ip] %s fail %d× ⇒ delay %d",ip,e->count,e->delay);
    }else{
        mosquitto_log_printf(MOSQ_LOG_INFO,
            "[auth-lockout-ip] %s fail cnt %d",ip,e->count);
    }
#ifdef _WIN32
    LeaveCriticalSection(&fail_mtx);
#else
    pthread_mutex_unlock(&fail_mtx);
#endif
    return MOSQ_ERR_AUTH;
}
