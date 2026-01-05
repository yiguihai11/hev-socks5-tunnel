/* Enable GNU extensions for pthread_tryjoin_np and pthread_cancel */
#define _GNU_SOURCE

#ifdef ANDROID

#include <jni.h>
#include <pthread.h>
#include <time.h>
#include <errno.h>

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

#include "hev-main.h"
#include "hev-logger.h"

#include "hev-jni.h"

/* clang-format off */
#ifndef PKGNAME
#define PKGNAME hev/htproxy
#endif
#ifndef CLSNAME
#define CLSNAME TProxyService
#endif
/* clang-format on */

#define STR(s) STR_ARG (s)
#define STR_ARG(c) #c
#define N_ELEMENTS(arr) (sizeof (arr) / sizeof ((arr)[0]))

#define STOP_TIMEOUT_MS 5000 /* 5 seconds timeout for graceful shutdown */

typedef struct _ThreadData ThreadData;

struct _ThreadData
{
    char *path;
    int fd;
};

static int is_working;
static JavaVM *java_vm;
static pthread_t work_thread;
static pthread_mutex_t mutex;
static pthread_key_t current_jni_env;
static int force_quit; /* Force quit flag */

static void native_start_service (JNIEnv *env, jobject thiz, jstring conig_path,
                                  jint fd);
static void native_stop_service (JNIEnv *env, jobject thiz);
static jlongArray native_get_stats (JNIEnv *env, jobject thiz);

static JNINativeMethod native_methods[] = {
    { "TProxyStartService", "(Ljava/lang/String;I)V",
      (void *)native_start_service },
    { "TProxyStopService", "()V", (void *)native_stop_service },
    { "TProxyGetStats", "()[J", (void *)native_get_stats },
};

static void
detach_current_thread (void *env)
{
    (*java_vm)->DetachCurrentThread (java_vm);
}

jint
JNI_OnLoad (JavaVM *vm, void *reserved)
{
    JNIEnv *env = NULL;
    jclass klass;

    java_vm = vm;
    if (JNI_OK != (*vm)->GetEnv (vm, (void **)&env, JNI_VERSION_1_4)) {
        return 0;
    }

    klass = (*env)->FindClass (env, STR (PKGNAME) "/" STR (CLSNAME));
    (*env)->RegisterNatives (env, klass, native_methods,
                             N_ELEMENTS (native_methods));
    (*env)->DeleteLocalRef (env, klass);

    pthread_key_create (&current_jni_env, detach_current_thread);
    pthread_mutex_init (&mutex, NULL);

    return JNI_VERSION_1_4;
}

static void *
thread_handler (void *data)
{
    ThreadData *tdata = data;

    printf ("DEBUG: thread_handler starting with path=%s, fd=%d\n",
            tdata->path ? tdata->path : "NULL", tdata->fd);
    fflush (stdout);

    hev_socks5_tunnel_main (tdata->path, tdata->fd);

    printf ("DEBUG: thread_handler finished\n");
    fflush (stdout);

    free (tdata->path);
    free (tdata);

    return NULL;
}

static void
native_start_service (JNIEnv *env, jobject thiz, jstring config_path, jint fd)
{
    const jbyte *bytes;
    ThreadData *tdata;
    int res;

    printf ("DEBUG: native_start_service called with fd=%d\n", fd);
    fflush (stdout);

    pthread_mutex_lock (&mutex);

    if (is_working) {
        printf ("DEBUG: service already working\n");
        fflush (stdout);
        goto exit;
    }

    tdata = malloc (sizeof (ThreadData));
    tdata->fd = fd;

    bytes = (const jbyte *)(*env)->GetStringUTFChars (env, config_path, NULL);
    tdata->path = strdup ((const char *)bytes);
    (*env)->ReleaseStringUTFChars (env, config_path, (const char *)bytes);

    res = pthread_create (&work_thread, NULL, thread_handler, tdata);
    if (res != 0) {
        free (tdata->path);
        free (tdata);
        goto exit;
    }

    is_working = 1;
exit:
    pthread_mutex_unlock (&mutex);
}

static void
native_stop_service (JNIEnv *env, jobject thiz)
{
    struct timespec timeout;
    int ret;
    int wait_count = 0;
    const int max_wait_ms = STOP_TIMEOUT_MS;
    const int check_interval_ms = 100;

    pthread_mutex_lock (&mutex);

    if (!is_working) {
        LOG_D ("jni: service not working, nothing to stop");
        goto exit;
    }

    LOG_I ("jni: stopping native service with %d ms timeout", max_wait_ms);

    /* Send quit signal to C program */
    force_quit = 0;
    hev_socks5_tunnel_quit ();

    /* Wait for thread to finish with timeout */
    /* pthread_join with timeout using multiple checks */
    for (wait_count = 0; wait_count < (max_wait_ms / check_interval_ms);
         wait_count++) {
        /* Try to join with non-blocking check */
        ret = pthread_tryjoin_np (work_thread, NULL);
        if (ret == 0) {
            LOG_I ("jni: native thread exited gracefully");
            is_working = 0;
            goto exit;
        }

        if (ret != EBUSY) {
            LOG_W ("jni: pthread_tryjoin_np error: %d", ret);
            break;
        }

        /* Thread still running, wait a bit */
        usleep (check_interval_ms * 1000);

        /* Log progress every second */
        if ((wait_count * check_interval_ms) % 1000 == 0) {
            LOG_D ("jni: waiting for thread to exit... (%d ms elapsed)",
                   wait_count * check_interval_ms);
        }
    }

    /* Timeout reached, force quit */
    LOG_W ("jni: native thread did not exit after %d ms, forcing shutdown",
           max_wait_ms);

    force_quit = 1;

    /* Send SIGTERM to thread group */
    pthread_kill (work_thread, SIGTERM);

    /* Final wait with shorter timeout */
    for (wait_count = 0; wait_count < 10; wait_count++) {
        ret = pthread_tryjoin_np (work_thread, NULL);
        if (ret == 0) {
            LOG_I ("jni: native thread exited after SIGTERM");
            is_working = 0;
            goto exit;
        }
        usleep (100000); /* 100ms */
    }

    /* Last resort: cancel the thread */
    LOG_E ("jni: native thread did not respond to SIGTERM, cancelling");
    ret = pthread_cancel (work_thread);
    if (ret == 0) {
        pthread_join (work_thread, NULL);
        LOG_W ("jni: native thread was cancelled");
    } else {
        LOG_E ("jni: failed to cancel thread: %d", ret);
    }

    is_working = 0;
exit:
    pthread_mutex_unlock (&mutex);
}

static jlongArray
native_get_stats (JNIEnv *env, jobject thiz)
{
    size_t tx_packets, rx_packets, tx_bytes, rx_bytes;
    jlongArray res;
    jlong array[4];

    hev_socks5_tunnel_stats (&tx_packets, &tx_bytes, &rx_packets, &rx_bytes);
    array[0] = tx_packets;
    array[1] = tx_bytes;
    array[2] = rx_packets;
    array[3] = rx_bytes;

    res = (*env)->NewLongArray (env, 4);
    (*env)->SetLongArrayRegion (env, res, 0, 4, array);

    return res;
}

#endif /* ANDROID */
