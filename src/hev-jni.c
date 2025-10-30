/*
 ============================================================================
 Name        : hev-jni.c
 Author      : hev <r@hev.cc>
 Copyright   : Copyright (c) 2019 - 2023 hev
 Description : Jave Native Interface
 ============================================================================
 */

#ifdef ANDROID

#include <jni.h>
#include <pthread.h>

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>

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

static void native_start_service (JNIEnv *env, jobject thiz, jstring conig_path,
                                  jint fd);
static void native_stop_service (JNIEnv *env, jobject thiz);
static jlongArray native_get_stats (JNIEnv *env, jobject thiz);
static jstring native_get_logs (JNIEnv *env, jobject thiz, jint max_lines);

static JNINativeMethod native_methods[] = {
    { "TProxyStartService", "(Ljava/lang/String;I)V",
      (void *)native_start_service },
    { "TProxyStopService", "()V", (void *)native_stop_service },
    { "TProxyGetStats", "()[J", (void *)native_get_stats },
    { "TProxyGetLogs", "(I)Ljava/lang/String;", (void *)native_get_logs },
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
    if (res < 0) {
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
    pthread_mutex_lock (&mutex);

    if (!is_working)
        goto exit;

    hev_socks5_tunnel_quit ();
    pthread_join (work_thread, NULL);

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

static jstring
native_get_logs (JNIEnv *env, jobject thiz, jint max_lines)
{
    char *logs = hev_logger_get_logs (max_lines);
    jstring result;

    if (!logs) {
        return (*env)->NewStringUTF (env, "Failed to get logs");
    }

    result = (*env)->NewStringUTF (env, logs);
    free (logs);

    return result;
}

#endif /* ANDROID */
