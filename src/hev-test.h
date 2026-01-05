/*
 ============================================================================
 Name        : hev-test.h
 Author      : L Gemini
 Copyright   : Copyright (c) 2025 L Gemini
 Description : Test Runner
 ============================================================================
 */

#ifndef __HEV_TEST_H__
#define __HEV_TEST_H__

/**
 * g_is_test_mode:
 *
 * Global flag to indicate test mode. When set to 1, certain features
 * like background tasks are disabled to prevent crashes in test environment.
 */
extern int g_is_test_mode;

/**
 * hev_test_run:
 *
 * Runs all built-in tests and reports the results.
 *
 * Returns: 0 on success (all tests passed), -1 on failure.
 */
int hev_test_run (void);

#endif /* __HEV_TEST_H__ */
