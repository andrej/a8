#ifndef CONFIG_H
#define CONFIG_H

/**
 * USE_FORK - if set, this will launch each test in its own process. This allows
 * catching and reporting crashing test cases (such as segmentation faults).
 * 
 * If disabled, all tests will be run in the main process. A crashing test
 * will crash the test suite. This is faster and works in more constrained
 * environments.
 */
#define USE_FORK 1

/**
 * ENABLE_PARALLELISM - if set, this allows definition of parallelized tests, 
 * that is tests that make use of parallelization. This does NOT run multiple 
 * tests in parallel; it is purely for defining tests using the PARALLEL_TEST 
 * macros.
 */
#define ENABLE_PARALLELISM 1

#endif