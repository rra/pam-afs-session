/*
 * Test handling of k_hasafs failure.
 *
 * Written by Russ Allbery <eagle@eyrie.org>
 * Copyright 2015 Russ Allbery <eagle@eyrie.org>
 * Copyright 2011
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/system.h>

#include <tests/fakepam/script.h>
#include <tests/tap/basic.h>

/* Provided by the fakekafs layer. */
extern int fakekafs_hasafs;


int
main(void)
{
    struct script_config config;

    /* Set up the plan. */
    plan_lazy();

    /* Claim that AFS doesn't exist. */
    fakekafs_hasafs = 0;

    /* Run all of the tests. */
    memset(&config, 0, sizeof(config));
    config.user = "test";
    run_script_dir("data/scripts/hasafs", &config);

    return 0;
}
