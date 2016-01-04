#include <stdio.h>
#include <signal.h>
#include <pthread.h>
#include "util.h"
#include "signals.h"

/* Thread local SIGUSR1 signal interrupted flag */
static __thread boolean SIGUSR1InterruptedFlag = False;

static void
SIGUSR1Handler (int signo) {
    SIGUSR1InterruptedFlag = True;
}

boolean
taskShouldExit (void) {
    return SIGUSR1InterruptedFlag;
}

void
setupSignals (void) {
    struct sigaction action;

    /* Setup SIGUSR1 signal */
    action.sa_handler = SIGUSR1Handler;
    action.sa_flags = 0;
    sigemptyset (&action.sa_mask);
    sigaction (SIGUSR1, &action, NULL);
}

void
resetSignalsFlag (void) {
    SIGUSR1InterruptedFlag = False;
}
