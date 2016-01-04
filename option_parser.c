#include <stdio.h>
#include <getopt.h>
#include "config.h"
#include "util.h"
#include "properties.h"
#include "version.h"
#include "option_parser.h"

char configFilePath [256] = NTRACE_CONFIG_FILE;

static struct option options [] = {
    {"config", required_argument, NULL, 'C'},
    {"version", no_argument, NULL, 'v'},
    {"help", no_argument, NULL, 'h'},
    {NULL, no_argument, NULL, 0},
};

static void
showHelpInfo (const char *cmd) {
    const char *cmdName;

    cmdName = strrchr (cmd, '/') ? (strrchr (cmd, '/') + 1) : cmd;
    fprintf (stdout,
             "Usage: %s -C <config_file>\n"
             "Options: \n"
             "  -C|--config, config file\n"
             "  -v|--version, version of %s\n"
             "  -h|--help, help information\n",
             cmdName, cmdName);
}

/* Get config file */
char *
getConfigFile (void) {
    return configFilePath;
}

/* Command line options parser */
int
parseOptions (int argc, char *argv []) {
    char option;
    boolean useDefaultConfig = True;
    boolean showVersion = False;
    boolean showHelp = False;

    while ((option = getopt_long (argc, argv, ":C:vh?", options, NULL)) != -1) {
        switch (option) {
            case 'C':
                snprintf(configFilePath, sizeof (configFilePath), "%s", optarg);
                useDefaultConfig = False;
                break;

            case 'v':
                showVersion = True;
                break;

            case 'h':
                showHelp = True;
                break;

            case ':':
                fprintf (stderr, "Miss option argument.\n");
                showHelpInfo (argv [0]);
                return -1;

            case '?':
                fprintf (stderr, "Unknown option.\n");
                showHelpInfo (argv [0]);
                return -1;
        }
    }

    if (showVersion || showHelp) {
        if (showVersion)
            fprintf (stdout, "Current version: %s\n", VERSION_STRING);

        if (showHelp)
            showHelpInfo (argv [0]);
        exit (0);
    }

    if (useDefaultConfig)
        snprintf (configFilePath, sizeof (configFilePath), "%s", NTRACE_CONFIG_FILE);

    return 0;
}
