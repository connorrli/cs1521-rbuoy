#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <getopt.h>

#include "rbuoy.h"

int main(int argc, char **argv) {
    int stage = 0;
    for (;;) {
        int option_index;
        int opt = getopt_long(
            argc, argv,
            ":1234",
            (struct option[]) {
                {"stage-1", no_argument, NULL, 1},
                {"stage-2", no_argument, NULL, 2},
                {"stage-3", no_argument, NULL, 3},
                {"stage-4", no_argument, NULL, 4},
                {0,         0,           0,    '?'},
            },
            &option_index
        );

        if (opt == -1) {
            break;
        }

        switch (opt) {
            case 1:
            case 2:
            case 3:
            case 4: {
                stage = opt;
                break;
            }
            case ':':
            case '?':
            default: {
                fprintf(stderr, "Usage: %s [--stage-1|--stage-2|--stage-3|--stage-4]\n", argv[0]);
                return EXIT_FAILURE;
            }
        }
    }

    switch (stage) {
        case 1: {
            if (argc - optind < 1) {
                fprintf(stderr, "Usage: %s --stage-1 <outfile> [<file> ...]\n", argv[0]);
                return EXIT_FAILURE;
            }
            char *outfile = argv[optind];
            char **files = argv + optind + 1;
            size_t num_files = argc - optind - 1;
            stage_1(outfile, files, num_files);
            break;
        }
        case 2: {
            if (argc - optind != 2) {
                fprintf(stderr, "Usage: %s --stage-2 <outfile> <infile>\n", argv[0]);
                return EXIT_FAILURE;
            }
            char *outfile = argv[optind];
            char *infile = argv[optind + 1];
            stage_2(outfile, infile);
            break;
        }
        case 3: {
            if (argc - optind != 2) {
                fprintf(stderr, "Usage: %s --stage-3 <outfile> <infile>\n", argv[0]);
                return EXIT_FAILURE;
            }
            char *outfile = argv[optind];
            char *infile = argv[optind + 1];
            stage_3(outfile, infile);
            break;
        }
        case 4: {
            if (argc - optind != 1) {
                fprintf(stderr, "Usage: %s --stage-4 <infile>\n", argv[0]);
                return EXIT_FAILURE;
            }
            char *infile = argv[optind];
            stage_4(infile);
            break;
        }
        case 0: {
            fprintf(stderr, "Usage: %s [--stage-1|--stage-2|--stage-3|--stage-4]\n", argv[0]);
            return EXIT_FAILURE;
        }
    }

    return EXIT_SUCCESS;
}
