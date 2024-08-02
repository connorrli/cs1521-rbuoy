////////////////////////////////////////////////////////////////////////
// COMP1521 24T2 --- Assignment 2: `rbuoy', a simple file synchroniser
// <https://cgi.cse.unsw.edu.au/~cs1521/24T2/assignments/ass2/index.html>
//
// Written by YOUR-NAME-HERE (z5555555) on INSERT-DATE-HERE.
// INSERT-DESCRIPTION-OF-PROGAM-HERE
//
// 2023-07-12   v1.0    Team COMP1521 <cs1521 at cse.unsw.edu.au>


#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "rbuoy.h"
#include "helpers.h"

/// @brief Create a TABI file from an array of pathnames.
/// @param out_pathname A path to where the new TABI file should be created.
/// @param in_pathnames An array of strings containing, in order, the files
//                      that should be placed in the new TABI file.
/// @param num_in_pathnames The length of the `in_pathnames` array. In
///                         subset 5, when this is zero, you should include
///                         everything in the current directory.
void stage_1(char *out_pathname, char *in_pathnames[], size_t num_in_pathnames) {
    // Create file with name `out_pathname`
    FILE *output_file = File_Open(out_pathname, "w", HANDLED);

    Out_Create_TABI(output_file, in_pathnames, num_in_pathnames, TYPE_A_MAGIC);

    fclose(output_file);

    return;
}   


/// @brief Create a TBBI file from a TABI file.
/// @param out_pathname A path to where the new TBBI file should be created.
/// @param in_pathname A path to where the existing TABI file is located.
void stage_2(char *out_pathname, char *in_pathname) {
    FILE *input_file = File_Open(in_pathname, "r", HANDLED);
    FILE *output_file = File_Open(out_pathname, "w", HANDLED);

    Out_Create_TBBI(input_file, output_file);

    fclose(input_file);
    fclose(output_file);
}


/// @brief Create a TCBI file from a TBBI file.
/// @param out_pathname A path to where the new TCBI file should be created.
/// @param in_pathname A path to where the existing TBBI file is located.
void stage_3(char *out_pathname, char *in_pathname) {
    FILE *input_file = File_Open(in_pathname, "r", HANDLED);
    FILE *output_file = File_Open(out_pathname, "w", HANDLED);

    Out_Create_TCBI(input_file, output_file);

    fclose(input_file);
    fclose(output_file);
}


/// @brief Apply a TCBI file to the filesystem.
/// @param in_pathname A path to where the existing TCBI file is located.
void stage_4(char *in_pathname) {
    // TODO: implement this.
}