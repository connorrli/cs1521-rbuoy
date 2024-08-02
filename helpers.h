// Header file for helpers.c written by Connor Li (z5425430)
// For implementation details go to helpers.c.

#ifndef HELPERS_H_
#define HELPERS_H_

enum Open_Errors { HANDLED = 0, NOT_HANDLED };

/// @brief Open a file given the pathname, open_type and handled values.
/// @param pathname A path to where the file is/should be located.
/// @param handled An enum to describe how to handle opening errors.
FILE *File_Open(char *pathname, char *open_type, enum Open_Errors handled);

/// @brief Create a TABI file from an array of pathnames.
/// @param f The newly created TABI file
/// @param in_pathnames An array of strings containing, in order, the files
//                      that should be placed in the new TABI file.
/// @param num_in_pathnames The length of the `in_pathnames` array. In
///                         subset 5, when this is zero, you should include
///                         everything in the current directory.
/// @param magic_number The associated magic number (TABI)
void Out_Create_TABI(
    FILE *f, char *in_pathnames[], size_t num_in_pathnames, char *magic_number
);

/// @brief Create a TBBI file from a TABI file.
/// @param out_pathname A path to where the new TBBI file should be created.
/// @param in_pathname A path to where the existing TABI file is located.
void Out_Create_TBBI(FILE *tabi, FILE *tbbi);

/// @brief Create a TBBI file from a TABI file.
/// @param out_pathname A path to where the new TBBI file should be created.
/// @param in_pathname A path to where the existing TABI file is located.
void Out_Create_TCBI(FILE* tbbi, FILE *tcbi);

#endif