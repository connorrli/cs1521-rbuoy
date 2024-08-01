#ifndef HELPERS_H_
#define HELPERS_H_

FILE *File_Open(char *pathname, char *open_type, char *file_type);
void Out_Create_TABI(FILE *f, char *in_pathnames[], size_t num_in_pathnames, char *magic_number);
void Out_Create_TBBI(FILE *tabi, FILE *tbbi);

#endif