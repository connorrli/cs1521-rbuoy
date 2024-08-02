#ifndef HELPERS_H_
#define HELPERS_H_

enum Open_Errors { HANDLED = 0, NOT_HANDLED };

FILE *File_Open(char *pathname, char *open_type, enum Open_Errors handled);

void Out_Create_TABI(FILE *f, char *in_pathnames[], size_t num_in_pathnames, char *magic_number);
void Out_Create_TBBI(FILE *tabi, FILE *tbbi);
void Out_Create_TCBI(FILE* tbbi, FILE *tcbi);

#endif