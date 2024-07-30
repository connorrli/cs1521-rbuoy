#ifndef HELPERS_H_
#define HELPERS_H_

FILE *Out_Open(char *pathname, char *open_type);
void Out_Create_Table(FILE *f, char *in_pathnames[], size_t num_in_pathnames, char *magic_number);

#endif