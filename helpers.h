#ifndef HELPERS_H_
#define HELPERS_H_

FILE *Out_Open(char *pathname, char *open_type);
int Out_Append_Records(FILE *f, char *in_pathnames[], size_t num_in_pathnames);

#endif