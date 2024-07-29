#ifndef RSYNC_H
#define RSYNC_H

#include <stdlib.h>
#include <stdint.h>


// Sizes (in bytes) of various fields.
#define MAGIC_SIZE        4
#define NUM_RECORDS_SIZE  1
#define PATHNAME_LEN_SIZE 2
#define NUM_BLOCKS_SIZE   3
#define HASH_SIZE         8
#define MODE_SIZE         10
#define FILE_SIZE_SIZE    4
#define BLOCK_INDEX_SIZE  3
#define UPDATE_LEN_SIZE   2

#define MATCH_BYTE_BITS   8

// Note that the rbuoy index magic numbers are exactly 4 bytes, and so
// don't include the nul-terminator implicit at the end of these strings.
#define TYPE_A_MAGIC "TABI"
#define TYPE_B_MAGIC "TBBI"
#define TYPE_C_MAGIC "TCBI"

// The maximum size of a block (the trailing block of a file might be smaller).
#define BLOCK_SIZE 256

// rbuoy.c
void stage_1(char *out_pathname, char *in_pathnames[], size_t num_in_pathnames);
void stage_2(char *out_pathname, char *in_pathname);
void stage_3(char *out_pathname, char *in_pathname);
void stage_4(char *in_pathname);

// rbuoy_provided.c
uint64_t hash_block(char block[], size_t block_size);
size_t number_of_blocks_in_file(size_t num_bytes);
size_t num_tbbi_match_bytes(size_t num_blocks);


#endif /* RSYNC_H */
