#include <stdio.h>
#include <sys/stat.h>
#include <string.h>
#include <limits.h>
#include "helpers.h"
#include "rbuoy.h"

#define BITS_IN_BYTE 8
#define START_BYTE (MAGIC_SIZE + NUM_RECORDS_SIZE)

//////////////////////////////////////////////////////////////////////
//                        FUNCTION PROTOTYPES
//////////////////////////////////////////////////////////////////////

// CONVERTING //

void int_to_bytes(uint64_t num, unsigned char bytes[], int num_bytes);

uint64_t bytes_to_uint(uint8_t bytes[], uint64_t num_bytes);

// FETCHING //

uint64_t file_get_size(FILE *f);

struct stat file_get_stat(char *pathname);

size_t file_get_num_blocks(long bytes, char *pathname);

void file_get_hashes(FILE *src, uint64_t hashes[], size_t num_blocks);

void file_find_matches(
    FILE *tabi, uint64_t hashes[], uint8_t match_bytes[], 
    size_t num_blocks, size_t max_blocks, size_t num_match_bytes
);

uint64_t block_get_trailing(uint64_t size);

uint64_t block_get_hash(
    FILE *src, char block[BLOCK_SIZE], int isTrailing, long trailing_size
);

size_t file_get_num_records(FILE *f);

// APPENDING & COPYING //

void out_append_header(FILE *f, char *magic_number, int num_records);

void file_append_hashes(
    FILE *src, FILE *dest, uint64_t hashes[], size_t num_hashes
);

void file_append_matches(
    FILE* src, FILE *dest, char *pathname, size_t num_blocks
);

size_t file_append_updates(FILE *src, FILE *tbbi, FILE *tcbi, size_t num_blocks);

void file_append_size(FILE *f);

void file_append_type(FILE *f, uint64_t type);

void file_append_permissions(FILE *f, uint64_t type);

size_t file_copy_num_blocks(FILE *src, FILE *dest);

void file_copy_pathname(
    FILE* src, FILE* dest, size_t pathname_length, char pathname[]
);

size_t file_copy_pathname_length(FILE* src, FILE* dest);

// ERROR CHECKING //

void enforce_identifier(FILE *f, char *magic_number);

void check_eof(FILE *f);

// FUNCTION WRAPPERS (W/ ERROR CHECKS) //

void fseek_handler(FILE *f, long offset, int whence);

void fread_handler(void *ptr, size_t size, size_t n, FILE *stream);

void fputc_handler(FILE *f, int8_t c);

//////////////////////////////////////////////////////////////////////
//                        INTERFACE FUNCTIONS
//////////////////////////////////////////////////////////////////////

FILE *File_Open(char *pathname, char *open_type, enum Open_Errors handled) {
    FILE *f = fopen(pathname, open_type);

    if (f == NULL) {
        if (handled == HANDLED) {
            perror("Error");
            exit(1);
        }

        if (handled == NOT_HANDLED) return f;

        // TODO: Cover case for TYPE_C_MAGIC depending on requirements
    }
    return f;
}

void Out_Create_TABI(FILE *f, char *in_pathnames[], size_t num_in_pathnames, char *magic_number) {
    int counter = 0;

    // Set pointer to just after the header
    fseek_handler(f, START_BYTE, SEEK_SET);
    for (size_t i = 0; i < num_in_pathnames; i++) {
        if (counter > UCHAR_MAX) {
            fprintf(stderr, "Error: Too many files, > %u", UCHAR_MAX);
            exit(1);
        }

        // Get file status
        struct stat stat = file_get_stat(in_pathnames[i]);

        // Get path length
        size_t path_length = strlen(in_pathnames[i]);
        if ((path_length | USHRT_MAX) > USHRT_MAX) {
            fprintf(
                stderr, "Error: file '%s' length > %u", 
                in_pathnames[i], USHRT_MAX
            );
            exit(1);
        }

        // Get number of 256-byte blocks
        size_t num_blocks = file_get_num_blocks(
            stat.st_size, in_pathnames[i]
        );

        unsigned char path_length_bytes[PATHNAME_LEN_SIZE];
        int_to_bytes(path_length, path_length_bytes, PATHNAME_LEN_SIZE);

        unsigned char num_blocks_bytes[NUM_BLOCKS_SIZE];
        int_to_bytes(num_blocks, num_blocks_bytes, NUM_BLOCKS_SIZE);

        // Write record details
        fwrite(path_length_bytes, sizeof(char), PATHNAME_LEN_SIZE, f);
        fwrite(in_pathnames[i], sizeof(char), path_length, f);
        fwrite(num_blocks_bytes, sizeof(char), NUM_BLOCKS_SIZE, f);

        // Write hashed blocks separately
        FILE *local_file = File_Open(in_pathnames[i], "rb", NOT_HANDLED);

        counter++;

        if (num_blocks <= 0) continue;

        uint64_t hashes[num_blocks];

        file_get_hashes(local_file, hashes, num_blocks);
        file_append_hashes(local_file, f, hashes, num_blocks);

        fclose(local_file);
    }
    out_append_header(f, magic_number, counter);

    return;
}

void Out_Create_TBBI(FILE *tabi, FILE *tbbi) {
    enforce_identifier(tabi, TYPE_A_MAGIC);

    size_t num_records = file_get_num_records(tabi);

    fseek_handler(tabi, START_BYTE, SEEK_SET);
    fseek_handler(tbbi, START_BYTE, SEEK_SET);
    for (size_t record_n = 0; record_n < num_records; record_n++) {
        size_t pathname_length = file_copy_pathname_length(tabi, tbbi);
        char pathname[pathname_length + 1];
        file_copy_pathname(tabi, tbbi, pathname_length, pathname);
        size_t num_blocks = file_copy_num_blocks(tabi, tbbi);

        if (num_blocks == 0) continue;

        file_append_matches(tabi, tbbi, pathname, num_blocks);
    }
    out_append_header(tbbi, TYPE_B_MAGIC, num_records);

    check_eof(tabi);
    return;
}

void Out_Create_TCBI(FILE* tbbi, FILE *tcbi) {
    enforce_identifier(tbbi, TYPE_B_MAGIC);

    size_t num_records = file_get_num_records(tbbi);

    fseek_handler(tbbi, START_BYTE, SEEK_SET);
    for (size_t record_n = 0; record_n < num_records; record_n++) {
        size_t pathname_length = file_copy_pathname_length(tbbi, tcbi);
        char pathname[pathname_length + 1];
        file_copy_pathname(tbbi, tcbi, pathname_length, pathname);

        uint8_t num_blocks_bytes[NUM_BLOCKS_SIZE];
        fread_handler(num_blocks_bytes, sizeof(uint8_t), NUM_BLOCKS_SIZE, tbbi);
        size_t num_blocks = bytes_to_uint(num_blocks_bytes, NUM_BLOCKS_SIZE);

        struct stat stat = file_get_stat(pathname);

        file_append_type(tcbi, stat.st_mode);
        file_append_permissions(tcbi, stat.st_mode);
        file_append_size(tcbi);

        FILE *local_file = File_Open(pathname, "r", HANDLED);

        int64_t update_size_pos = ftell(tcbi); 
        fseek_handler(tcbi, UPDATE_LEN_SIZE, SEEK_CUR);
        size_t num_updates = file_append_updates(local_file, tbbi, tcbi, num_blocks);
        int64_t curr_pos = ftell(tcbi); 

        fseek_handler(tcbi, update_size_pos, SEEK_SET);
        uint8_t size_bytes[UPDATE_LEN_SIZE];
        int_to_bytes(num_updates, size_bytes, UPDATE_LEN_SIZE);
        fwrite(size_bytes, sizeof(uint8_t), UPDATE_LEN_SIZE, tcbi);

        // Return back to original spot
        fseek_handler(tcbi, curr_pos, SEEK_SET);
    }
}

size_t file_append_updates(FILE *src, FILE *tbbi, FILE *tcbi, size_t num_blocks) {
    if (num_blocks == 0) return 0;
    
    size_t num_match_bytes = num_tbbi_match_bytes(num_blocks);

    size_t counter = 0;

    uint8_t match_bytes[num_match_bytes];
    fread_handler(match_bytes, sizeof(uint8_t), num_match_bytes, tbbi);

    for (size_t match_byte_n = 0; match_byte_n < num_match_bytes; match_byte_n++) {
        size_t block_n = 0;
        while (block_n < MATCH_BYTE_BITS) {
            if ((match_bytes[match_byte_n] & 0x01) == 0x01) {
                // Get the block's index
                size_t block_index = (match_byte_n * MATCH_BYTE_BITS) + block_n;
                uint8_t block_index_bytes[BLOCK_INDEX_SIZE];
                int_to_bytes(block_index, block_index_bytes, BLOCK_INDEX_SIZE);

                // Get the update length (i.e. block length)
                size_t update_length = (block_index + 1 == num_blocks) ?
                block_get_trailing(file_get_size(src)) : BLOCK_SIZE;
                uint8_t update_length_bytes[UPDATE_LEN_SIZE];
                int_to_bytes(update_length, update_length_bytes, UPDATE_LEN_SIZE);

                // Get bytes for file
                uint8_t buffer[BLOCK_SIZE];
                fseek_handler(src, block_index, SEEK_SET);
                fread_handler(buffer, sizeof(uint8_t), BLOCK_SIZE, src);

                // Write in that order (block_index, update_length, block data)
                fwrite(block_index_bytes, sizeof(uint8_t), BLOCK_INDEX_SIZE, tcbi);
                fwrite(update_length_bytes, sizeof(uint8_t), UPDATE_LEN_SIZE, tcbi);
                fwrite(buffer, sizeof(uint8_t), BLOCK_SIZE, tcbi);

                counter++;
            }

            match_bytes[match_byte_n] >>= 1;
            block_n++;
        }
    }
    
    return counter;
}

void file_append_size(FILE *f) {
    uint8_t file_size_bytes[FILE_SIZE_SIZE];

    uint64_t size = file_get_size(f);
    int_to_bytes(size, file_size_bytes, FILE_SIZE_SIZE);

    fwrite(file_size_bytes, sizeof(uint8_t), FILE_SIZE_SIZE, f);

    return;
}

void file_append_type(FILE *f, uint64_t type) {
    switch (type & __S_IFMT) {
        case __S_IFREG: fputc_handler(f, '-'); break;
        case __S_IFDIR: fputc_handler(f, 'd'); break;
        // Not necessary but just in case
        default: fputc_handler(f, '?'); break;
    }
}

void fputc_handler(FILE *f, int8_t c) {
    int8_t status = fputc(c, f);
    if (status == EOF) {
        fprintf(stderr, "Error: fputc failed");
        exit(1);
    }
}

void file_append_permissions(FILE *f, uint64_t type) {
    int8_t val = type & ~__S_IFMT;

    for (size_t i = 1; i < MODE_SIZE; i++) {
        switch (i % 3) {
            case 1:
                (val & S_IRUSR) ? 
                fputc_handler(f, 'r') : fputc_handler(f, '-');
                break;
            case 2:
                (val & S_IRUSR) ?
                fputc_handler(f, 'w') : fputc_handler(f, '-');
                break;
            case 0:
                (val & S_IRUSR) ? 
                fputc_handler(f, 'x') : fputc_handler(f, '-');
                break;
        }
    }

    return;
}

//////////////////////////////////////////////////////////////////////
//                           LOCAL HELPERS
//////////////////////////////////////////////////////////////////////

void out_append_header(FILE *f, char *magic_number, int num_records) {
    fseek_handler(f, 0, SEEK_SET);
    if (num_records > 0xFF) {
        fprintf(stderr, "Error: Too many records (> 256)");
        exit(1);
    }
    
    for (int i = 0; i < MAGIC_SIZE; i++) {
        fputc(magic_number[i], f);
    }

    fputc(num_records, f);

    return;
}

void file_get_hashes(FILE *src, uint64_t hashes[], size_t num_blocks) {
    const size_t TRAILING_BLOCK = num_blocks - 1;

    uint64_t size = file_get_size(src);

    uint64_t trailing_size = block_get_trailing(size);

    for (size_t block_n = 0; block_n < num_blocks; block_n++) {
        fseek_handler(src, BLOCK_SIZE * block_n, SEEK_SET);

        int isTrailing = (block_n == TRAILING_BLOCK) ? 1 : 0;

        char block[BLOCK_SIZE];
        uint64_t hashed_block = block_get_hash(src, block, isTrailing, trailing_size);

        hashes[block_n] = hashed_block;
    }
}

void file_append_hashes(FILE *src, FILE *dest, uint64_t hashes[], size_t num_hashes) {
    for (size_t hash_n = 0; hash_n < num_hashes; hash_n++) {
        unsigned char hashed_chars[HASH_SIZE];
        int_to_bytes(hashes[hash_n], hashed_chars, HASH_SIZE);

        fwrite(hashed_chars, sizeof(char), HASH_SIZE, dest);
    }

    return;
}

uint64_t block_get_trailing(uint64_t size) {
    uint64_t trailing_size_mod = size % BLOCK_SIZE;
    // If trailing block size is 256, don't make it equal to 0
    return (trailing_size_mod == 0) ? BLOCK_SIZE : trailing_size_mod;
}

uint64_t block_get_hash(
    FILE *src, char block[BLOCK_SIZE], int isTrailing, long trailing_size
) {
    uint64_t hashed_block;
    if (isTrailing) {
        fread_handler(block, sizeof(char), trailing_size, src);
        hashed_block = hash_block(block, trailing_size);
    } else {
        fread_handler(block, sizeof(char), BLOCK_SIZE, src);
        hashed_block = hash_block(block, BLOCK_SIZE);
    }

    return hashed_block;
}

struct stat file_get_stat(char *pathname) {
    struct stat buffer;
    int status;
    if ((status = stat(pathname, &buffer)) != 0) {
        perror("Missing File");
        exit(1);
    }

    return buffer;
}

size_t file_get_num_blocks(long bytes, char *pathname) {
    // LOCAL CONSTS
    const int MAX_3_BYTES = 0xFFFFFF;

    size_t num_blocks = number_of_blocks_in_file(bytes);
    if ((num_blocks | MAX_3_BYTES) > MAX_3_BYTES) {
        fprintf(
            stderr, "Error: file '%s' too large", 
            pathname
        );
        exit(1);
    }

    return num_blocks;
}

void int_to_bytes(uint64_t num, unsigned char bytes[], int num_bytes) {
    // Put largest number in biggest index to make little-endian
    for (int i = num_bytes - 1; i >= 0; i--) {
        bytes[i] = (num >> i * BITS_IN_BYTE) & 0xFF;
    }
}

// Simple function that call fseek but errors out on fail
void fseek_handler(FILE *f, long offset, int whence) {
    if (fseek(f, offset, whence) != 0) {
        perror("Seek Failed");
        exit(1);
    }

    return;
}

// Simple function that call fread but errors out on fail
void fread_handler(void *ptr, size_t size, size_t n, FILE *stream) {
    if (fread(ptr, size, n, stream) < n) {
        perror("Read Failed");
        exit(1);
    }
}

uint64_t bytes_to_uint(uint8_t bytes[], uint64_t num_bytes) {
    uint64_t converted = 0;

    for (uint64_t byte_n = 0; byte_n < num_bytes; byte_n++) {
        converted += ((uint64_t)bytes[byte_n] << (byte_n * BITS_IN_BYTE));
    }

    return converted;
}

uint64_t file_get_size(FILE *f) {
    if (f == NULL) return 0;

    long pos = ftell(f);
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, pos, SEEK_SET);

    return size;
}

void enforce_identifier(FILE *f, char *magic_number) {
    unsigned char magic[MAGIC_SIZE];
    fread_handler(magic, sizeof(char), MAGIC_SIZE, f);

    for (size_t i = 0; i < MAGIC_SIZE; i++) {
        if (magic[i] != magic_number[i]) {
            fprintf(stderr, "Error: Invalid file (missing TABI)");
            exit(1);
        }
    }

    fseek_handler(f, 0, SEEK_SET);
    return;
}

void check_eof(FILE *f) {
    if (fgetc(f) != EOF) {
        fprintf(stderr, "Error: visited all records but not EOF");
        exit(1);
    }
}

void file_find_matches(
    FILE *tabi, uint64_t hashes[], uint8_t match_bytes[], 
    size_t num_blocks, size_t max_blocks, size_t num_match_bytes
) {
    uint64_t match_index = 0;

    // Cover for first byte. Should have at least 1 byte but just in case.
    if (num_match_bytes > 0) match_bytes[0] = 0;

    for (size_t block_n = 0; block_n < num_blocks; block_n++) {
        if (block_n % 8 == 0 && block_n != 0) {
            match_index++;
            match_bytes[match_index] = 0;
        } else {
            match_bytes[match_index] = match_bytes[match_index] << 1;
        }

        uint8_t buffer[HASH_SIZE];
        fread_handler(buffer, sizeof(char), HASH_SIZE, tabi);

        if (block_n >= max_blocks) continue;

        uint64_t src_block_hash = bytes_to_uint(buffer, HASH_SIZE);
        // If they are the same hash, then this block is a match
        if (src_block_hash == hashes[block_n]) {
            match_bytes[match_index] |= 0x01;
        }

        if (block_n == num_blocks - 1) {
            uint8_t right_padding_amount = 7 - (block_n % 8);
            match_bytes[match_index] = match_bytes[match_index] << right_padding_amount;
        }
    }
}

void file_append_matches(FILE* src, FILE *dest, char *pathname, size_t num_blocks) {
    FILE *local_file = File_Open(pathname, "r", NOT_HANDLED);

    size_t num_local_blocks = file_get_num_blocks(
        file_get_size(local_file),
        pathname
    );

    // If file not found or no blocks, then matches is 0
    size_t num_match_bytes = num_tbbi_match_bytes(num_blocks);
    uint8_t match_bytes[num_match_bytes];
    
    if (local_file == NULL || num_local_blocks == 0) {
        uint64_t placeholder_array[1];
        file_find_matches(
            src, placeholder_array, match_bytes, num_blocks, 0, num_match_bytes
        );
    } else {
        uint64_t hashes[num_local_blocks];
        file_get_hashes(local_file, hashes, num_local_blocks);

        size_t max_num_blocks = (num_blocks > num_local_blocks) ? 
        num_local_blocks : num_blocks;

        file_find_matches(
            src, hashes, match_bytes, num_blocks, max_num_blocks, num_match_bytes
        );
    }

    fwrite(match_bytes, sizeof(char), num_match_bytes, dest);
    if (local_file != NULL) fclose(local_file);
}

size_t file_copy_pathname_length(FILE* src, FILE* dest) { 
    uint8_t pathname_length_bytes[PATHNAME_LEN_SIZE];
    fread_handler(
        pathname_length_bytes, sizeof(char), PATHNAME_LEN_SIZE, src
    );
    size_t pathname_length = bytes_to_uint(
        pathname_length_bytes, PATHNAME_LEN_SIZE
    );

    fwrite(pathname_length_bytes, sizeof(char), PATHNAME_LEN_SIZE, dest);

    return pathname_length;
}

void file_copy_pathname(
    FILE* src, FILE* dest, size_t pathname_length, char pathname[]
) { 
    fread_handler(
        pathname, sizeof(char), pathname_length, src
    );
    pathname[pathname_length] = '\0';

    fwrite(pathname, sizeof(char), pathname_length, dest);
}

size_t file_copy_num_blocks(FILE *src, FILE *dest) {
    uint8_t num_blocks_bytes[NUM_BLOCKS_SIZE];
    fread_handler(
        num_blocks_bytes, sizeof(char), NUM_BLOCKS_SIZE, src
    );

    fwrite(num_blocks_bytes, sizeof(char), NUM_BLOCKS_SIZE, dest);

    return bytes_to_uint(num_blocks_bytes, NUM_BLOCKS_SIZE);;
}

size_t file_get_num_records(FILE *f) {
    fseek_handler(f, MAGIC_SIZE, SEEK_SET);
    unsigned char num_record_char[NUM_RECORDS_SIZE];
    fread_handler(num_record_char, sizeof(char), NUM_RECORDS_SIZE, f);
    fseek_handler(f, 0, SEEK_SET);

    return bytes_to_uint(num_record_char, 1); 
}

