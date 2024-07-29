#include <stdlib.h>
#include <stdint.h>
#include <assert.h>

#include "rbuoy.h"


/// @brief Compute the hash of a block of bytes, using the 64 bit NFV-1a hash.
///
/// If you wish to represent your bytes differently (say as an array of uint8_t)
/// you may want to make a wrapper around this function.
///
/// @param block      The array of bytes to be hashed.
/// @param block_size The length of that array. Must be at most 256.
///
/// @return The hash of the block.
uint64_t hash_block(char block[], size_t block_size) {
    assert(block_size <= BLOCK_SIZE);

    uint64_t hash = 0xcbf29ce484222325ull;
    for (size_t i = 0; i < block_size; ++i) {
        hash ^= (unsigned char) block[i];
        hash *= 0x100000001b3;
    }

    return hash;
}


/// @brief Compute the number of blocks in a file, given its size.
/// @param num_bytes The number of bytes in a file.
/// @return The nunber of blocks that are needed for that file.
size_t number_of_blocks_in_file(size_t num_bytes) {
    // This is equal to
    //   ceil(num_bytes / BLOCK_SIZE)
    return (num_bytes + BLOCK_SIZE - 1) / BLOCK_SIZE;
}


/// @brief Compute the nunber of 'match' bytes that are needed for a TBBI record.
/// @param num_blocks The number of blocks.
/// @return The number of 'match' bytes needed.
size_t num_tbbi_match_bytes(size_t num_blocks) {
    // This is equal to
    //   ceil(num_blocks / 8)
    return (num_blocks + MATCH_BYTE_BITS - 1) / MATCH_BYTE_BITS;
}
