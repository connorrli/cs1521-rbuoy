// Given up to BLOCK_SIZE (256) bytes, produce the
// hash of that block. You should not modify this file,
// and should not attempt to compile it as part of your
// solution.

// You can run this program yourself using
// 1521 rbuoy-hash-block - for example,
// 1521 rbuoy-hash-block < examples/aaa/emojis.txt

#include "rbuoy.h"
#include <stdio.h>

int main(void) {
	char buf[BLOCK_SIZE];
	// Read in up to BLOCK_SIZE bytes from stdin
	size_t bytes_read = fread(buf, 1, BLOCK_SIZE, stdin);
	// It's important that we pass in the number of bytes read
	// to hash_block - not BLOCK_SIZE - since it's possible that
	// we reach the end of file/user input before filling up
	// the buffer.
	printf("%016lx\n", hash_block(buf, bytes_read));
	return 0;
}
