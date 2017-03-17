/*
 * From COMPUTATION TOOLS 2012 : The Third International Conference on Computational Logics, Algebras, Programming, Tools, and Benchmarking
 *		Fast Efficient Fixed-Size Memory Pool
 *		No Loops and No Overhead
 *
 *		Ben Kenwright
 *		School of Computer Science
 *		Newcastle University
 *		Newcastle, United Kingdom,
 *		b.kenwright@ncl.ac.uk
 */

#ifndef MEMPOOL_H_
#define MEMPOOL_H_

#include <stddef.h>

typedef unsigned int uint;
typedef unsigned char uchar;

typedef struct mempool {
	uint m_numOfBlocks; //Num of blocks
	uint m_sizeOfEachBlock; //Size of each block
	uint m_numFreeBlocks; //Num of remaining blocks
	uint m_numInitialized; //Num of initialized blocks
	uchar* m_memStart; //Beginning of memory pool
	uchar* m_memEnd; //End of memory pool
	uchar* m_next; //Num of next free block
} mempool;

mempool create_pool(size_t sizeOfEachBlock, uint numOfBlocks);
void destroy_pool(mempool* pool);

inline int pool_address_is_valid(mempool* pool, void* p) {
	return ((uchar*)p >= pool->m_memStart && (uchar*)p <= pool->m_memEnd);
}

void* pool_alloc(mempool* pool);
void pool_dealloc(mempool* pool, void* p);

#endif
