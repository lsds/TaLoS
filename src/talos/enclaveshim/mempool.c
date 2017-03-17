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

#include <string.h>

#include "mempool.h"
#include "enclave_t.h"

mempool create_pool(size_t sizeOfEachBlock, uint numOfBlocks) {
	mempool pool;

	pool.m_numOfBlocks = numOfBlocks;
	pool.m_sizeOfEachBlock = sizeOfEachBlock;
	pool.m_numFreeBlocks = numOfBlocks;
	pool.m_numInitialized = 0;
	ocall_malloc((void**)&pool.m_memStart, sizeOfEachBlock*numOfBlocks);
	pool.m_memEnd = pool.m_memStart + sizeOfEachBlock*numOfBlocks;
	pool.m_next = pool.m_memStart;
	//my_printf("create pool for %u objects of size %ld: [%p, %p]\n", numOfBlocks, sizeOfEachBlock, pool.m_memStart, pool.m_memEnd);

	return pool;
}

void destroy_pool(mempool* pool) {
	ocall_free(pool->m_memStart);
	pool->m_memStart = NULL;
	pool->m_memEnd = NULL;
}

uchar* AddrFromIndex(mempool* pool, uint i) 
{
	return pool->m_memStart + ( i * pool->m_sizeOfEachBlock );
}
uint IndexFromAddr(mempool* pool, const uchar* p) 
{
	return (((uint)(p - pool->m_memStart)) / pool->m_sizeOfEachBlock);
}

void* pool_alloc(mempool* pool) {
	if (pool->m_numInitialized < pool->m_numOfBlocks )
	{
		uint* p = (uint*)AddrFromIndex(pool, pool->m_numInitialized );
		*p = pool->m_numInitialized + 1;
		pool->m_numInitialized++;
	}
	void* ret = NULL;
	if ( pool->m_numFreeBlocks > 0 )
	{
		ret = (void*)pool->m_next;
		--pool->m_numFreeBlocks;
		if (pool->m_numFreeBlocks!=0)
		{
			pool->m_next = AddrFromIndex(pool, *((uint*)pool->m_next) );
		}
		else
		{
			pool->m_next = NULL;
		}
	}
	if (ret) {
		bzero(ret, pool->m_sizeOfEachBlock);
	}
	//my_printf("alloc %p in pool for %u objects of size %ld: [%p, %p]\n", ret, pool->m_numOfBlocks, pool->m_sizeOfEachBlock, pool->m_memStart, pool->m_memEnd);
	return ret;
}

void pool_dealloc(mempool* pool, void* p) {
	//my_printf("free %p in pool for %u objects of size %ld: [%p, %p]\n", p, pool->m_numOfBlocks, pool->m_sizeOfEachBlock, pool->m_memStart, pool->m_memEnd);
	if (pool->m_next != NULL)
	{
		(*(uint*)p) = IndexFromAddr(pool, pool->m_next );
		pool->m_next = (uchar*)p;
	}
	else
	{
		*((uint*)p) = pool->m_numOfBlocks;
		pool->m_next = (uchar*)p;
	}
	++pool->m_numFreeBlocks;
}

