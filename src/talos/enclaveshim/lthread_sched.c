/*
 * Lthread
 * Copyright (C) 2012, Hasan Alayli <halayli@gmail.com>
 * Copyright (C) 2017 Imperial College London
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * lthread_sched.c
 */


#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <pthread.h>
#include <errno.h>
#include <inttypes.h>

#include "sgx_thread.h"

#include "lthread_int.h"
#include "tree.h"
#include "mpmc_queue.h"

#define FD_KEY(f,e) (((int64_t)(f) << (sizeof(int32_t) * 8)) | e)
#define FD_EVENT(f) ((int32_t)(f))
#define FD_ONLY(f) ((f) >> ((sizeof(int32_t) * 8)))

extern int my_printf(const char *format, ...);

static inline int _lthread_sleep_cmp(struct lthread *l1, struct lthread *l2);
static inline int _lthread_wait_cmp(struct lthread *l1, struct lthread *l2);

static inline int
_lthread_sleep_cmp(struct lthread *l1, struct lthread *l2)
{
    if (l1->sleep_usecs < l2->sleep_usecs)
        return (-1);
    if (l1->sleep_usecs == l2->sleep_usecs)
        return (0);
    return (1);
}

static inline int
_lthread_wait_cmp(struct lthread *l1, struct lthread *l2)
{
    if (l1->fd_wait < l2->fd_wait)
        return (-1);
    if (l1->fd_wait == l2->fd_wait)
        return (0);
    return (1);
}

RB_GENERATE(lthread_rb_sleep, lthread, sleep_node, _lthread_sleep_cmp);
RB_GENERATE(lthread_rb_wait, lthread, wait_node, _lthread_wait_cmp);

static inline int _lthread_sched_isdone(struct lthread_sched *sched);

static struct lthread find_lt;


/*
 * Returns 0 if there is a pending job in scheduler or 1 if done and can exit.
 */
static inline int
_lthread_sched_isdone(struct lthread_sched *sched)
{
    return (RB_EMPTY(&sched->waiting) &&
        LIST_EMPTY(&sched->busy) &&
        RB_EMPTY(&sched->sleeping) &&
        TAILQ_EMPTY(&sched->ready));
}

void
lthread_run(void* ecall_queue, void* ocall_queue, int tid, int appthreads, int sgxthreads, int lthread_tasks, int ncycles, struct mpmc_queue* sched_ready_q, struct mpmc_queue* sched_ocall_q, uint64_t* rdtsc_value)
{
    struct lthread_sched *sched;
    struct lthread *lt = NULL;
    //size_t pauses = ncycles;

    sched = lthread_get_sched();
    /* scheduler not initiliazed, and no lthreads where created */
    if (sched == NULL)
        return;

    int i;
#if SGX_THREAD_SLEEPING
    uint64_t work_duration = 0;
    uint64_t loop_duration = 0;
#endif
    for (;;) {
#if SGX_THREAD_SLEEPING
        uint64_t startwork, startloop;
        startloop = __atomic_load_n(rdtsc_value, __ATOMIC_RELAXED);
#endif

    	/* 1. check if there is an ocall result */
    	if (mpmc_queue_dequeue(sched_ocall_q, (void **)&lt)) {
    		if (mpmc_wait_for_result(ocall_queue, lt->task_args.slot, 0)) {
    			//my_printf("ocall gonna resume task %p slot %d\n", lt, lt->task_args.slot);
#if SGX_THREAD_SLEEPING
    			startwork = __atomic_load_n(rdtsc_value, __ATOMIC_RELAXED);
#endif
    			_lthread_resume(lt);
    			//pauses = ncycles;
#if SGX_THREAD_SLEEPING
    			work_duration += __atomic_load_n(rdtsc_value, __ATOMIC_RELAXED)-startwork;
#endif
    			//my_printf("ocall gonna resume task %p slot %d done ocall = %d size = %d\n", lt, lt->task_args.slot, lt->task_args.do_ocall, lt->task_args.size);

				// the ocall has terminated, and also the ecall which triggered the ocall
				// so enqueue the result for the ecall
				if (lt->task_args.size > 0) {
					mpmc_enqueue_result(ecall_queue, lt->task_args.slot, lt->task_args.size);
				}

	    		struct mpmc_queue* q = (lt->task_args.do_ocall ? sched_ocall_q : sched_ready_q);
	    		for (;!mpmc_queue_enqueue(q, lt);) mpmc_pause();
    		} else {
	    		for (;!mpmc_queue_enqueue(sched_ocall_q, lt);) mpmc_pause();
    		}
    	}

    	/* 2. check if there is an ecall to execute */
    	if (mpmc_queue_dequeue(sched_ready_q, (void **)&lt)) {
			lt->task_args.do_ocall = 0;
			lt->task_args.size = 0;
    		for (i=0; i<appthreads; i++) {
    			char* msg;
    			enum transition_type type = mpmc_dequeue(ecall_queue, i, (void**)&msg);

    			if (type != transition_undef_t) {
    				lt->task_args.msg = msg;
    				lt->task_args.type = type;
    				lt->task_args.slot = i;
        			//my_printf("ecall gonna resume task %p slot %d\n", lt, lt->task_args.slot);
#if SGX_THREAD_SLEEPING
        			startwork = __atomic_load_n(rdtsc_value, __ATOMIC_RELAXED);
#endif
        			_lthread_resume(lt);
        			//pauses = ncycles;

#if SGX_THREAD_SLEEPING
        			work_duration += __atomic_load_n(rdtsc_value, __ATOMIC_RELAXED)-startwork;
#endif
        			//my_printf("ecall gonna resume task %p slot %d done ocall = %d size = %d\n", lt, lt->task_args.slot, lt->task_args.do_ocall, lt->task_args.size);
    				if (lt->task_args.size > 0) {
    					mpmc_enqueue_result(ecall_queue, i, lt->task_args.size);
    				}
    				break; // execute only 1 ecall
    			}
    		}

    		struct mpmc_queue* q = (lt->task_args.do_ocall ? sched_ocall_q : sched_ready_q);
    		for (;!mpmc_queue_enqueue(q, lt);) mpmc_pause();
    	}

    	// decrease the perf: throughput ~1200req/s, does not seem to go beyond this value
    	/*
        if (pauses > 0) {
            pauses--;
        } else {
            ocall_nanosleep(0, 1); 
            pauses = ncycles;
        }
        */

#if SGX_THREAD_SLEEPING
		loop_duration += __atomic_load_n(rdtsc_value, __ATOMIC_RELAXED)-startloop;

		if (loop_duration > 10000000000) {
    		float percentage_of_work = work_duration*100/(float)loop_duration;
    		my_printf("thread %d work %.2f%%\n", tid, percentage_of_work);

    		if (percentage_of_work < 20.0) {
    			if (tid != 0) {
    	    		ocall_sgx_thread_sleep();
    			}
    		} else if (percentage_of_work > 80.0) {
	    		ocall_sgx_thread_wake_up();
    		}

    		work_duration = 0;
    		loop_duration = 0;
		}
#endif
    }

    _sched_free(sched);

    return;
}

/*
 * Cancels registered event in poller and deschedules (fd, ev) -> lt from
 * rbtree. This is safe to be called even if the lthread wasn't waiting on an
 * event.
 */
void
_lthread_cancel_event(struct lthread *lt)
{
    if (lt->state & BIT(LT_ST_WAIT_READ)) {
        lt->state &= CLEARBIT(LT_ST_WAIT_READ);
    } else if (lt->state & BIT(LT_ST_WAIT_WRITE)) {
        lt->state &= CLEARBIT(LT_ST_WAIT_WRITE);
    }

    if (lt->fd_wait >= 0)
        _lthread_desched_event(FD_ONLY(lt->fd_wait), FD_EVENT(lt->fd_wait));
    lt->fd_wait = -1;
}

/*
 * Deschedules an event by removing the (fd, ev) -> lt node from rbtree.
 * It also deschedules the lthread from sleeping in case it was in sleeping
 * tree.
 */
struct lthread *
_lthread_desched_event(int fd, enum lthread_event e)
{
    struct lthread *lt = NULL;
    struct lthread_sched *sched = lthread_get_sched();
    find_lt.fd_wait = FD_KEY(fd, e);

    lt = RB_FIND(lthread_rb_wait, &sched->waiting, &find_lt);
    if (lt != NULL) {
        RB_REMOVE(lthread_rb_wait, &lt->sched->waiting, lt);
        _lthread_desched_sleep(lt);
    }

    return (lt);
}

/*
 * Schedules an lthread for a poller event.
 * Sets its state to LT_EV_(READ|WRITE) and inserts lthread in waiting rbtree.
 * When the event occurs, the state is cleared and node is removed by 
 * _lthread_desched_event() called from lthread_run().
 *
 * If event doesn't occur and lthread expired waiting, _lthread_cancel_event()
 * must be called.
 */
void
_lthread_sched_event(struct lthread *lt, int fd, enum lthread_event e,
    uint64_t timeout)
{
    struct lthread *lt_tmp = NULL;
    enum lthread_st st;
    if (lt->state & BIT(LT_ST_WAIT_READ) || lt->state & BIT(LT_ST_WAIT_WRITE)) {
        my_printf("Unexpected event. lt id %"PRIu64" fd %"PRId64" already in %"PRId32" state\n",
            lt->id, lt->fd_wait, lt->state);
        assert(0);
    }

    if (e == LT_EV_READ) {
        st = LT_ST_WAIT_READ;
    } else if (e == LT_EV_WRITE) {
        st = LT_ST_WAIT_WRITE;
    } else {
        assert(0);
    }

    lt->state |= BIT(st);
    lt->fd_wait = FD_KEY(fd, e);
    lt_tmp = RB_INSERT(lthread_rb_wait, &lt->sched->waiting, lt);
    assert(lt_tmp == NULL);
    if (timeout == -1)
        return;
    _lthread_sched_sleep(lt, timeout);
    lt->fd_wait = -1;
    lt->state &= CLEARBIT(st);
}

/*
 * Removes lthread from sleeping rbtree.
 * This can be called multiple times on the same lthread regardless if it was
 * sleeping or not.
 */
void
_lthread_desched_sleep(struct lthread *lt)
{
    if (lt->state & BIT(LT_ST_SLEEPING)) {
        RB_REMOVE(lthread_rb_sleep, &lt->sched->sleeping, lt);
        lt->state &= CLEARBIT(LT_ST_SLEEPING);
        lt->state |= BIT(LT_ST_READY);
        lt->state &= CLEARBIT(LT_ST_EXPIRED);
    }
}

/*
 * Schedules lthread to sleep for `msecs` by inserting lthread into sleeping
 * rbtree and setting the lthread state to LT_ST_SLEEPING.
 * lthread state is cleared upon resumption or expiry.
 */
void
_lthread_sched_sleep(struct lthread *lt, uint64_t msecs)
{
    struct lthread *lt_tmp = NULL;
    uint64_t usecs = msecs * 1000u;

    /*
     * if msecs is 0, we won't schedule lthread otherwise loop until
     * collision resolved(very rare) by incrementing usec++.
     */
    lt->sleep_usecs = _lthread_diff_usecs(lt->sched->birth,
        _lthread_usec_now()) + usecs;
    while (msecs) {
        lt_tmp = RB_INSERT(lthread_rb_sleep, &lt->sched->sleeping, lt);
        if (lt_tmp) {
            lt->sleep_usecs++;
            continue;
        }
        lt->state |= BIT(LT_ST_SLEEPING);
        break;
    }

    _lthread_yield(lt);
    if (msecs > 0)
        lt->state &= CLEARBIT(LT_ST_SLEEPING);

    lt->sleep_usecs = 0;
}

void
_lthread_sched_busy_sleep(struct lthread *lt, uint64_t msecs)
{

    LIST_INSERT_HEAD(&lt->sched->busy, lt, busy_next);
    lt->state |= BIT(LT_ST_BUSY);
    _lthread_sched_sleep(lt, msecs);
    lt->state &= CLEARBIT(LT_ST_BUSY);
    LIST_REMOVE(lt, busy_next);
}

