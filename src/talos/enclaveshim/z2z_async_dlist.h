// doubly linked lists, taken from Linux
// Modified by Yérom-David Bromberg for C++ compatibility

#ifndef __DLIST_H__
#define __DLIST_H__

#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

struct list_head {
  struct list_head *next, *prev;
};

// -----------------------------------------------------------------------
// Create

static inline void INIT_LIST_HEAD(struct list_head *list)
{
	list->next = list;
	list->prev = list;
}

// -----------------------------------------------------------------------
// Add

/*
 * Insert a new entry between two known consecutive entries.
 *
 * This is only for internal list manipulation where we know
 * the prev/next entries already!
 */
static inline void __list_add(struct list_head *newl,
			      struct list_head *prev,
			      struct list_head *next)
{
	next->prev = newl;
	newl->next = next;
	newl->prev = prev;
	prev->next = newl;
}

/**
 * list_add - add a new entry
 * @new: new entry to be added
 * @head: list head to add it after
 *
 * Insert a new entry after the specified head.
 * This is good for implementing stacks.
 */
static inline void list_add(struct list_head *newl, struct list_head *head)
{
	__list_add(newl, head, head->next);
}

/**
 * list_add_tail - add a new entry
 * @new: new entry to be added
 * @head: list head to add it before
 *
 * Insert a new entry before the specified head.
 * This is useful for implementing queues.
 */
static inline void list_add_tail(struct list_head *newl, struct list_head *head)
{
	__list_add(newl, head->prev, head);
}

// -----------------------------------------------------------------------
// Delete

/*
 * Delete a list entry by making the prev/next entries
 * point to each other.
 *
 * This is only for internal list manipulation where we know
 * the prev/next entries already!
 */
static inline void __list_del(struct list_head * prev, struct list_head * next)
{
	next->prev = prev;
	prev->next = next;
}

/**
 * list_del - deletes entry from list.
 * @entry: the element to delete from the list.
 * Note: list_empty() on entry does not return true after this, the entry is
 * in an undefined state.
 */
#define LIST_POISON1  ((void *) 0x00100100)
#define LIST_POISON2  ((void *) 0x00200200)

static inline void list_del(struct list_head *entry)
{
	__list_del(entry->prev, entry->next);
	entry->next = (struct list_head*)LIST_POISON1;
	entry->prev = (struct list_head*)LIST_POISON2;
}

// -----------------------------------------------------------------------
// Iterate

/**
 * list_for_each	-	iterate over a list
 * @pos:	the &struct list_head to use as a loop cursor.
 * @head:	the head for your list.
 */
#define list_for_each(pos, head) \
	for (pos = (head)->next; pos != (head); pos = pos->next)

/**
 * list_for_each_safe - iterate over a list safe against removal of list entry
 * @pos:	the &struct list_head to use as a loop cursor.
 * @n:		another &struct list_head to use as temporary storage
 * @head:	the head for your list.
 */
#define list_for_each_safe(pos, n, head) \
	for (pos = (head)->next, n = pos->next; pos != (head); \
		pos = n, n = pos->next)

/**
* container_of - cast a member of a structure out to the containing structure
* @ptr: the pointer to the member.
* @type: the type of the container struct this is embedded in.
* @member: the name of the member within the struct.
*
*/

/* >>>>>
 * Bromberg hack to make it work with C++
 */
#undef offsetof
#ifndef __cplusplus
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#else /* C++ */
#define offsetof(TYPE, MEMBER) (reinterpret_cast <size_t>		\
				(&reinterpret_cast <char &>(static_cast <TYPE *> (0)->MEMBER)))
#endif /* C++ */

#ifndef __cplusplus
#define container_of(ptr, type, member) ({ \
const typeof( ((type *)0)->member ) *__mptr = (ptr); \
(type *)( (char *)__mptr - offsetof(type,member) );}) 
#else /* C++ */
#define container_of(ptr, type_, member) ({		  \
      const __typeof(static_cast <type_ *> (0)->member) *__mptr = (ptr); \
(type_ *)( (char *)__mptr - offsetof(type_,member) );}) 
#endif /* C++ */

/* <<<<<<<<<<
 */



/**
* list_entry - get the struct for this entry
* @ptr: the &struct list_head pointer.
* @type: the type of the struct this is embedded in.
* @member: the name of the list_struct within the struct.
*/
#define list_entry(ptr, type_, members) \
container_of(ptr, type_, members) 

/**
 * list_first_entry - get the first element from a list
 * @ptr:        the list head to take the element from.
 * @type:       the type of the struct this is embedded in.
 * @member:     the name of the list_struct within the struct.
 *
 * Note, that list is expected to be not empty.
 */
#define list_first_entry(ptr, type, member) \
        list_entry((ptr)->next, type, member)

/**
 * list_for_each_entry	-	iterate over list of given type
 * @pos:	the type * to use as a loop cursor.
 * @head:	the head for your list.
 * @member:	the name of the list_struct within the struct.
 */
#define list_for_each_entry(pos, head, members)				\
	for (pos = list_entry((head)->next, __typeof(*pos), members);	\
	     &pos->members != (head); 	                                \
	     pos = list_entry(pos->members.next, __typeof(*pos), members))

/**
 * list_empty - tests whether a list is empty
 * @head: the list to test.
 */
static inline int list_empty(const struct list_head *head)
{
	return head->next == head;
}

#define init_list(x) (x)->next = (x)->prev = x

#endif /* __DLIST_H__ */

