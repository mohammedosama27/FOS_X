
#include <inc/lib.h>

// malloc()
//	This function use BEST FIT strategy to allocate space in heap
//  with the given size and return void pointer to the start of the allocated space

//	To do this, we need to switch to the kernel, allocate the required space
//	in Page File then switch back to the user again.
//
//	We can use sys_allocateMem(uint32 virtual_address, uint32 size); which
//		switches to the kernel mode, calls allocateMem(struct Env* e, uint32 virtual_address, uint32 size) in
//		"memory_manager.c", then switch back to the user mode here
//	the allocateMem function is empty, make sure to implement it.

#define max_pages ((USER_HEAP_MAX - USER_HEAP_START) / PAGE_SIZE)

static uint32 next_fit_index = 0;
bool alloc_map[(USER_HEAP_MAX-USER_HEAP_START)/PAGE_SIZE] = {0};

struct Allocation {
    uint32 base_va;
    uint32 pages_count;
    uint32 size;
} allocations[(USER_HEAP_MAX-USER_HEAP_START)/PAGE_SIZE];
static int alloc_count = 0;

//==================================================================================//
//============================ REQUIRED FUNCTIONS ==================================//
//==================================================================================//

void* malloc(uint32 size)
{
	//TODO: [PROJECT 2025 - MS2 - [2] User Heap] malloc() [User Side]
	// Write your code here, remove the panic and write your code
	//panic("malloc() is not implemented yet...!!");

	// Steps:
	//	1) Implement BEST FIT strategy to search the heap for suitable space
	//		to the required allocation size (space should be on 4 KB BOUNDARY)
	//	2) if no suitable space found, return NULL
	//	 Else,
	//	3) Call sys_allocateMem to invoke the Kernel for allocation
	// 	4) Return pointer containing the virtual address of allocated space,
	//

	//This function should find the space of the required range
	// ******** ON 4KB BOUNDARY ******************* //

	//Use sys_isUHeapPlacementStrategyBESTFIT() to check the current strategy

	//change this "return" according to your answer
	//return 0;

	if (size == 0 || size > (USER_HEAP_MAX - USER_HEAP_START)) {
		return NULL;
	}

	uint32 size_needed = ROUNDUP(size, PAGE_SIZE);
	uint32 pages_needed = size_needed / PAGE_SIZE;

	// Use Next-Fit to find a suitable region
	uint32 va = 0;
	uint32 count = 0;
	uint32 start = next_fit_index;

	for (uint32 checked = 0; checked < max_pages; checked++) {
		uint32 i = (start + checked) % max_pages;

		if (!alloc_map[i]) {
			count++;
			if (count == pages_needed) {
				uint32 start_index = (i + 1 - pages_needed + max_pages) % max_pages;
				next_fit_index = (start_index + pages_needed) % max_pages;
				va = (USER_HEAP_START + start_index*PAGE_SIZE);
				break;
			}
		}
		else {
			count = 0;
		}
	}

	if (va == 0) {
		return NULL;
	}

	// Request kernel to allocate memory
	sys_allocateMem(va, pages_needed*PAGE_SIZE);

	// Mark allocated pages
	uint32 start_index = (va - USER_HEAP_START)/PAGE_SIZE;
    for(uint32 i = 0; i < pages_needed; i++) {
    	alloc_map[start_index + i] = 1;
    }

	allocations[alloc_count].base_va = va;
	allocations[alloc_count].pages_count = pages_needed;
	allocations[alloc_count].size = size_needed;
	alloc_count++;

	return (void*)va;

}

void* smalloc(char *sharedVarName, uint32 size, uint8 isWritable)
{
	// Write your code here, remove the panic and write your code
	panic("smalloc() is not required...!!");

	// Steps:
	//	1) Implement BEST FIT strategy to search the heap for suitable space
	//		to the required allocation size (space should be on 4 KB BOUNDARY)
	//	2) if no suitable space found, return NULL
	//	 Else,
	//	3) Call sys_createSharedObject(...) to invoke the Kernel for allocation of shared variable
	//		sys_createSharedObject(): if succeed, it returns the ID of the created variable. Else, it returns -ve
	//	4) If the Kernel successfully creates the shared variable, return its virtual address
	//	   Else, return NULL

	//This function should find the space of the required range
	// ******** ON 4KB BOUNDARY ******************* //

	//Use sys_isUHeapPlacementStrategyBESTFIT() to check the current strategy

	//change this "return" according to your answer
	return 0;
}

void* sget(int32 ownerEnvID, char *sharedVarName)
{
	// Write your code here, remove the panic and write your code
	panic("sget() is not required ...!!");

	// Steps:
	//	1) Get the size of the shared variable (use sys_getSizeOfSharedObject())
	//	2) If not exists, return NULL
	//	3) Implement BEST FIT strategy to search the heap for suitable space
	//		to share the variable (should be on 4 KB BOUNDARY)
	//	4) if no suitable space found, return NULL
	//	 Else,
	//	5) Call sys_getSharedObject(...) to invoke the Kernel for sharing this variable
	//		sys_getSharedObject(): if succeed, it returns the ID of the shared variable. Else, it returns -ve
	//	6) If the Kernel successfully share the variable, return its virtual address
	//	   Else, return NULL
	//

	//This function should find the space for sharing the variable
	// ******** ON 4KB BOUNDARY ******************* //

	//Use sys_isUHeapPlacementStrategyBESTFIT() to check the current strategy

	//change this "return" according to your answer
	return 0;
}

// free():
//	This function frees the allocation of the given virtual_address
//	To do this, we need to switch to the kernel, free the pages AND "EMPTY" PAGE TABLES
//	from page file and main memory then switch back to the user again.
//
//	We can use sys_freeMem(uint32 virtual_address, uint32 size); which
//		switches to the kernel mode, calls freeMem(struct Env* e, uint32 virtual_address, uint32 size) in
//		"memory_manager.c", then switch back to the user mode here
//	the freeMem function is empty, make sure to implement it.

void free(void* virtual_address)
{
	//TODO: [PROJECT 2025 - MS2 - [2] User Heap] free() [User Side]
	// Write your code here, remove the panic and write your code
	//panic("free() is not implemented yet...!!");

	//you should get the size of the given allocation using its address
	//you need to call sys_freeMem()
	//refer to the project presentation and documentation for details

	if (virtual_address == NULL)
		return;

    uint32 va = (uint32)virtual_address;
    int index = -1;
    for (int i = 0; i < alloc_count; ++i) {
        if (allocations[i].base_va == va) {
        	index = i;
            break;
        }
    }

    // Handle error if allocation is not found
    if (index == -1) {
        return; // or handle error accordingly
    }

    uint32 pages_num = allocations[index].pages_count;
    uint32 size = pages_num * PAGE_SIZE;

    //free both page file entries and physical frames
    sys_freeMem(va, size);

    //remove the record
    allocations[index] = allocations[--alloc_count];

	//clear our own bitmap
	uint32 start_index = (va - USER_HEAP_START) / PAGE_SIZE;

	for (uint32 j = 0; j < pages_num; ++j) {
		alloc_map[start_index + j] = 0;
	}
}

//==================================================================================//
//============================== BONUS FUNCTIONS ===================================//
//==================================================================================//

//=============
// [1] sfree():
//=============
//	This function frees the shared variable at the given virtual_address
//	To do this, we need to switch to the kernel, free the pages AND "EMPTY" PAGE TABLES
//	from main memory then switch back to the user again.
//
//	use sys_freeSharedObject(...); which switches to the kernel mode,
//	calls freeSharedObject(...) in "shared_memory_manager.c", then switch back to the user mode here
//	the freeSharedObject() function is empty, make sure to implement it.

void sfree(void* virtual_address)
{
	// Write your code here, remove the panic and write your code
	panic("sfree() is not required ...!!");

	//	1) you should find the ID of the shared variable at the given address
	//	2) you need to call sys_freeSharedObject()

}


//===============
// [2] realloc():
//===============

//	Attempts to resize the allocated space at "virtual_address" to "new_size" bytes,
//	possibly moving it in the heap.
//	If successful, returns the new virtual_address, in which case the old virtual_address must no longer be accessed.
//	On failure, returns a null pointer, and the old virtual_address remains valid.

//	A call with virtual_address = null is equivalent to malloc().
//	A call with new_size = zero is equivalent to free().

//  Hint: you may need to use the sys_moveMem(uint32 src_virtual_address, uint32 dst_virtual_address, uint32 size)
//		which switches to the kernel mode, calls moveMem(struct Env* e, uint32 src_virtual_address, uint32 dst_virtual_address, uint32 size)
//		in "memory_manager.c", then switch back to the user mode here
//	the moveMem function is empty, make sure to implement it.

void *realloc(void *virtual_address, uint32 new_size)
{
	// Write your code here, remove the panic and write your code
	panic("realloc() is not required yet...!!");

}
