#include <inc/memlayout.h>
#include <kern/kheap.h>
#include <kern/memory_manager.h>

//NOTE: All kernel heap allocations are multiples of PAGE_SIZE (4KB)

//needed to store data from kmalloc to kfree
struct allocated_data {
    uint32 start;
    int num_frames;
}arr[999];

int index = 0; //index of the array

void* kmalloc(unsigned int size)
{
	//TODO: [PROJECT 2025 - MS1 - [1] Kernel Heap] kmalloc()
	// Write your code here, remove the panic and write your code
	//kpanic_into_prompt("kmalloc() is not implemented yet...!!");

	//NOTE: Allocation is based on FIRST FIT strategy
	//NOTE: All kernel heap allocations are multiples of PAGE_SIZE (4KB)
	//refer to the project presentation and documentation for details

	//change this "return" according to your answer
	//return NULL;

	if (size == 0) //no space passed
		return NULL;

	int free_count = 0; //number of available consecutive free frames
	uint32 best_start = 0; //starting address for best
	unsigned int best_space = 999999999; //the best (least) available space at the end of block
	uint32 start = 0; //the starting address of currently block
	bool found = 0; //flag

	//num of frames needed to allocate the passed size
	unsigned int needed_frames = ROUNDUP(size, PAGE_SIZE) / PAGE_SIZE;

	//stay in kheap
	//search for best frame(s)
	uint32 i = KERNEL_HEAP_START;
	while (i < KERNEL_HEAP_MAX) {
		uint32 *ptr_page_table = NULL;
		struct Frame_Info *frame_info_ptr = get_frame_info(ptr_page_directory, (void*) i, &ptr_page_table);

		if (frame_info_ptr == NULL) //this frame is empty(not-allocated)
		{
			//start counting from 0 of consecutive free frames
			if (free_count == 0)
				start = i;
			//it is a free frame but has at least free frame before it
			//continue in counting
			free_count++;
		}//end if
		else //the frame is allocated
		{
			//check(these frames are suggested to be the best fit)
			if (free_count >= needed_frames) {
				unsigned int free_space = free_count - needed_frames;
				if (free_space < best_space) {
					best_space = free_space;
					best_start = start;
					found = 1;
				}
			}
			//return to search again until finding a best free_extra
			free_count = 0; //reset to 0
		} //end else
		i += PAGE_SIZE;
	} //end while

	//the heap is completely free(all frames are not allocated)
	if (free_count >= needed_frames) {
		unsigned int extra_space = free_count - needed_frames;
		if (extra_space < best_space) {
			best_space = extra_space;
			best_start = start;
			found = 1;
		}
	}

	//no frames is best for this size(no consecutive space for size)
	if (!found)
		return NULL;

	//save those needed for kfree
	arr[index].start = best_start;
	arr[index].num_frames = needed_frames;
	index++;

	//allocate and map
	for (unsigned int i = 0; i < needed_frames; i++) {
		struct Frame_Info *frame_info_ptr = NULL;
		if (allocate_frame(&frame_info_ptr) != 0) //failed to allocate
			return NULL;
		else //can be allocated correctly
		{
			uint32 va = best_start + (PAGE_SIZE * i);
			map_frame(ptr_page_directory, frame_info_ptr, (void*)(va), PERM_PRESENT|PERM_WRITEABLE);
		}
	}

	return (void*) best_start; //the starting virtual address for the allocated block(frames)
}

void kfree(void* virtual_address)
{
	//TODO: [PROJECT 2025 - MS1 - [1] Kernel Heap] kfree()
	// Write your code here, remove the panic and write your code
	//panic("kfree() is not implemented yet...!!");

	//you need to get the size of the given allocation using its address
	//refer to the project presentation and documentation for details

	uint32 va = (uint32) virtual_address;
	//check if this address is within the boundaries of kheap
	if (va < KERNEL_HEAP_START || va >= KERNEL_HEAP_MAX)
		return;

	int required_frames = 0; //will be equal to num_frames(needed_frames)
	int required_index; //index for the array

	//check all addresses in the array
	for (int i = 0; i < index; i++) {
		if (va == arr[i].start) {
			required_frames = arr[i].num_frames;
			required_index = i;
			break;
		}
	}

	//this address not found in the array as allocated frame
	if (required_frames == 0)
		return;

	//unmap
	for (int i = 0; i < required_frames; i++) {
		uint32* ptr_table = NULL;
		struct Frame_Info* frame_info = get_frame_info(ptr_page_directory, (void*)va, &ptr_table);
		if (frame_info != NULL)
			free_frame(frame_info);

		unmap_frame(ptr_page_directory, (void*) va);
		va += PAGE_SIZE;
	}

	//delete this block from the allocated blocks
	arr[required_index].start = 0;
	arr[required_index].num_frames = 0;

}

unsigned int kheap_virtual_address(unsigned int physical_address)
{
	//TODO: [PROJECT 2025 - MS1 - [1] Kernel Heap] kheap_virtual_address()
	// Write your code here, remove the panic and write your code
	//panic("kheap_virtual_address() is not implemented yet...!!");

	//return the virtual address corresponding to given physical_address
	//refer to the project presentation and documentation for details

	//change this "return" according to your answer

	//return 0;

	for (uint32 VA = KERNEL_HEAP_START; VA < KERNEL_HEAP_MAX; VA += PAGE_SIZE)
	{
		uint32 PDI = PDX(VA);
		uint32 PTI = PTX(VA);
		uint32 PDE = ptr_page_directory[PDI];

		//continue if page table is not present
		if (!(PDE & PERM_PRESENT))
			continue;

		uint32 *PT;
		get_page_table(ptr_page_directory, (void*) VA, &PT);
		//check if page table exists or not
		if (PT == NULL)
			continue;

		uint32 PTE = PT[PTI];

		//continue if the page is not mapped(not-present)
		if (!(PTE & PERM_PRESENT))
			continue;

		uint32 FRAMADD = PTE & 0xFFFFF000;

		if (FRAMADD == (physical_address & 0xFFFFF000)) {
			uint32 OFF = physical_address & 0xFFF;
			return (VA & 0xFFFFF000) | OFF;
		}
	}
	return 0;
}

unsigned int kheap_physical_address(unsigned int virtual_address)
{
	//TODO: [PROJECT 2025 - MS1 - [1] Kernel Heap] kheap_physical_address()
	// Write your code here, remove the panic and write your code
	//panic("kheap_physical_address() is not implemented yet...!!");

	//return the physical address corresponding to given virtual_address
	//refer to the project presentation and documentation for details

	//change this "return" according to your answer

	//return 0;

	uint32 PDI = PDX(virtual_address), PTI = PTX(virtual_address);
	uint32 PDE = ptr_page_directory[PDI];

	//check if the page directory entry is present
	if (!(PDE & PERM_PRESENT))
		return 0;

	uint32 PTPHYS = PDE & 0xFFFFF000;
	uint32 *PT = NULL;
	get_page_table(ptr_page_directory, (void*) virtual_address, &PT);
	//check if page table exists or not
	if (PT == NULL)
		return 0;

	uint32 PTE = PT[PTI];

	//check if the page table entry itself is present
	if (!(PTE & PERM_PRESENT))
		return 0;

	uint32 FRAMADD = PTE & 0xFFFFF000;
	uint32 OFF = virtual_address & 0xFFF;

	uint32 compindPhyAdd = FRAMADD | OFF;
	return compindPhyAdd;
}

void *krealloc(void *virtual_address, uint32 new_size)
{
	panic("krealloc() is not required...!!");
	return NULL;

}
