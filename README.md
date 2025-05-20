# FOS_X
An educational operating system project that works with kernel and user heap. Developed as part of the OS course at Ain Shams University.
This project works with Kernel heap and user heap to allocate and free or handle page fault with buffering.

What we did?
1. Kmalloc(): dynamically allocate space size using the best fit strategy and map it.
2. Kfree(): delete a previously allocated space by removing all its pages from the Kernel Heap.
3. kheap_virtual_address(): find kernel virtual address of the given physical one.
4. kheap_physical_address(): find physical address of the given kernel virtual address.

5. page_fault_handler(): Handle page faults, if working set not full, reclaim buffered page or allocate/read page; else apply modified clock to find a victim page.
6. malloc(): Search user heap using next fit strategy, call sys_allocateMem() on success, return allocated virtual address or NULL.
7. allocateMem(): Add allocated pages to page file in kernel.
8. free(): Call sys_freeMem() to free user heap memory in given range.
9. freeMem_with_buffering(): Free buffered pages, update frame lists, clear page tables, update working sets, and remove pages from page file.
10. free_environment(): For each buffered user page, remove modified pages from modified list and free frames; then free all working set pages, tables, directory, page file, and the environment.
