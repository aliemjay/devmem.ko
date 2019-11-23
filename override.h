static typeof(&kmsg_fops) o_kmsg_fops;
static typeof(&phys_mem_access_prot) o_phys_mem_access_prot;
static typeof(&shmem_get_unmapped_area) o_shmem_get_unmapped_area;
static typeof(&shmem_zero_setup) o_shmem_zero_setup;
static typeof(&splice_from_pipe) o_splice_from_pipe;
static typeof(&unxlate_dev_mem_ptr) o_unxlate_dev_mem_ptr;
static typeof(&xlate_dev_mem_ptr) o_xlate_dev_mem_ptr;
#ifdef ARCH_HAS_VALID_PHYS_ADDR_RANGE
static typeof(&valid_mmap_phys_addr_range) o_valid_mmap_phys_addr_range;
static typeof(&valid_phys_addr_range) o_valid_phys_addr_range;
#endif
#ifdef CONFIG_STRICT_DEVMEM
static typeof(&devmem_is_allowed) o_devmem_is_allowed;
#endif


#undef xlate_dev_mem_ptr
#undef unxlate_dev_mem_ptr

#define kmsg_fops (*o_kmsg_fops)
#define phys_mem_access_prot (*o_phys_mem_access_prot)
#define shmem_get_unmapped_area (*o_shmem_get_unmapped_area)
#define shmem_zero_setup (*o_shmem_zero_setup)
#define splice_from_pipe (*o_splice_from_pipe)
#define unxlate_dev_mem_ptr (*o_unxlate_dev_mem_ptr)
#define xlate_dev_mem_ptr (*o_xlate_dev_mem_ptr)

#ifdef ARCH_HAS_VALID_PHYS_ADDR_RANGE
#define valid_mmap_phys_addr_range (*o_valid_mmap_phys_addr_range)
#define valid_phys_addr_range (*o_valid_phys_addr_range)
#endif

#ifdef CONFIG_STRICT_DEVMEM
#define devmem_is_allowed (*o_devmem_is_allowed)
#endif


static const struct o_sym {
	char *orig_name;
	unsigned long *sym;
} o_syms[] = {
	{"kmsg_fops", (unsigned long *)&o_kmsg_fops},
	{"phys_mem_access_prot", (unsigned long *)&o_phys_mem_access_prot},
	{"shmem_get_unmapped_area", (unsigned long *)&o_shmem_get_unmapped_area},
	{"shmem_zero_setup", (unsigned long *)&o_shmem_zero_setup},
	{"splice_from_pipe", (unsigned long *)&o_splice_from_pipe},
	{"unxlate_dev_mem_ptr", (unsigned long *)&o_unxlate_dev_mem_ptr},
	{"xlate_dev_mem_ptr", (unsigned long *)&o_xlate_dev_mem_ptr},
#ifdef ARCH_HAS_VALID_PHYS_ADDR_RANGE
	{"valid_mmap_phys_addr_range", (unsigned long *)&o_valid_mmap_phys_addr_range},
	{"valid_phys_addr_range", (unsigned long *)&o_valid_phys_addr_range},
#endif
#ifdef CONFIG_STRICT_DEVMEM
	{"devmem_is_allowed", (unsigned long *)&o_devmem_is_allowed},
#endif
};
