/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#define LIBCGC_IMPL
#include "libcgc.h"
#include "ansi_x931_aes128.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/select.h>
#include <sys/types.h>
#include <unistd.h>
#include <err.h>


#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#define MAX(a, b) (((a) < (b)) ? (b) : (a))

#ifdef __linux__
# include <ucontext.h>

/* Notifies a signal handler that a memory read or write is recoverable. */
static int gInTryAccess = 0;

/* Opportunistically try to write a byte to memory, and provide a recovery
 * path for segfaults. */
static int try_write(uint8_t *ptr, uint8_t val) {
  int ret = 0;
  gInTryAccess = 1;
  __asm__ __volatile__ (
    "jmp 1f;"
    ".align 16, 0x90;"
    "1:"
    "movb %0, (%1);"
    "jmp 2f;"
    ".align 16, 0x90;"
    "2:"
    :
    : "r"(val), "r"(ptr)
    : "memory"
  );
  ret = gInTryAccess;
  gInTryAccess = 0;
  return ret;
}

/* Opportunistically try to read a byte to memory, and provide a recovery
 * path for segfaults. */
static int try_read(const uint8_t *ptr, uint8_t *val) {
  uint8_t read_val = 0;
  int ret = 0;

  gInTryAccess = 1;
  __asm__ __volatile__ (
    "jmp 1f;"
    ".align 16, 0x90;"
    "1:"
    "movb (%0), %1;"
    "jmp 2f;"
    ".align 16, 0x90;"
    "2:"
    :
    : "r"(ptr), "r"(read_val)
    : "memory"
  );
  ret = gInTryAccess;
  fault_can_recover = 0;
  if (ret && val) {
    *val = read_val;
  }
  return ret;
}

/* Catch and try to handle a segfault. */
static void catch_fault(int sig, siginfo_t *info, void *context_) {
  (void) sig;
  (void) info;
  if (gInTryAccess) {
    gInTryAccess = 0;
    ucontext_t *context = (ucontext_t *) context_;
    context->uc_mcontext.gregs[REG_RIP] += 16;  // Return to recovery code.
  }
}

#else

/* TODO(withzombies): Add macOS or Windows API calls. */
static int try_write(uint8_t *ptr, uint8_t val) {
  *ptr = val;
  return 1;
}

/* TODO(withzombies): Add macOS or Windows API calls. */
static int try_read(const uint8_t *ptr, uint8_t *val) {
  *val = *ptr;
  return 1;
}
#endif  /* ! __linux__ */

static int gMemoryInitialized = 0;

/* Reserve a large slab of memory that we'll use for doling out allocations.
 * The CGC allocator, for the most part, is a bump pointer allocator, returning
 * pages from a contiguous range. There are some edge cases, e.g. the stack,
 * high memory pressure, etc.
 */
static void init_memory(void) {
  if (gMemoryInitialized) {
    return;
  }
  gMemoryInitialized = 1;
  errno = 0;
#ifdef __linux__
  struct sigaction sig;
  sig.sa_sigaction = catch_fault;
  sig.sa_flags = SA_SIGINFO;
  sig.sa_restorer = NULL;
  sigfillset(&(sig.sa_mask));
  sigaction(SIGSEGV, &sig, nullptr);
#endif  // __linux__
}


/* Returns `1` if a page is readable, otherwise `0`. */
static int page_is_readable(const void *ptr) {
  return try_read((uint8_t *) ptr, NULL);
}

/* Returns `1` if a page is writable, otherwise `0`. */
static int page_is_writable(void *ptr) {
  return try_write((uint8_t *) ptr, 0);
}

/* Returns the number of readable bytes pointed to by `ptr`, up to a maximum
 * of `size` bytes. */
static cgc_size_t num_readable_bytes(const void *ptr, cgc_size_t size) {
  const uintptr_t addr = (uintptr_t) ptr;
  const uintptr_t end_addr = addr + size;
  uintptr_t page_addr = addr & ~(((uintptr_t) PAGE_SIZE) - 1);
  cgc_size_t count = 0;
  cgc_size_t disp = addr - page_addr;
  for (; page_addr < end_addr; page_addr += PAGE_SIZE) {
    if (!page_is_readable((const void *) page_addr)) {
      break;
    }
    count += PAGE_SIZE - disp;
    disp = 0;
  }
  return MIN(count, size);
}

/* Returns the number of writable bytes pointed to by `ptr`, up to a maximum
 * of `size` bytes. */
static cgc_size_t num_writable_bytes(void *ptr, cgc_size_t size) {
  const uintptr_t addr = (uintptr_t) ptr;
  const uintptr_t end_addr = addr + size;
  uintptr_t page_addr = addr & ~(((uintptr_t) PAGE_SIZE) - 1);
  cgc_size_t count = 0;
  cgc_size_t disp = addr - page_addr;
  for (; page_addr < end_addr; page_addr += PAGE_SIZE) {
    if (!page_is_readable((const void *) page_addr) ||
        !page_is_writable((void *) page_addr)) {
      break;
    }
    count += PAGE_SIZE - disp;
    disp = 0;
  }
  return MIN(count, size);
}

/* Terminates the process. */
void _terminate(unsigned int status) {
  exit(status);
  __builtin_unreachable();
}

#define OBJECT_IS_READABLE(ptr) \
  (sizeof(*(ptr)) == num_readable_bytes((ptr), sizeof(*(ptr))))

#define OBJECT_IS_WRITABLE(ptr) \
  (sizeof(*(ptr)) == num_writable_bytes((ptr), sizeof(*(ptr))))

/* Updates a byte counter and returns the corresponding status code. */
static int update_byte_count(cgc_size_t *counter, cgc_size_t count) {
  if (!counter) return 0;
  if (!OBJECT_IS_WRITABLE(counter)) {
    return CGC_EFAULT;
  } else {
    *counter = count;
    return 0;
  }
}

/* Transmits data from one CGC process to another. */
int transmit(int fd, const void *buf, cgc_size_t count, cgc_size_t *tx_bytes) {
  init_memory();
  
  if (!count) {
    return update_byte_count(tx_bytes, 0);
  } else if (0 > fd) {
    return CGC_EBADF;
  }

  const cgc_size_t max_count = num_readable_bytes(buf, count);
  if (!max_count) {
    return CGC_EFAULT;
  } else if (max_count < count) {
    count = max_count & ~2047;
  } else {
    count = max_count;
  }

  errno = 0;
  const cgc_ssize_t ret = write(fd, buf, count);
  const int errno_val = errno;
  errno = 0;

  if (EFAULT == errno_val) {
    return CGC_EFAULT;
  } else if (EBADF == errno_val) {
    return CGC_EBADF;
  } else if (errno_val) {
    return CGC_EPIPE;  /* Guess... */
  } else {
    return update_byte_count(tx_bytes, (cgc_size_t) ret);
  }
}

/* Receives data from another CGC process. */
int receive(int fd, void *buf, cgc_size_t count, cgc_size_t *rx_bytes) {
  init_memory();

  if (!count) {
    return update_byte_count(rx_bytes, 0);
  } else if (0 > fd) {
    return CGC_EBADF;
  }

  const cgc_size_t max_count = num_writable_bytes(buf, count);
  if (!max_count) {
    return CGC_EFAULT;
  }

  errno = 0;
  const cgc_ssize_t ret = read(fd, buf, max_count);
  const int errno_val = errno;
  errno = 0;

  if (EFAULT == errno_val) {
    return CGC_EFAULT;
  } else if (EBADF == errno_val) {
    return CGC_EBADF;
  } else if (errno_val) {
    return CGC_EPIPE;  /* Guess... */
  } else {
    return update_byte_count(rx_bytes, (cgc_size_t) ret);
  }
}

/* Tries to validate a timeout. */
static int check_timeout(const struct cgc_timeval *timeout) {
  if (!timeout) {
    return 0;
  } else if (!OBJECT_IS_READABLE(timeout)) {
    return CGC_EFAULT;
  } else if (0 > timeout->tv_sec || 0 > timeout->tv_usec) {
    return CGC_EINVAL;
  } else {
    return 0;
  }
}

enum {
    // Maximum number of binaries running for one challenge
    kPracticalMaxNumCBs = 10,

    // STD(IN/OUT/ERR) + a socketpair for every binary
    // All fds used by the binaries should be less than this
    kExpectedMaxFDs = 3 + (2 * kPracticalMaxNumCBs)
};

/* Marshal a CGC fd set into an OS fd set. */
static int copy_cgc_fd_set(const cgc_fd_set *cgc_fds, fd_set *os_fds, int *num_fds) {
  for (unsigned fd = 0; fd < CGC__NFDBITS; ++fd) {
    if (CGC_FD_ISSET(fd, cgc_fds)) {
      // Shouldn't be using an fd greater than the allowed values
      if (fd >= kExpectedMaxFDs) {
          return CGC_EBADF;
      }

      if (fd > NFDBITS) {
        continue;  /* OS set size is too small. */
      }
      FD_SET(fd, os_fds);
      ++*num_fds;
    }
  }
  return 0;
}

/* Marshal an OS fd set into a CGC fd set. */
static void copy_os_fd_set(const fd_set *os_fds, cgc_fd_set *cgc_fds) {
  for (unsigned fd = 0; fd < MIN(NFDBITS, CGC__NFDBITS); ++fd) {
    if (FD_ISSET(fd, os_fds)) {
      CGC_FD_SET(fd, cgc_fds);
    }
  }
}
int cgc_fdwait(int nfds, cgc_fd_set *readfds, cgc_fd_set *writefds,
               const struct cgc_timeval *timeout, int *readyfds) {

  init_memory();

  int ret = check_timeout(timeout);
  int actual_num_fds = 0;
  struct timeval max_wait_time = {0, 0};
  fd_set read_fds;
  fd_set write_fds;

  if (ret) {
    return ret;
  } else if (0 > nfds || CGC__NFDBITS < nfds) {
    return EINVAL;
  }

  FD_ZERO(&read_fds);
  FD_ZERO(&write_fds);

  if (readfds) {
    if (!OBJECT_IS_WRITABLE(readfds)) {  /* Opportunistic. */
      return CGC_EFAULT;
    } else if (0 != (ret = copy_cgc_fd_set(readfds, &read_fds, &actual_num_fds))) {
      return ret;
    }
  }

  if (writefds) {
    if (!OBJECT_IS_WRITABLE(writefds)) {  /* Opportunistic. */
      return CGC_EFAULT;
    } else if (0 != (ret = copy_cgc_fd_set(writefds, &write_fds, &actual_num_fds))) {
      return ret;
    }
  }

  if (actual_num_fds != nfds) {
    return EINVAL;  /* Not actually specified, but oh well. */
  }

  if (readfds)  CGC_FD_ZERO(readfds);
  if (writefds) CGC_FD_ZERO(writefds);

  if (timeout) {
    max_wait_time.tv_sec = timeout->tv_sec;
    max_wait_time.tv_usec = timeout->tv_usec;
  }

  errno = 0;
  int num_selected_fds = select(
          nfds,
          (readfds ? &read_fds : NULL),
          (writefds ? &write_fds : NULL),
          NULL,
          (timeout ? &max_wait_time : NULL));
  const int errno_val = errno;
  errno = 0;

  if (errno_val) {
    if (ENOMEM == errno_val) {
      return CGC_ENOMEM;
    } else if (EBADF == errno_val) {
      return CGC_EBADF;
    } else {
      return CGC_EINVAL;
    }
  }

  if (readfds) {
    copy_os_fd_set(&read_fds, readfds);
  }

  if (writefds) {
    copy_os_fd_set(&write_fds, writefds);
  }

  if (readyfds) {
    if (!OBJECT_IS_WRITABLE(readyfds)) {
      return CGC_EFAULT;
    }
    *readyfds = num_selected_fds;
  }

  return 0;
}

#define PAGE_ALIGN(x) (((x) + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1))

/* Going to ignore `is_executable`. It's not really used in the official CGC
 * challenges, and if it were used, then JITed code would likely be 32-bit, and
 * ideally, this code will also work on 64-bit.
 */
int allocate(cgc_size_t length, int is_executable, void **addr) {
  init_memory();
  if (!length) {
    return CGC_EINVAL;
  }

  length = PAGE_ALIGN(length);  /* Might overflow. */

  void *mmap_addr = mmap(0, length, PROT_READ | PROT_WRITE,
		  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

  const int errno_val = errno;
  errno = 0;

  if (errno_val) {
    if (ENOMEM == CGC_ENOMEM) {
      return CGC_ENOMEM;
    } else {
      return CGC_EINVAL;
    }
  }

  if (addr) {
    *addr = mmap_addr;
  }

  return 0;
}

/* Deallocate some range of memory and mark the pages as free. */
int deallocate(void *addr, cgc_size_t length) {
  init_memory();

  uintptr_t base = (uintptr_t) addr;
  if (!length || base != PAGE_ALIGN(base)) {
    return CGC_EINVAL;
  }

  length = PAGE_ALIGN(length);
  return munmap(addr, length);
}


cgc_prng *cgc_internal_prng = NULL;
/**
 * Initializes the prng for use with cgc_random and the secret page
 */
void try_init_prng() {
    // Don't reinitialize
    if (cgc_internal_prng != NULL) return;

    // This will be hex encoded
    const char *prng_seed_hex = getenv("seed");
    if (prng_seed_hex == NULL || strlen(prng_seed_hex) != (BLOCK_SIZE * 3) * 2) {
        // TODO: Actually make this random
        prng_seed_hex = "736565647365656473656564736565643031323334353637383961626364656600000000000000000000000000000000";
    }

    // Convert the hex encoded seed to a normal string
    const char *pos = prng_seed_hex;
    uint8_t prng_seed[BLOCK_SIZE * 3];
    for(int i = 0; i < BLOCK_SIZE * 3; ++i) {
        sscanf(pos, "%2hhx", &prng_seed[i]);
        pos += 2;
    }

    // Create the prng
    cgc_internal_prng = (cgc_prng *) malloc(sizeof(cgc_prng));
    cgc_aes_state *seed = (cgc_aes_state *) prng_seed;
    cgc_init_prng(cgc_internal_prng, seed);
}

int cgc_random(void *buf, cgc_size_t count, cgc_size_t *rnd_bytes) {
  init_memory();
  if (!count) {
    return update_byte_count(rnd_bytes, 0);
  } else if (count > SSIZE_MAX) {
    return CGC_EINVAL;
  } else if (!(count = num_writable_bytes(buf, count))) {
    return CGC_EFAULT;
  } else {
    // Get random bytes from the prng
    try_init_prng();
    cgc_aes_get_bytes(cgc_internal_prng, count, buf);
    return update_byte_count(rnd_bytes, count);
  }
}

void *cgc_initialize_secret_page(void) {
  init_memory();
  const void * MAGIC_PAGE_ADDRESS = (void *)0x4347C000;
  const size_t MAGIC_PAGE_SIZE = 4096;

  void *mmap_addr = mmap(MAGIC_PAGE_ADDRESS, MAGIC_PAGE_SIZE,
                         PROT_READ | PROT_WRITE,
                         MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS,
                         -1, 0);

  if (mmap_addr != MAGIC_PAGE_ADDRESS) {
    err(1, "[!] Failed to map the secret page");
  }

  // Fill the magic page with bytes from the prng
  try_init_prng();
  cgc_aes_get_bytes(cgc_internal_prng, MAGIC_PAGE_SIZE, mmap_addr);

  return mmap_addr;
}