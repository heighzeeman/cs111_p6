
#include <cstdio>
#include <iostream>

#include <fcntl.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "vm.hh"

const std::size_t page_size = get_page_size();

itree<&VMRegion::base_, &VMRegion::baselink_> VMRegion::regions_;
itree<&VMRegion::Mapping::va_,
      &VMRegion::Mapping::valink_> VMRegion::pagemap_;

VMRegion::Mapping::Mapping(VPage va)
    : va_(va), pi_({nullptr, PROT_NONE})
{
    VMRegion::pagemap_.insert(this);
}

VMRegion::VMRegion(std::size_t num_bytes, std::function<void(char *)> handler)
    : base_(static_cast<VPage>(mmap(nullptr, num_bytes, PROT_NONE,
                                    MAP_ANONYMOUS|MAP_PRIVATE, -1, 0))),
      nbytes_(num_bytes), handler_(std::move(handler))
{
    if (base_ == MAP_FAILED)
        threrror("mmap");
    regions_.insert(this);

    static bool handler_installed;
    if (!handler_installed) {
	handler_installed = true;
	struct sigaction sa;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_SIGINFO;
	sa.sa_sigaction = &fault_handler;
	if (sigaction(SIGSEGV, &sa, nullptr) == -1)
	    threrror("sigaction");
    }
}

VMRegion::~VMRegion()
{
    if (munmap(base_, nbytes_) == -1)
	threrror("mmap");
#ifndef NDEBUG
    if (Mapping *m = pagemap_.lower_bound(base_))
        // If this assertion fails, you tried to delete a region that
        // still had mapped pages.
        assert(m->va_ >= base_ + nbytes_);
#endif // !NDEBUG
}

void
VMRegion::map(VPage va, PPage pa, Prot prot)
{
    assert(std::uintptr_t(va) % page_size == 0);
    Mapping *m = pagemap_[va];
    if (!m)
        m = new Mapping(va);
    update(m, {pa, prot});
}

void
VMRegion::unmap(VPage va)
{
    assert(std::uintptr_t(va) % page_size == 0);
    Mapping *m = pagemap_[va];
    if (m)
        update(m, {nullptr, PROT_NONE});
}

#include <stdio.h>

void
VMRegion::update(Mapping *m, PageInfo pi)
{
    if (pi == m->pi_)
        return;

    if (pi.pa == nullptr) {
        // If you are deleting a mapping, protections need to be none.
        assert(pi.prot == PROT_NONE);
        if (m->pi_.pa) {
            if (mmap(m->va_, page_size, PROT_NONE,
                     MAP_ANONYMOUS|MAP_PRIVATE|MAP_FIXED, -1, 0) == MAP_FAILED)
                threrror("mmap");
            --*refcount(m->pi_.pa);
        }
        delete m;
    }
    else if (pi.pa != m->pi_.pa) {
        PhysMem *pm = PhysMem::find(pi.pa);
        if(mmap(m->va_, page_size, pi.prot, MAP_SHARED|MAP_FIXED,
                pm->fd_, pi.pa - pm->pool_) == MAP_FAILED)
            threrror("mmap");
        ++*refcount(pi.pa);
        if (m->pi_.pa)
            --*refcount(m->pi_.pa);
        m->pi_ = pi;
    }
    else if (pi.prot != m->pi_.prot) {
        if (mprotect(m->va_, page_size, pi.prot) == -1)
            threrror("mprotect");
        m->pi_ = pi;
    }
}

void
VMRegion::fault_handler(int sig, siginfo_t *info, void *ctx)
{
    VPage addr = static_cast<VPage> (info->si_addr);
    VMRegion *r = regions_.upper_bound_prev(addr);
    if (!r || addr >= r->base_ + r->nbytes_) {
	std::fprintf(stderr, "page fault at invalid address %p\n", addr);
	std::abort();
    }
    try {
        r->handler_(addr);
    }
    catch (std::exception &e) {
	// You can't throw C++ exceptions from a signal handler, so
	// abort the process if the page fault handler failed.
	std::cerr << e.what() << std::endl;
	std::abort();
    }
    catch (...) {
	std::cerr << "Non-std::exception thrown from page fault handler\n";
	std::abort();
    }
}

int *
VMRegion::refcount(PPage pa)
{
    int *c = PhysMem::find(pa)->refcount(pa);
    // If this assertion fails, you tried to use a PPage that was
    // either already freed or never allocated.
    assert(*c >= 0);
    return c;
}

namespace {

void
close_on_exec(int fd)
{
    int flags = fcntl(fd, F_GETFD);
    if (fd == -1)
	threrror("F_GETFD");
    if (fcntl(fd, F_SETFD, flags|FD_CLOEXEC) == -1)
	threrror("F_SETFD");
}

void
set_file_size(int fd, off_t size)
{
#if MISSING_POSIX_FALLOCATE
    if (ftruncate(fd, size) == -1)
	threrror("ftruncate");
#else // !MISSING_POSIX_FALLOCATE
    // We prefer to allocate disk space now so as to throw an
    // exception in response to an error.  If we don't call fallocate,
    // then an out-of-disk space or over-quota condition will result
    // in confusing page faults at the time the pages are first
    // accessed (and hence allocated on-demand by the kernel).
    if (int err = posix_fallocate(fd, 0, size)) {
	errno = err;
	threrror("fallocate");
    }
#endif // !MISSING_POSIX_FALLOCATE
}

unique_fd
make_temp_file(off_t size)
{
    char path[] = "/tmp/XXXXXXXXXXXXXX";
    mode_t old_mask = umask(0077);
    unique_fd fd (mkstemp(path));
    umask(old_mask);
    if (fd == -1)
	threrror(path);
    unlink(path);
    close_on_exec(fd);
    set_file_size(fd, size);
    return fd;
}

std::size_t
cache_size(int npages)
{
    const std::ptrdiff_t max_pageno =
        std::numeric_limits<std::ptrdiff_t>::max() / get_page_size();

    if (npages < 0 || npages >= max_pageno)
	throw std::domain_error("PhysMem: invalid number of pages requested");
    return std::size_t(npages) * get_page_size();
}

char *
map_temp_file(int fd, std::size_t size)
{
    set_file_size(fd, size);
    void *ret = mmap(nullptr, size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    if (ret == MAP_FAILED)
	threrror("mmap");

    // We don't want the contents of this file (which is our
    // "pseudo-physical memory") to be paged out to disk for two
    // reasons.  First, since we are already managing it as a cache,
    // this double caching will yield terrible performance--better to
    // reduce the size of the cache than to have non-resident pages in
    // the cache.  Second, since the pages contain potentially
    // sensitive plaintext of encrypted files, you don't want these to
    // be written back to the underlying file system or swap partition
    // where they could be extracted by forensic analysis.
    //
    // To be polite, however, we don't try to lock more than 1 MiB of
    // memory.  Furthermore, depending on system configuration, mlock
    // could fail when you are not root.  Hence, we ignore any error.
    // (If mlock succeeds, the memory will automatically be unlocked
    // later by munmap, so we don't really care if it succeeded or
    // not.)
    if (size <= 0x10'0000)
	mlock(ret, size);

    return static_cast<char *>(ret);
}

} // anonoymous namespace

PhysMem::PhysMem(std::size_t npages)
    : npages_(npages),
      size_(cache_size(npages)),
      fd_(make_temp_file(size_)),
      pool_(map_temp_file(fd_, size_)),
      nfree_(npages),
      free_pages_(nullptr),
      refcounts_(npages, -1)
{
    pools().insert(this);
    for (char *p = pool_ + size_; p != pool_;) {
	p -= get_page_size();
	FreePage *fp = FreePage::construct(p);
	fp->next_ = free_pages_;
	free_pages_ = fp;
    }
}

PhysMem::~PhysMem()
{
    assert(nfree_ == npages_);
    munmap(pool_, size_);
}

PPage
PhysMem::page_alloc()
{
    // Get the next free page, or return nullptr if none are left.
    FreePage *fp = free_pages_;
    if (!fp)
	return nullptr;
    free_pages_ = fp->next_;
    PPage p = fp->destroy();
    --nfree_;
    int *c = refcount(p);
    assert(*c == -1);
    *c = 0;
    return p;
}

void
PhysMem::page_free(PPage p)
{
    assert(std::uintptr_t(p)%page_size == 0);

    int *c = refcount(p);
    // If this assertion fails, the page was already free or the page
    // was still mapped at one or more VAddrs.
    assert(*c == 0);
    *c = -1;

    FreePage *fp = FreePage::construct(p);
    fp->next_ = free_pages_;
    free_pages_ = fp;
    ++nfree_;
}
