
#pragma once

#include <optional>

#include "cryptfile.hh"


// Mostly based on the provided TraceRegion and AuxPTE in section
// Credit: David Mazieres
struct PagedVRegion {
	struct PTE {
		const VPage vp;
		const PPage pp;
		Prot prot;
		bool accessed = false;
		bool dirty = false;
		itree_entry link;


		PTE(VPage vp0, Prot p);
		~PTE();
		void protect(Prot p);
		void clear_accessed() { accessed = false; protect(PROT_NONE); }
	};
	
    VMRegion vmem;
	itree<&PTE::vp, &PTE::link> pt;

    PagedVRegion(std::size_t nbytes, std::function<void(char *)> hdlr)
     : vmem(nbytes, [hdlr](char *a){ hdlr(a); }), pt(), handler(hdlr) {}
    ~PagedVRegion();

    std::function<void(char *)> handler;
	char *get_base() { return vmem.get_base(); }
	std::size_t size() { return vmem.nbytes_; }

    char &operator[](std::ptrdiff_t i) {
        assert(i >= 0 && std::size_t(i) < vmem.nbytes_);
		return vmem.get_base()[i];
    }
};


// An MCryptFile is a CryptFile that supports one additional feature.
// In addition to the base functionality of reading and writing data,
// you can also memory-map the file--just like the mmap system call,
// except that pages are decrypted on the way in and encrypted when
// written back out.
struct MCryptFile : public CryptFile {
    // Opens file path using encryption key key.  Throws a
    // std::system_error if the file cannot be opened.
    MCryptFile(Key key, std::string path);
    ~MCryptFile();

    // Create a region that memory-maps the decrypted contents of the
    // file and return the address of the first byte of the region.  If you
    // want to grow the file, you can supply a min_size > 0, and the
    // mapped region will be the larger of min_size and the file's actual
    // size.  If you want to grow a file after it has already been mapped,
    // unmap() and then re-map() it, which will likely move map_base() and
    // invalidate any old pointers into the previous mapped region.
    char *map(std::size_t min_size = 0);

    // Remove the mapping created by map, invalidating all pointers.
    void unmap();

    // Address of the first byte of the memory mapped file.  It is an
    // error to call this if before calling map() or after calling
    // unmap().
    char *map_base() {
        if (pvreg == nullptr) throw std::runtime_error("MCryptFile is not currently mapped.");
        return pvreg->get_base();
    }

    // Size of mapped file (once map() has been called)
    std::size_t map_size() {
        if (pvreg == nullptr) throw std::runtime_error("MCryptFile is not currently mapped.");
        return pvreg->size();
    }

    // Flush all changes back to the encrypted file; pages currently
    // in memory remain there.
    void flush();
    
    // Specifies size of the physical memory pool shared by all
    // MCryptFile objects. Must be invoked before any MCryptFile
    // objects have been created; later indications will have no effect.
    static void set_memory_size(std::size_t npages);
	
	friend PagedVRegion;
private:
	static PhysMem *pm;	  // Pointer to a PhysMem object created statically on the first use of map
	static std::size_t phys_npages;
	static bool not_allocated;
	
    PagedVRegion *pvreg;
	void VMhandler(char *va);
};


