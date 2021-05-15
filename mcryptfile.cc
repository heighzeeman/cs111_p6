#include "mcryptfile.hh"
#include "vm.hh"

// Initialize some static MCryptFile variables
std::size_t MCryptFile::phys_npages = 1000;
// Doesn't allocate, simply initializes MCryptFile::pm so PagedVRegion can access it
PhysMem *MCryptFile::pm = nullptr;

PagedVRegion::PTE::PTE(VPage vp0, Prot p)
  : vp(vp0), pp(MCryptFile::pm->page_alloc())
{
    if (!pp) throw std::runtime_error("Out of PhysMem pages");
    protect(p);
}

PagedVRegion::PTE::~PTE()
{
    VMRegion::unmap(vp);
    MCryptFile::pm->page_free(pp);
}

void
PagedVRegion::PTE::protect(Prot p)
{
    prot = p;
    VMRegion::map(vp, pp, prot);
    if (prot & PROT_READ) accessed = true;
    if (prot & PROT_WRITE) dirty = true;
}


PagedVRegion::~PagedVRegion()
{
    PTE *lpte = pt.lower_bound(get_base());
    PTE *end = pt.upper_bound(get_base() + size());
    while (lpte != end) {
        PTE *to_delete = lpte;
        lpte = pt.next(lpte);
		delete to_delete;
    }
}


void MCryptFile::VMhandler(char *va) {
	VPage vp = va - std::uintptr_t(va) % get_page_size();
	PagedVRegion::PTE *pte = pvreg->pt[vp];
	if (!pte) {
		pte = new PagedVRegion::PTE(vp, PROT_READ | PROT_WRITE);
		pvreg->pt.insert(pte);
		std::size_t offset = static_cast<std::size_t>(std::uintptr_t(vp - pvreg->get_base()));
		aligned_pread(vp, get_page_size(), offset);
	}
	pte->clear_accessed();
	Prot prot = PROT_READ;
	if (pte->accessed || pte->dirty) prot |= PROT_WRITE;
	pte->protect(prot);
}


MCryptFile::MCryptFile(Key key, std::string path)
    : CryptFile(key, path), pvreg(nullptr)
{
    // Empty initializer
}

MCryptFile::~MCryptFile()
{
    unmap();
}


char *
MCryptFile::map(size_t min_size)
{	
	// Allocates PhysMem on first use of map. If statement not necessary but for ideological flow.
	if (!pm) {
		static PhysMem p(phys_npages);
		pm = &p;
	}
	while (pvreg != nullptr) unmap();	// Same thing as an if here. If currently mapped, unmap.
    pvreg = new PagedVRegion(std::max(min_size, file_size()), [this](char *a){ VMhandler(a); });
    return pvreg->get_base();
}

void
MCryptFile::unmap()
{
    flush();
	delete pvreg;
	pvreg = nullptr;
}


void
MCryptFile::flush()
{
	itree<&PagedVRegion::PTE::vp, &PagedVRegion::PTE::link>& pt = pvreg->pt;
    PagedVRegion::PTE *cpte = pt.lower_bound(pvreg->get_base());
    PagedVRegion::PTE *end = pt.upper_bound(pvreg->get_base() + pvreg->size());
    while (cpte != end) {
        if (cpte->dirty) {
			VPage vp = cpte->vp;
			std::size_t offset = static_cast<std::size_t>(std::uintptr_t(vp - pvreg->get_base()));
			aligned_pwrite(vp, get_page_size(), offset);
		}
		cpte = pt.next(cpte);
    }
}

void
MCryptFile::set_memory_size(std::size_t npages)
{
    phys_npages = npages;
}
