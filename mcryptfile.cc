#include "mcryptfile.hh"
#include "vm.hh"

// Initialize some static MCryptFile variables
std::size_t MCryptFile::phys_npages = 1000;
ilist<&PagedVRegion::PTE::list_link> MCryptFile::currentPTEs;
// Doesn't allocate, simply initializes MCryptFile::pm so PagedVRegion can access it
PhysMem *MCryptFile::pm = nullptr;

PagedVRegion::PTE::PTE(VPage vp0, Prot p, VPage vr)
  : vp(vp0), pp(MCryptFile::pm->page_alloc()), vr(vr)
{
    if (!pp) throw std::runtime_error("Not enough PhysMem pages.");
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
		if (!pm->nfree()) {
			static PagedVRegion::PTE *curr = currentPTEs.front();
			while (true) {
				curr = curr ? curr : currentPTEs.front();
				if (!curr) throw std::runtime_error("No page table entries.");
				if (!curr->accessed) {
					if (curr->dirty) {
						curr->protect(PROT_READ | PROT_WRITE);
						VPage oldvp = curr->vp;
						std::size_t offset = static_cast<std::size_t>(std::uintptr_t(oldvp - curr->vr));
					
						MCryptFile::aligned_pwrite(oldvp, get_page_size(), offset);
					}
					PagedVRegion::PTE *to_delete = curr;
					curr = currentPTEs.next(curr);
					delete to_delete;
					break;
				} else {
					curr->clear_accessed();
					curr = currentPTEs.next(curr);
				}
			}
		}
		pte = new PagedVRegion::PTE(vp, PROT_READ | PROT_WRITE, pvreg->get_base());
		
		currentPTEs.push_back(pte);
		pvreg->pt.insert(pte);
		std::size_t offset = static_cast<std::size_t>(std::uintptr_t(vp - pte->vr));
		aligned_pread(vp, get_page_size(), offset);
		pte->clear_accessed();
		pte->dirty = false;
	}
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
	if (!pvreg) throw std::runtime_error("Unable to create VMRegion.");
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
	itree<&PagedVRegion::PTE::vp, &PagedVRegion::PTE::tree_link>& pt = pvreg->pt;
    PagedVRegion::PTE *cpte = pt.lower_bound(pvreg->get_base());
    PagedVRegion::PTE *end = pt.upper_bound(pvreg->get_base() + pvreg->size());
    while (cpte != end) {
        if (cpte->dirty) {
			cpte->protect(PROT_READ | PROT_WRITE);
			VPage vp = cpte->vp;
			std::size_t offset = static_cast<std::size_t>(std::uintptr_t(vp - cpte->vr));
			aligned_pwrite(vp, get_page_size(), offset);
			cpte->dirty = false;
			cpte->protect(PROT_READ);
		}
		cpte = pt.next(cpte);
    }
}

void
MCryptFile::set_memory_size(std::size_t npages)
{
    phys_npages = npages;
}
