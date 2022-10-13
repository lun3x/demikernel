// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// This DemiBuffer type is designed to be a common abstraction defining the behavior of data buffers in Demikernel.
// It currently supports two underlying types of buffers: heap-allocated and DPDK-allocated.  The basic operations on
// DemiBuffers are designed to have equivalent behavior (effects on the data), regardless of the underlying buffer type.
// In particular, len(), adjust(), trim(), clone(), and split() are present and designed to behave the same regardless.
//
// The constructors/destructors, however, are necessarily different.  For DPDK-allocated buffers, a MBuf is expected
// to be allocated externally and provided to the DemiBuffer's "from_mbuf" constructor.  A MBuf can also be extracted
// from a DPDK allocated DemiBuffer via the "into_mbuf" routine.
//
// Note: if compiled without the "libdpdk" feature defined, the DPDK-specific functionality won't be present.

// Note on buffer chain support:
// DPDK has a concept of MBuf chaining where multiple MBufs may be linked together to form a "packet".  While the
// DemiBuffer routines for heap-allocated buffers also now support this functionality, it isn't yet exposed via the
// DemiBuffer interface.
// ToDo: Expose buffer chain support once we have a solid use case.

// Note on intrusive queueing:
// Since all DemiBuffer types keep the metadata for each "view" in a separate allocated region, they can be queued
// using intrusive links (i.e. have a link field in the metadata).
// ToDo: Expose calls to get/set a linking field.

// Note on the allocation functions:
// This code currently uses std::alloc() and std::dealloc() to allocate/free things from the heap.  Note that the Rust
// documentation says that these functions are expected to be deprecated in favor of their respective methods of the
// "Global" type when it and the "Allocator" trait become stable.
use crate::runtime::fail::Fail;
#[cfg(feature = "libdpdk")]
use ::dpdk_rs::{
    rte_mbuf,
    rte_mempool,
    rte_pktmbuf_adj,
    rte_pktmbuf_clone,
    rte_pktmbuf_free,
    rte_pktmbuf_trim,
};
#[cfg(feature = "libdpdk")]
use ::std::mem;
use ::std::{
    alloc::{
        alloc,
        dealloc,
        handle_alloc_error,
        Layout,
    },
    marker::PhantomData,
    mem::size_of,
    num::NonZeroUsize,
    ops::{
        Deref,
        DerefMut,
    },
    ptr::{
        self,
        null_mut,
        NonNull,
    },
    slice,
};

// Cache line size, defined here for code clarity.
// While this is arguably architecture dependent, and thus should be pulled from some architecture-specific information,
// this value (64 bytes) is used by all architectures we're likely to care about (and is also assumed by DPDK).
const CACHE_LINE_SIZE: usize = 64;

// Buffer Metadata.
// This is defined to match a DPDK MBuf (rte_mbuf) in order to potentially use the same code for some DemiBuffer
// operations that currently use identical (but separate) implementations for heap vs DPDK allocated buffers.
// Fields beginning with an underscore are not directly used by the current DemiBuffer implementation.
// Should be cache-line aligned and consume 2 cache lines (128 bytes).
#[repr(C)]
#[repr(align(64))]
struct MetaData {
    // Virtual address of the start of the actual data.
    buf_addr: *mut u8,

    // Physical address of the buffer.
    _buf_iova: u64,

    // Data offset.
    data_off: u16,
    // Reference counter.
    refcnt: u16,
    // Number of segments in this buffer chain (only valid in first segment's MetaData).
    nb_segs: u16,
    // Input port.
    _port: u16,

    // Offload features.
    // Note, despite the "offload" name, the indirect buffer flag (METADATA_F_INDIRECT) lives here.
    ol_flags: u64,

    // L2/L3/L4 and tunnel information.
    _packet_type: u32,
    // Total packet data length (sum of all segments' data_len).
    pkt_len: u32,

    // Amount of data in this segment buffer.
    data_len: u16,
    // VLAN TCI.
    _vlan_tci: u16,
    // Potentially used for various things, including RSS hash.
    _various1: u32,

    // Potentially used for various things, including RSS hash.
    _various2: u32,
    _vlan_tci_outer: u16,
    // Allocated length of the buffer that buf_addr points to.
    buf_len: u16,

    // Pointer to memory pool (rte_mempool) from which mbuf was allocated.
    _pool: u64,

    // Second cache line (64 bytes) begins here.

    // Pointer to the MetaData of the next segment in this packet's chain (must be NULL in last segment).
    next: Option<NonNull<MetaData>>,

    // Various fields for TX offload.
    _tx_offload: u64,

    // Pointer to shared info (rte_mbuf_ext_shared_info).  DPDK uses this for external MBufs.
    _shinfo: u64,

    // Size of private data (between rte_mbuf struct and the data) in direct MBufs.
    _priv_size: u16,
    // Timesync flags for use with IEEE 1588 "Precision Time Protocol" (PTP).
    _timesync: u16,
    // Reserved for dynamic fields.
    _dynfield: [u32; 9],
}

// MetaData "offload flags".  These exactly mimic those of DPDK MBufs.

// Indicates this MetaData struct doesn't have the actual data directly attached, but rather this MetaData's buf_addr
// points to another MetaData's directly attached data.
const METADATA_F_INDIRECT: u64 = 1 << 62;

impl MetaData {
    // Note on Reference Counts:
    // Since we are currently single-threaded, there is no need to use atomic operations for refcnt manipulations.
    // We should rework the implementation of inc_refcnt() and dec_refcnt() to use atomic operations if this changes.
    // Also, we intentionally don't check for refcnt overflow.  This matches DPDK's behavior, which doesn't check for
    // reference count overflow either (we're highly unlikely to ever have 2^16 copies of the same data).

    // Increments the reference count and returns the new value.
    #[inline]
    pub fn inc_refcnt(&mut self) -> u16 {
        self.refcnt += 1;
        self.refcnt
    }

    // Decrements the reference count and returns the new value.
    #[inline]
    pub fn dec_refcnt(&mut self) -> u16 {
        self.refcnt -= 1;
        self.refcnt
    }

    // Gets the MetaData for the last segment in the buffer chain.
    #[inline]
    pub fn get_last_segment(&mut self) -> &mut MetaData {
        let mut md: &mut MetaData = self;
        while md.next.is_some() {
            // Safety: The call to as_mut is safe, as the pointer is aligned and dereferenceable, and the MetaData
            // struct it points to is initialized properly.
            md = unsafe { md.next.unwrap().as_mut() };
        }
        &mut *md
    }
}

// The DemiBuffer.
pub struct DemiBuffer {
    // Pointer to the buffer metadata.
    // Stored as a NonNull so it can efficiently be packed into an Option.
    // This is a "tagged pointer" where the lower bits encode the type of buffer this points to.
    ptr: NonNull<MetaData>,
    // Hint to compiler that this struct "owns" a MetaData (for safety determinations).  Doesn't consume space.
    _phantom: PhantomData<MetaData>,
}

// DemiBuffer tag types.
// Since our MetaData structure is 64-byte aligned, the lower 6 bits of a pointer to it are guaranteed to be zero.
// We currently only use the lower 2 of those bits to hold the tag.
const TAG_MASK: usize = 0x3;
const TAG_HEAP: usize = 0x1;
const TAG_DPDK: usize = 0x2;

impl DemiBuffer {
    // ------------
    // Constructors
    // ------------

    // Create a new (Heap-allocated) DemiBuffer.
    //
    // Implementation Note:
    // This function is replacing the new() function of DataBuffer, which could return failure.  However, the only
    // failure it actually reported was if the new DataBuffer request was for zero size.  A seperate empty() function
    // was provided to allocate zero-size buffers.  This new implementation does not have a special case for this,
    // instead, zero is a valid argument to new().  So we no longer need the failure return case of this function.
    //
    // Of course, allocations can fail.  Most of the allocating functions in Rust's standard library expect allocations
    // to be infallible, including "Arc" (which was used as the allocator in DataBuffer::new()).  None of these can
    // return an error condition.  But since we call the allocator directly in this implementation, we could now
    // propagate actual allocation failures outward, if we determine that would be helpful.  For now, we stick to the
    // status quo, and assume this allocation never fails.
    //
    pub fn new(capacity: u16) -> Self {
        // Allocate some memory off the heap.
        let mut temp: NonNull<MetaData> = allocate_metadata_data(capacity);

        // Initialize the MetaData.
        {
            // Safety: This is safe, as temp is aligned, dereferenceable, and metadata isn't aliased in this block.
            let metadata: &mut MetaData = unsafe { temp.as_mut() };

            // Point buf_addr at the newly allocated data space (if any).
            if capacity == 0 {
                // No direct data, so don't point buf_addr at anything.
                metadata.buf_addr = null_mut();
            } else {
                // The direct data immediately follows the MetaData struct.
                let address: *mut u8 = temp.cast::<u8>().as_ptr();
                // Safety: The call to offset is safe, as the provided offset is known to be within the allocation.
                metadata.buf_addr = unsafe { address.offset(size_of::<MetaData>() as isize) };
            }

            // Set field values as appropriate.
            metadata.data_off = 0;
            metadata.refcnt = 1;
            metadata.nb_segs = 1;
            metadata.ol_flags = 0;
            metadata.pkt_len = capacity as u32;
            metadata.data_len = capacity;
            metadata.buf_len = capacity;
            metadata.next = None;
        }

        // Embed the buffer type into the lower bits of the pointer.
        let tagged: NonNull<MetaData> = temp.with_addr(temp.addr() | TAG_HEAP);

        // Return the new DemiBuffer.
        DemiBuffer {
            ptr: tagged,
            _phantom: PhantomData,
        }
    }

    // Create a new Heap-allocated DemiBuffer from a slice.
    // Note: This is implemented as stand-alone function instead of a conversion (From) Trait in order to be able to
    // handle the error case where the given slice is larger than a single DemiBuffer can hold.  ToDo: Review this?
    pub fn from_slice(slice: &[u8]) -> Result<Self, Fail> {
        // Check size of the slice to ensure a single DemiBuffer can hold it.
        if slice.len() > u16::MAX as usize {
            return Err(Fail::new(libc::EINVAL, "slice is larger than a DemiBuffer can hold"));
        }
        let amount: u16 = slice.len() as u16;

        // Allocate some memory off the heap.
        let mut temp: NonNull<MetaData> = allocate_metadata_data(amount);

        // Initialize the MetaData.
        {
            // Safety: This is safe, as temp is aligned, dereferenceable, and metadata isn't aliased in this block.
            let metadata: &mut MetaData = unsafe { temp.as_mut() };

            // Point buf_addr at the newly allocated data space (if any).
            if amount == 0 {
                // No direct data, so don't point buf_addr at anything.
                metadata.buf_addr = null_mut();
            } else {
                // The direct data immediately follows the MetaData struct.
                let address: *mut u8 = temp.cast::<u8>().as_ptr();
                // Safety: The call to offset is safe, as the provided offset is known to be within the allocation.
                metadata.buf_addr = unsafe { address.offset(size_of::<MetaData>() as isize) };

                // Copy the data from the slice into the DemiBuffer.
                // Safety: This is safe, as the src/dst argument pointers are valid for reads/writes of `amount` bytes,
                // are aligned (trivial for u8 pointers), and the regions they specify do not overlap one another.
                unsafe { ptr::copy_nonoverlapping(slice.as_ptr(), metadata.buf_addr, amount as usize) };
            }

            // Set field values as appropriate.
            metadata.data_off = 0;
            metadata.refcnt = 1;
            metadata.nb_segs = 1;
            metadata.ol_flags = 0;
            metadata.pkt_len = amount as u32;
            metadata.data_len = amount;
            metadata.buf_len = amount;
            metadata.next = None;
        }

        // Embed the buffer type into the lower bits of the pointer.
        let tagged: NonNull<MetaData> = temp.with_addr(temp.addr() | TAG_HEAP);

        // Return the new DemiBuffer.
        Ok(DemiBuffer {
            ptr: tagged,
            _phantom: PhantomData,
        })
    }

    #[cfg(feature = "libdpdk")]
    // Creates a DemiBuffer from a raw MBuf pointer (*mut rte_mbuf).
    // The MBuf's internal reference count is left unchanged (a reference is effectively donated to the DemiBuffer).
    // Note: Must be called with a non-null (i.e. actual) MBuf pointer.  The MBuf is expected to be in a valid state.
    // It is the caller's responsibility to guarantee this, which is why this function is marked "unsafe".
    pub unsafe fn from_mbuf(mbuf_ptr: *mut rte_mbuf) -> Self {
        // Convert the raw pointer into a NonNull and add a tag indicating it is a DPDK buffer (i.e. a MBuf).
        let temp: NonNull<MetaData> = NonNull::new_unchecked(mbuf_ptr as *mut _);
        let tagged: NonNull<MetaData> = temp.with_addr(temp.addr() | TAG_DPDK);

        DemiBuffer {
            ptr: tagged,
            _phantom: PhantomData,
        }
    }

    // ----------------
    // Public Functions
    // ----------------

    pub fn is_heap_allocated(&self) -> bool {
        self.get_tag() == TAG_HEAP
    }

    pub fn is_dpdk_allocated(&self) -> bool {
        self.get_tag() == TAG_DPDK
    }

    // Returns the length of the data stored in the DemiBuffer.
    // Note that while we return a usize here (for convenience), the value is guaranteed to never exceed u16::MAX.
    pub fn len(&self) -> usize {
        self.get_metadata().data_len as usize
    }

    // Removes `nbytes` bytes from the beginning of the DemiBuffer chain.
    // Note: If `nbytes` is greater than the length of the first segment in the chain, then this function will fail and
    // return an error, rather than remove the remaining bytes from subsequent segments in the chain.  This is to match
    // the behavior of DPDK's rte_pktmbuf_adj() routine.
    pub fn adjust(&mut self, nbytes: u16) -> Result<(), Fail> {
        // ToDo: Review having this "match", since MetaData and MBuf are laid out the same, these are equivalent cases.
        match self.get_tag() {
            TAG_HEAP => {
                let metadata: &mut MetaData = self.get_metadata();
                if nbytes > metadata.data_len {
                    return Err(Fail::new(libc::EINVAL, "tried to remove more bytes than are present"));
                }
                metadata.data_off += nbytes;
                metadata.pkt_len -= nbytes as u32;
                metadata.data_len -= nbytes;
            },
            #[cfg(feature = "libdpdk")]
            TAG_DPDK => {
                // Safety: rte_pktmbuf_adj is a FFI, which is safe since we call it with an actual MBuf pointer.
                if unsafe { rte_pktmbuf_adj(self.get_mbuf(), nbytes) } == ptr::null_mut() {
                    return Err(Fail::new(libc::EINVAL, "tried to remove more bytes than are present"));
                }
            },
            _ => {
                panic!("corrupted DemiBuffer");
            },
        }

        Ok(())
    }

    // Removes `nbytes` bytes from the end of the DemiBuffer chain.
    // Note: If `nbytes` is greater than the length of the last segment in the chain, then this function will fail and
    // return an error, rather than remove the remaining bytes from subsequent segments in the chain.  This is to match
    // the behavior of DPDK's rte_pktmbuf_trim() routine.
    pub fn trim(&mut self, nbytes: u16) -> Result<(), Fail> {
        // ToDo: Review having this "match", since MetaData and MBuf are laid out the same, these are equivalent cases.
        match self.get_tag() {
            TAG_HEAP => {
                let md_first: &mut MetaData = self.get_metadata();
                let md_last: &mut MetaData = md_first.get_last_segment();

                if nbytes > md_last.data_len {
                    return Err(Fail::new(libc::EINVAL, "tried to remove more bytes than are present"));
                }
                md_last.data_len -= nbytes;
                md_first.pkt_len -= nbytes as u32;
            },
            #[cfg(feature = "libdpdk")]
            TAG_DPDK => {
                // Safety: rte_pktmbuf_trim is a FFI, which is safe since we call it with an actual MBuf pointer.
                if unsafe { rte_pktmbuf_trim(self.get_mbuf(), nbytes) } != 0 {
                    return Err(Fail::new(libc::EINVAL, "tried to remove more bytes than are present"));
                }
            },
            _ => {
                panic!("corrupted DemiBuffer");
            },
        }

        Ok(())
    }

    // Splits off a new DemiBuffer containing a subset of the data in this DemiBuffer, starting at the given offset.
    // The data contained in the new DemiBuffer is removed from the original DemiBuffer.
    // Note: the DemiBuffer being split must be a single buffer segment (not a chain) large enough to hold `offset`.
    pub fn split(&mut self, offset: u16) -> Result<Self, Fail> {
        // Check that a split is allowed.
        match self.get_tag() {
            TAG_HEAP => {
                let md_front: &mut MetaData = self.get_metadata();
                if md_front.nb_segs != 1 {
                    return Err(Fail::new(libc::EINVAL, "attempted to split multi-segment DemiBuffer"));
                }
                if md_front.data_len < offset {
                    return Err(Fail::new(libc::EINVAL, "split offset is more bytes than are present"));
                }
            },
            #[cfg(feature = "libdpdk")]
            TAG_DPDK => {
                let mbuf: *mut rte_mbuf = self.get_mbuf();
                // Safety: The `mbuf` dereferences in this block are safe, as it is aligned and dereferenceable.
                unsafe {
                    if (*mbuf).nb_segs != 1 {
                        return Err(Fail::new(libc::EINVAL, "attempted to split multi-segment DemiBuffer"));
                    }
                    if (*mbuf).data_len < offset {
                        return Err(Fail::new(libc::EINVAL, "split offset is more bytes than are present"));
                    }
                }
            },
            _ => {
                panic!("corrupted DemiBuffer");
            },
        }

        // Clone ourselves.
        let mut back_half: DemiBuffer = self.clone();

        // Remove data starting at `offset` from the front (original) DemiBuffer as those bytes now belong to the back.
        let trim: u16 = self.len() as u16 - offset;
        // This unwrap won't panic as we already performed its error checking above.
        self.trim(trim).unwrap();

        // Remove `offset` bytes from the beginning of the back (clone) DemiBuffer as they now belong to the front.
        // This unwrap won't panic as we already performed its error checking above.
        back_half.adjust(offset).unwrap();

        // Return the back DemiBuffer.
        Ok(back_half)
    }

    // Consumes the DemiBuffer, returning the contained MBuf pointer.
    // The returned MBuf takes all existing references on the data with it (the DemiBuffer donates its ref to the MBuf).
    #[cfg(feature = "libdpdk")]
    pub fn into_mbuf(this: Self) -> Option<*mut rte_mbuf> {
        if this.get_tag() == TAG_DPDK {
            let mbuf = Self::get_mbuf(&this);
            // Don't run the DemiBuffer destructor on this.
            mem::forget(this);
            Some(mbuf)
        } else {
            None
        }
    }

    // ------------------
    // Internal Functions
    // ------------------

    // Gets the tag containing the type of DemiBuffer.
    #[inline]
    fn get_tag(&self) -> usize {
        usize::from(self.ptr.addr()) & TAG_MASK
    }

    // Gets the untagged pointer to the underlying type.
    #[inline]
    fn get_ptr<U>(&self) -> NonNull<U> {
        // Safety: The call to NonZeroUsize::new_unchecked is safe, as its argument is guaranteed to be non-zero.
        let address: NonZeroUsize = unsafe { NonZeroUsize::new_unchecked(usize::from(self.ptr.addr()) & !TAG_MASK) };
        self.ptr.with_addr(address).cast::<U>()
    }

    // Gets the DemiBuffer as a mutable MetaData reference.
    // Note: Caller is responsible for enforcing Rust's aliasing rules for the returned MetaData reference.
    fn get_metadata(&self) -> &mut MetaData {
        // Safety: The call to as_mut is safe, as the pointer is aligned and dereferenceable, and the MetaData struct
        // it points to is initialized properly.
        unsafe { self.get_ptr::<MetaData>().as_mut() }
    }

    // Gets the DemiBuffer as a mutable MBuf pointer.
    #[cfg(feature = "libdpdk")]
    fn get_mbuf(&self) -> *mut rte_mbuf {
        self.get_ptr::<rte_mbuf>().as_ptr()
    }

    // Gets a raw pointer to the DemiBuffer data.
    fn data_ptr(&self) -> *mut u8 {
        let metadata: &mut MetaData = self.get_metadata();
        let buf_ptr: *mut u8 = metadata.buf_addr;
        // Safety: The call to offset is safe, as its argument is known to remain within the allocated region.
        unsafe { buf_ptr.offset(metadata.data_off as isize) }
    }

    // Gets a raw pointer to the DemiBuffer data (DPDK type specific).
    // Note: Since our MetaData and DPDK's rte_mbuf have equivalent layouts for the buf_addr and data_off fields, this
    // function isn't strictly necessary, as it does the exact same thing as data_ptr() does.
    #[cfg(feature = "libdpdk")]
    fn dpdk_data_ptr(&self) -> *mut u8 {
        let mbuf: *mut rte_mbuf = self.get_mbuf();
        unsafe {
            // Safety: It is safe to dereference "mbuf" as it is known to be valid.
            let buf_ptr: *mut u8 = (*mbuf).buf_addr as *mut u8;
            // Safety: The call to offset is safe, as its argument is known to remain within the allocated region.
            buf_ptr.offset((*mbuf).data_off as isize)
        }
    }
}

// ----------------
// Helper Functions
// ----------------

// Allocates the MetaData (plus the space for any directly attached data) for a new heap-allocated DemiBuffer.
fn allocate_metadata_data(direct_data_size: u16) -> NonNull<MetaData> {
    // Since our MetaData structure is defined to mimic a DPDK MBuf, it should be two cache-lines in size (checked
    // here in debug builds) and cache-line aligned.
    // ToDo: When Rust adds proper compile-time assertions, switch this to one.
    #[cfg(debug_assertions)]
    if size_of::<MetaData>() != 2 * CACHE_LINE_SIZE {
        panic!("MetaData structure is not the expected size");
    }

    // Allocate space for the MetaData struct, plus any extra memory for directly attached data.

    let amount: usize = size_of::<MetaData>() + direct_data_size as usize;

    // Given our limited allocation amount (u16::MAX) and fixed alignment size, this unwrap cannot panic.
    let layout: Layout = Layout::from_size_align(amount, CACHE_LINE_SIZE).unwrap();

    // Safety: This is safe, as we check for a null return value before dereferencing "allocation".
    let allocation: *mut u8 = unsafe { alloc(layout) };
    if allocation.is_null() {
        handle_alloc_error(layout);
    }

    let metadata: *mut MetaData = allocation.cast::<MetaData>();

    // Initialize select MetaData fields in debug builds for sanity checking.
    // We check in debug builds that they aren't accidentally messed with.
    // Safety: The `metadata` dereferences in this block are safe, as it is known to be aligned and dereferenceable.
    #[cfg(debug_assertions)]
    unsafe {
        // This field should only be non-null for DPDK-allocated DemiBuffers.
        (*metadata)._pool = 0;

        // We don't currently use a "private data" feature akin to DPDK's.
        (*metadata)._priv_size = 0;
    }

    // Convert to NonNull<MetaData> type and return.
    // Safety: The call to NonNull::new_unchecked is safe, as `allocation` is known to be non-null.
    unsafe { NonNull::new_unchecked(metadata) }
}

// Frees the MetaData (plus the space for any directly attached data) for a heap-allocated DemiBuffer.
fn free_metadata_data(buffer: NonNull<MetaData>) {
    // Safety: This is safe, as `buffer` is aligned, dereferenceable, and we don't let `metadata` escape this function.
    let metadata: &MetaData = unsafe { buffer.as_ref() };

    // Check in debug builds that we weren't accidentally passed a DPDK-allocated MBuf to free.
    debug_assert_eq!(metadata._pool, 0);

    // Determine the size of the original allocation.
    // Note that this code currently assumes we're not using a "private data" feature akin to DPDK's.
    debug_assert_eq!(metadata._priv_size, 0);
    let amount: usize = size_of::<MetaData>() + metadata.buf_len as usize;
    // This unwrap will never panic, as we pass a known allocation amount and a fixed alignment to from_size_align().
    let layout: Layout = Layout::from_size_align(amount, CACHE_LINE_SIZE).unwrap();

    // Convert buffer pointer into a raw allocation pointer.
    let allocation: *mut u8 = buffer.cast::<u8>().as_ptr();

    // Safety: this is safe because we're using the same (de)allocator and Layout used for allocation.
    unsafe { dealloc(allocation, layout) };
}

// ---------------------
// Trait Implementations
// ---------------------

// Clone Trait Implementation for DemiBuffer
impl Clone for DemiBuffer {
    fn clone(&self) -> Self {
        match self.get_tag() {
            TAG_HEAP => {
                // To create a clone (not a copy), we construct a new indirect buffer for each buffer segment in the
                // original buffer chain.  An indirect buffer has its own MetaData struct representing its view into
                // the data, but the data itself resides in the original direct buffer and isn't copied.  Instead,
                // we increment the reference count on that data.

                // Allocate space for a new MetaData struct without any direct data.  This will become the clone.
                let head: NonNull<MetaData> = allocate_metadata_data(0);
                let mut temp = head;

                // This might be a chain of buffers.  If so, we'll walk the list.  There is always a first one.
                let mut next_entry: Option<NonNull<MetaData>> = Some(self.get_ptr::<MetaData>());
                while let Some(mut entry) = next_entry {
                    // Safety: This is safe, as `entry` is aligned, dereferenceable, and the MetaData struct it points
                    // to is initialized.
                    let original: &mut MetaData = unsafe { entry.as_mut() };

                    // Remember the next entry in the chain.
                    next_entry = original.next;

                    // Initialize the MetaData of the indirect buffer.
                    {
                        // Safety: Safe, as `temp` is aligned, dereferenceable, and `clone` isn't aliased in this block.
                        let clone: &mut MetaData = unsafe { temp.as_mut() };

                        // Our cloned segment has only one reference (the one we return from this function).
                        clone.refcnt = 1;

                        // Next needs to point to the next entry in the cloned chain, not the original.
                        if next_entry.is_none() {
                            clone.next = None;
                        } else {
                            // Allocate space for the next segment's MetaData struct.
                            temp = allocate_metadata_data(0);
                            clone.next = Some(temp);
                        }

                        // Copy other relevant fields from our progenitor.
                        clone.buf_addr = original.buf_addr;
                        clone.buf_len = original.buf_len;
                        clone.data_off = original.data_off;
                        clone.nb_segs = original.nb_segs;
                        clone.ol_flags = original.ol_flags | METADATA_F_INDIRECT; // Add indirect flag to clone.
                        clone.pkt_len = original.pkt_len;
                        clone.data_len = original.data_len;
                    }

                    // Incrememnt the reference count on the data.  It resides in the MetaData structure that the data
                    // is directly attached to.  If the buffer we're cloning is itself an indirect buffer, then we need
                    // to find the original direct buffer in order to increment the correct reference count.
                    if original.ol_flags & METADATA_F_INDIRECT == 0 {
                        // Cloning a direct buffer.  Increment the ref count on it.
                        original.inc_refcnt();
                    } else {
                        // Cloning an indirect buffer.  Increment the ref count on the direct buffer with the data.
                        // The direct buffer's MetaData struct should immediately preceed the actual data.
                        let offset: isize = -(size_of::<MetaData>() as isize);
                        let direct: &mut MetaData = unsafe {
                            // Safety: The offset call is safe as `offset` is known to be "in bounds" for buf_addr.
                            // Safety: The as_mut call is safe as the pointer is aligned, dereferenceable, and
                            // points to an initialized MetaData instance.
                            // The returned address is known to be non-Null, so the unwrap call will never panic.
                            original.buf_addr.offset(offset).cast::<MetaData>().as_mut().unwrap()
                        };
                        direct.inc_refcnt();
                    }
                }

                // Embed the buffer type into the lower bits of the pointer.
                let tagged: NonNull<MetaData> = head.with_addr(head.addr() | TAG_HEAP);

                // Return the new DemiBuffer.
                DemiBuffer {
                    ptr: tagged,
                    _phantom: PhantomData,
                }
            },
            #[cfg(feature = "libdpdk")]
            TAG_DPDK => unsafe {
                let mbuf_ptr: *mut rte_mbuf = self.get_mbuf();
                // ToDo: This allocates the clone MBuf from the same MBuf pool as the original MBuf.  Since the clone
                // never has any direct data, we could potentially save memory by allocating these from a special pool.
                // Safety: it is safe to dereference "mbuf_ptr" as it is known to point to a valid MBuf.
                let mempool_ptr: *mut rte_mempool = (*mbuf_ptr).pool;
                // Safety: rte_pktmbuf_clone is a FFI, which is safe to call since we call it with valid arguments and
                // properly check its return value for null (failure) before using.
                let mbuf_ptr_clone: *mut rte_mbuf = rte_pktmbuf_clone(mbuf_ptr, mempool_ptr);
                if mbuf_ptr_clone.is_null() {
                    panic!("failed to clone mbuf");
                }

                // Safety: from_mbuf is safe to call here as "mbuf_ptr_clone" is known to point to a valid MBuf.
                DemiBuffer::from_mbuf(mbuf_ptr_clone)
            },
            _ => {
                panic!("corrupted DemiBuffer");
            },
        }
    }
}

// De-Reference Trait Implementation for DemiBuffer.
impl Deref for DemiBuffer {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        // ToDo: Review having this "match", since MetaData and MBuf are laid out the same, these are equivalent cases.
        match self.get_tag() {
            TAG_HEAP => {
                // Safety: the call to from_raw_parts is safe, as its arguments refer to a valid readable memory region
                // of the size specified (which is guaranteed to be smaller than isize::MAX) and is contained within
                // a single allocated object.  Also, since the data type is u8, proper alignment is not an issue.
                unsafe { slice::from_raw_parts(self.data_ptr(), self.len()) }
            },
            #[cfg(feature = "libdpdk")]
            TAG_DPDK => {
                // Safety: the call to from_raw_parts is safe, as its arguments refer to a valid readable memory region
                // of the size specified (which is guaranteed to be smaller than isize::MAX) and is contained within
                // a single allocated object.  Also, since the data type is u8, proper alignment is not an issue.
                unsafe { slice::from_raw_parts(self.dpdk_data_ptr(), self.len()) }
            },
            _ => {
                panic!("corrupted DemiBuffer");
            },
        }
    }
}

// Mutable De-Reference Trait Implementation for DemiBuffer.
impl DerefMut for DemiBuffer {
    fn deref_mut(&mut self) -> &mut [u8] {
        // ToDo: Review having this "match", since MetaData and MBuf are laid out the same, these are equivalent cases.
        match self.get_tag() {
            TAG_HEAP => {
                // Safety: the call to from_raw_parts_mut is safe, as its args refer to a valid readable memory region
                // of the size specified (which is guaranteed to be smaller than isize::MAX) and is contained within
                // a single allocated object.  Also, since the data type is u8, proper alignment is not an issue.
                unsafe { slice::from_raw_parts_mut(self.data_ptr(), self.len()) }
            },
            #[cfg(feature = "libdpdk")]
            TAG_DPDK => {
                // Safety: the call to from_raw_parts_mut is safe, as its args refer to a valid readable memory region
                // of the size specified (which is guaranteed to be smaller than isize::MAX) and is contained within
                // a single allocated object.  Also, since the data type is u8, proper alignment is not an issue.
                unsafe { slice::from_raw_parts_mut(self.dpdk_data_ptr(), self.len()) }
            },
            _ => {
                panic!("corrupted DemiBuffer");
            },
        }
    }
}

// Drop Trait Implementation for DemiBuffer
impl Drop for DemiBuffer {
    fn drop(&mut self) {
        match self.get_tag() {
            TAG_HEAP => {
                // This might be a chain of buffers.  If so, we'll walk the list.
                let mut next_entry: Option<NonNull<MetaData>> = Some(self.ptr);
                while let Some(mut entry) = next_entry {
                    // Safety: This is safe, as `entry` is aligned, dereferenceable, and the MetaData struct it points
                    // to is initialized.
                    let mut metadata: &mut MetaData = unsafe { entry.as_mut() };

                    // Remember the next entry in the chain (if any) before we potentially free the current one.
                    next_entry = metadata.next;
                    metadata.next = None;

                    // Decrement the reference count.
                    if metadata.dec_refcnt() == 0 {
                        // See if the data is directly attached, or indirectly attached.
                        if metadata.ol_flags & METADATA_F_INDIRECT != 0 {
                            // This is an indirect buffer.  Find the direct buffer that holds the actual data.
                            let offset: isize = -(size_of::<MetaData>() as isize);
                            let direct: &mut MetaData = unsafe {
                                // Safety: The offset call is safe as `offset` is known to be "in bounds" for buf_addr.
                                // Safety: The as_mut call is safe as the pointer is aligned, dereferenceable, and
                                // points to an initialized MetaData instance.
                                // The returned address is known to be non-Null, so the unwrap call will never panic.
                                metadata.buf_addr.offset(offset).cast::<MetaData>().as_mut().unwrap()
                            };

                            // Restore buf_addr and buf_len to their unattached values.
                            metadata.buf_addr = null_mut();
                            metadata.buf_len = 0;
                            metadata.ol_flags = metadata.ol_flags & !METADATA_F_INDIRECT;

                            // Drop our reference to the direct buffer, and free it if ours was the last one.
                            if direct.dec_refcnt() == 0 {
                                // Verify this is a direct buffer in debug builds.
                                debug_assert_eq!(direct.ol_flags & METADATA_F_INDIRECT, 0);

                                // Convert to NonNull<MetaData> type.
                                // Safety: The NonNull::new_unchecked call is safe, as `direct` is known to be non-null.
                                let allocation: NonNull<MetaData> = unsafe { NonNull::new_unchecked(direct as *mut _) };

                                // Free the direct buffer.
                                free_metadata_data(allocation);
                            }
                        }

                        // Free this buffer.
                        free_metadata_data(entry);
                    }
                }
            },
            #[cfg(feature = "libdpdk")]
            TAG_DPDK => {
                let mbuf_ptr: *mut rte_mbuf = self.get_mbuf();
                // Safety: This is safe, as mbuf_ptr does indeed point to a valid MBuf.
                unsafe {
                    // Note: This DPDK routine properly handles MBuf chains, as well as indirect, and external MBufs.
                    rte_pktmbuf_free(mbuf_ptr);
                }
            },
            _ => {
                panic!("corrupted DemiBuffer");
            },
        }
    }
}
