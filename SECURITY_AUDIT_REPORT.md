# Firecracker Security Audit: KVM Interaction, Memory Management & Boot Process

**Scope:** KVM ioctls, guest memory mapping, hot-plug/hot-unplug, snapshot/restore, configuration validation  
**Exclusions:** Known findings (snapshot vCPU state, CRC64, pre-boot seccomp, kernel cmdline injection)

---

## Finding 1: KVM Slot Allocation Boundary Check Off-by-One

**File:** `src/vmm/src/vstate/vm.rs`, lines 404–415  
**Severity:** Medium  
**Category:** Missing validation / integer boundary error

### Description

`next_kvm_slot` atomically reserves `slot_cnt` contiguous KVM slot IDs by calling `fetch_add(slot_cnt)`, which returns the *first* slot in the reserved range. The subsequent bounds check only validates that the *first* slot (`next`) is less than `max_memslots`:

```rust
let next = self.common.next_kvm_slot.fetch_add(slot_cnt, Ordering::Relaxed);
if self.common.max_memslots <= next {
    None
} else {
    Some(next)
}
```

When `slot_cnt > 1` (as occurs with hotpluggable memory regions at line 480), the check should verify `next + slot_cnt <= max_memslots` to ensure the *entire* reserved range fits. If `max_memslots` is 509 and `next` is 508, reserving 4 slots passes the check but yields slot IDs 508–511, where 509–511 exceed the KVM limit.

### Attack Path

1. An attacker configures a VM with large DRAM and a hotpluggable memory region with many small slots, consuming most available KVM slots.
2. A subsequent hotplug registration calls `next_kvm_slot(N)` where `N > 1`.
3. The first slot passes the bounds check, but subsequent slots exceed `max_memslots`.
4. KVM rejects the out-of-range `set_user_memory_region` calls with `EINVAL`, but Firecracker has already atomically incremented the counter — those slot IDs are permanently "consumed" and cannot be reclaimed.
5. This leads to KVM slot exhaustion and an inconsistent state where Firecracker believes it has valid slots that KVM has rejected.

### Additional Concern: Relaxed Ordering

`fetch_add` uses `Ordering::Relaxed`. While slot allocation currently happens on a single thread (during VM setup or through the API controller which serializes requests), if future changes introduce concurrent callers, two threads could race to allocate overlapping slot ranges that individually pass the bounds check but collectively exceed `max_memslots`. The lack of a compare-and-swap loop makes this non-atomic from a correctness standpoint.

---

## Finding 2: Inconsistent State on Error in Memory Hotplug

**File:** `src/vmm/src/vstate/memory.rs`, lines 387–417  
**Severity:** Medium  
**Category:** Missing resource cleanup on error paths

### Description

In `update_slot`, the internal `plugged` bitmap is mutated *before* the KVM and mprotect operations:

```rust
let prev = bitmap_guard.replace((mem_slot.slot - self.slot_from) as usize, plug);
if prev == plug {
    return Ok(());
}
```

If the subsequent `set_user_memory_region` or `protect` call fails, the bitmap is **not rolled back**. This creates a divergence between Firecracker's internal tracking and the actual KVM/mprotect state.

### Attack Path — Plug Operation (lines 405–408)

1. Bitmap is set to `plugged = true`.
2. `mem_slot.protect(false)` (mprotect READ|WRITE) succeeds.
3. `vm.set_user_memory_region(kvm_region)` fails (e.g., KVM returns EINVAL due to the slot boundary issue from Finding 1, or resource limits).
4. Memory is now mprotect'd as accessible to the host process, and the bitmap says "plugged," but KVM has no mapping for it. Guest writes to this region would cause KVM exits that cannot be handled, potentially crashing the vCPU thread.

### Attack Path — Unplug Operation (lines 409–414)

1. Bitmap is set to `plugged = false`.
2. `vm.set_user_memory_region(zero-size)` succeeds — KVM removes the slot.
3. `mem_slot.protect(true)` (mprotect PROT_NONE) fails.
4. Memory is removed from KVM but still host-accessible. Guest-originated accesses are undefined. The bitmap says "unplugged" but the host can still read/write the region, potentially leaking stale guest data to later code that re-maps the same host virtual address range.

---

## Finding 3: Non-Atomic Guest Memory Registration Leaves Partial State

**File:** `src/vmm/src/vstate/vm.rs`, lines 429–447  
**Severity:** Medium  
**Category:** Missing resource cleanup on error paths

### Description

`register_memory_region` performs three sequential fallible operations without rollback:

```rust
fn register_memory_region(&mut self, region: Arc<GuestRegionMmapExt>) -> Result<(), VmError> {
    let new_guest_memory = self.common.guest_memory.insert_region(Arc::clone(&region))?;  // Step 1

    region.slots().try_for_each(|(ref slot, plugged)| match plugged {
        true => self.set_user_memory_region(slot.into()),     // Step 2a
        false => slot.protect(true).map_err(VmError::MemoryError), // Step 2b
    })?;

    self.common.guest_memory = new_guest_memory;  // Step 3
}
```

If Step 1 succeeds but Step 2 fails partway through (e.g., the third of five slots fails KVM registration), the first two slots are registered in KVM but `self.common.guest_memory` is never updated (Step 3 is skipped). These KVM slots become orphaned — they reference host memory that Firecracker no longer tracks, and will never be cleaned up.

Conversely, if Step 2 completes but Step 3 is somehow disrupted, `new_guest_memory` is dropped, but KVM still holds references to the registered slots.

### Impact

Orphaned KVM memory slots referencing the host-mapped guest memory regions persist for the VM lifetime. They consume KVM slot resources and could serve stale memory to the guest if the host virtual address range is later reused.

---

## Finding 4: Host Virtual Address Leak via UFFD Handshake

**File:** `src/vmm/src/persist.rs`, lines 570–591  
**Severity:** Medium  
**Category:** Information leak

### Description

During snapshot restore with UFFD (userfaultfd) backend, `create_guest_memory` populates `GuestRegionUffdMapping` with the raw host virtual address of each guest memory region:

```rust
backend_mappings.push(GuestRegionUffdMapping {
    base_host_virt_addr: mem_region.as_ptr() as u64,  // line 581
    size: mem_region.size(),
    offset,
    ...
});
```

This struct is serialized to JSON (line 600) and sent over a Unix domain socket to an external UFFD handler process (line 603). The external process receives the exact host virtual addresses where guest memory is mapped.

### Attack Path

1. A compromised or malicious UFFD handler process receives the `base_host_virt_addr` values.
2. These addresses reveal the ASLR layout of Firecracker's guest memory mappings in the host process.
3. Combined with any other vulnerability that provides write access to Firecracker's address space (e.g., a use-after-free in a shared library), the attacker can precisely target guest memory regions to inject code or data.
4. This defeats the purpose of ASLR for the guest memory region, reducing the exploit difficulty of any memory corruption vulnerability in Firecracker.

### Note

The UFFD handler is architecturally expected to be a trusted component, but defense-in-depth principles suggest minimizing the information shared. The handler needs these addresses to perform `UFFDIO_COPY` operations, making this partially by-design, but the information is more than what's strictly necessary (relative offsets from a base could suffice with a different protocol design).

---

## Finding 5: Unix Socket File Descriptor Leak via `forget()`

**File:** `src/vmm/src/persist.rs`, lines 638–641  
**Severity:** Low  
**Category:** Resource leak

### Description

After sending the UFFD handshake, the Unix socket is intentionally leaked:

```rust
// We prevent Rust from closing the socket file descriptor to avoid a potential race condition
// between the mappings message and the connection shutdown.
forget(socket);
```

While the comment explains the rationale (preventing a race between message delivery and connection shutdown), this permanently leaks the file descriptor. The socket will never be closed for the lifetime of the Firecracker process.

### Impact

- **Resource exhaustion:** Each snapshot restore leaks one FD. If Firecracker is used in a workflow involving repeated snapshot load operations (e.g., for testing or live migration retry scenarios), the process's FD limit (`RLIMIT_NOFILE`) is gradually consumed. With typical limits of 1024 or 65536, this is exploitable over many iterations.
- **Peer detection failure:** The UFFD handler process cannot detect Firecracker's exit via socket hangup (`POLLHUP`), because the socket remains open until Firecracker exits. The comment at lines 606–635 suggests using `SO_PEERCRED` for this purpose, but without socket closure, the handler has no reliable shutdown signal.
- **Connection state:** The leaked socket remains in `ESTABLISHED` state, consuming kernel resources (socket buffer memory, inode, dentry cache entry).

---

## Finding 6: Snapshot Memory Region Type Trusted Without Cross-Validation

**File:** `src/vmm/src/vstate/memory.rs`, lines 273–297  
**File:** `src/vmm/src/persist.rs`, lines 297–337  

**Severity:** Low  
**Category:** Missing validation

### Description

When restoring from a snapshot, `GuestRegionMmapExt::from_state` directly copies the `region_type` field from the deserialized snapshot state without validating it against the memory configuration:

```rust
Ok(GuestRegionMmapExt {
    inner: region,
    slot_size,
    region_type: state.region_type,  // Trusted from snapshot
    slot_from,
    plugged: Mutex::new(BitVec::from_iter(state.plugged.iter())),
})
```

The `snapshot_state_sanity_check` function (persist.rs:298–337) validates DRAM regions but does not check:
- That the number of hotpluggable regions matches the expected configuration.
- That a region marked `Hotpluggable` in the snapshot actually corresponds to a hotpluggable memory configuration.
- That `plugged` vectors for hotpluggable regions have slot counts consistent with the configured `slot_size`.

### Impact

A maliciously crafted snapshot file could mark a DRAM region as `Hotpluggable` or vice versa. Since `update_slot` (line 395) contains `assert!(self.region_type == GuestRegionType::Hotpluggable)`, misclassifying a DRAM region as hotpluggable wouldn't cause immediate harm (the assert would catch it). However, marking a hotpluggable region as DRAM could bypass hotplug validation logic, allowing the region to be treated as always-plugged memory that skips mprotect enforcement.

---

## Finding 7: Integer Overflow in `memfd_backed` Size Summation

**File:** `src/vmm/src/vstate/memory.rs`, line 572  
**Severity:** Low  
**Category:** Integer overflow

### Description

The `memfd_backed` function computes the total memory size by summing region sizes:

```rust
let size = regions.iter().map(|&(_, size)| size as u64).sum();
```

The `.sum()` call on `u64` values wraps on overflow without any checked arithmetic. If an attacker could craft region sizes that sum to more than `u64::MAX` (or that wrap to a small value), the `create_memfd` call would create an undersized file, and subsequent `mmap` operations would map beyond EOF, leading to `SIGBUS` on access.

### Practical Exploitability

This is difficult to exploit in practice because:
1. `size` is `usize` (cast to `u64`), and `regions` typically comes from `arch_memory_regions` which is bounded by `mem_size_mib` validation.
2. `MachineConfig::update` validates `mem_size_mib != 0` and page alignment.
3. The system would likely OOM or hit `mmap` limits before reaching values that could overflow `u64`.

However, the lack of `checked_add` is a defense-in-depth gap. The `create` function (line 549) correctly uses `checked_add` for the same purpose, making this an inconsistency.

---

## Summary Table

| # | Finding | Severity | File | Lines |
|---|---------|----------|------|-------|
| 1 | KVM slot allocation boundary check off-by-one | Medium | `vm.rs` | 404–415 |
| 2 | Bitmap/KVM state divergence in hotplug on error | Medium | `memory.rs` | 387–417 |
| 3 | Partial KVM registration without rollback | Medium | `vm.rs` | 429–447 |
| 4 | Host virtual address leak via UFFD handshake | Medium | `persist.rs` | 570–591 |
| 5 | Unix socket FD leak via `forget()` | Low | `persist.rs` | 638–641 |
| 6 | Snapshot region_type trusted without cross-validation | Low | `memory.rs` | 273–297 |
| 7 | Unchecked integer summation in `memfd_backed` | Low | `memory.rs` | 572 |
