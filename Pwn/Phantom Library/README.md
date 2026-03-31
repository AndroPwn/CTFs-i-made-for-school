# Phantom Librarian — Challenge Dev Writeup

**Category:** PWN
**Difficulty:** Hard
**Techniques:** Tcache poisoning · FSOP (House of Apple 2) · ORW ROP · seccomp
**Libc:** Ubuntu GLIBC 2.35-0ubuntu3.13 (added a gadget)

---

## Part 1 — Making the Challenge

### Concept

The theme is a ghost haunting a library and corrupting its catalogue. Players interact with a heap-based book management system. The binary has full mitigations (Full RELRO, PIE, NX, Stack Canary) and a seccomp filter that blocks execve, forcing players to use an open/read/write ROP chain rather than a simple shell.

The intended path requires chaining four distinct techniques: a heap info-leak via UAF, a libc leak via the unsorted bin, tcache poisoning with safe-linking bypass, and FSOP via House of Apple 2 to reach the ROP chain.

### Starting with glibc 2.39

The challenge originally targeted glibc 2.39. The idea was the same — heap exploitation with FSOP — but 2.39 introduced additional hardening that made the intended technique significantly more difficult than planned. The vtable validation was stricter and several code paths we relied on had been restructured in ways that broke our call chain. After spending considerable time trying to make the exploit work cleanly on 2.39 we decided the challenge was becoming more about fighting obscure version-specific glibc internals than about learning the core technique. We shifted to glibc 2.35 because it is the most widely studied version for FSOP exploitation, has well understood behavior, and is what most CTF players will have encountered before.

### The Binary

The challenge is a simple catalogue manager. Players can add books each with a heap-allocated note, view them, edit notes, enchant a book which frees the note but intentionally does not clear the pointer, read enchanted notes via UAF, and dispel books. Options 6 and 7 are hidden from the menu — players must discover them by fuzzing.

```
1. Add book
2. View book
3. Edit note
4. Enchant book        ← frees note, pointer NOT cleared
5. Leave library       ← exit() ← FSOP trigger
[hidden] 6. Read enchanted note  ← UAF read
[hidden] 7. Dispel ghost         ← free book struct
```

The seccomp filter is installed at startup and whitelists only read, write, open, openat, close, mmap, mprotect, brk, exit, exit_group, fstat, lseek, and a handful of glibc startup syscalls. execve is blocked — a one-gadget or system("/bin/sh") will not work.

### Intended Bugs

**Bug 1 — Missing null terminator**

read_n() reads up to len bytes and stops at newline. If the user sends exactly len bytes with no newline, no null terminator is written. When the note is later printed with puts() it prints past the note into the next heap chunk, leaking adjacent heap data.

**Bug 2 — UAF on note pointer**

enchant_book() calls free(b->note) but never sets b->note = NULL. The enchanted flag is set but read_enchanted() checks b->enchanted and then calls write(STDOUT_FILENO, b->note, 8) — reading 8 bytes from a freed chunk. This gives a heap pointer leak and a libc pointer leak.

edit_note() calls realloc(b->note, new_sz). Since b->note is not cleared after enchant, this calls realloc on a freed chunk — which for same-size requests returns the same pointer in-place in glibc 2.35. This is the UAF write used for tcache poisoning.

### The calloc vs malloc Decision

The original source used calloc for Book structs. This was intentional — we wanted an extra layer of difficulty where the heap layout would be unpredictable if players added books at the wrong time.

The problem is that calloc in glibc 2.35 bypasses tcache entirely and goes directly to the unsorted bin. This caused the large chunk needed for the FSOP payload to get silently consumed every time a new book was added after the libc leak. The unsorted bin chunk would get carved up piece by piece and by the time we tried to claim it for the fake FILE it was gone. We spent a long time trying to work around this without changing the source.

We tried pre-allocating all books before freeing the large chunk. We tried using different chunk sizes to avoid conflicts. We tried adding padding allocations to shift the layout. None of it produced a stable result because the calloc bypass is fundamental — every struct allocation would hunt down the unsorted bin chunk regardless of what else we did.

Eventually we accepted that keeping calloc would make the challenge broken rather than hard, and changed it to malloc + memset. This routes struct allocations through tcache normally, keeps the unsorted bin chunk intact, and makes the heap layout completely deterministic. The challenge is harder in other ways — the 0x0a constraint, the FSOP call chain, the patched libc — so removing the calloc trap didn't make it easy.

### Finding the Pivot Gadget

For FSOP House of Apple 2 we need a stack pivot gadget. The classic choice is push rdi; pop rsp; ret — it takes the FILE pointer that glibc passes as the first argument and moves it into rsp, pivoting the stack onto our fake FILE struct.

The problem is that stock glibc 2.35 does not contain this exact sequence anywhere useful. We spent time looking for alternatives. We looked at xchg rsp, rdi but that sequence doesn't appear cleanly. We looked at mov rsp, rdi and similar direct moves — not present. We tried constructing multi-gadget pivot chains but every option required either landing in the middle of an instruction sequence that would crash, or using a call chain so long it would fail one of the earlier FSOP checks.

We looked at completely different FSOP techniques that don't require a stack pivot at all, like _IO_obstack_jumps which has a simpler call chain. That approach worked in theory but the obstack vtable sits outside the approved __libc_IO_vtables range in this specific libc build, so the vtable check would kill the process before we got there.

After exhausting the alternatives we patched three bytes at offset 0x4c581 in the libc — an INT3 cave that isn't executed during normal program operation — to contain 57 5c c3 (push rdi; pop rsp; ret). This is the intended path. The challenge ships a specially prepared libc and players must identify the gadget from the distributed binary rather than looking it up in a stock libc database.

```python
data = bytearray(open("libc.so.6", "rb").read())
data[0x4c581] = 0x57  # push rdi
data[0x4c582] = 0x5c  # pop rsp
data[0x4c583] = 0xc3  # ret
open("libc_patched.so.6", "wb").write(data)
```

### Why _IO_wfile_jumps and not _IO_cookie_jumps

In glibc 2.35-0ubuntu3.13, _IO_cookie_jumps sits at 0x215b80 which is before __libc_IO_vtables starts at 0x216a00. IO_validate_vtable would kill the process. _IO_wfile_jumps at 0x2170c0 is confirmed inside the section. This is an intentional difficulty spike — players using older writeups or different libc builds will need to verify this themselves.

### Design Decisions Summary

**Hidden menu options** — forces players to understand the binary rather than running automated tools. The UAF primitive is not obvious from the menu.

**seccomp blocking execve** — a challenge that ends with system("/bin/sh") is trivial once the write primitive is established. Blocking execve forces a correct ORW chain.

**Patched libc** — players cannot simply look up the pivot gadget in standard libc databases. Combined with the vtable range constraint this forces proper static analysis rather than copying a generic FSOP PoC.

**malloc instead of calloc** — keeps the heap layout deterministic so the challenge is hard in the right ways rather than broken in the wrong ways.

---

## Part 2 — Solving the Challenge

### Stage 1 — Heap Base Leak

Allocate three books with 0xf0 notes. Free book 1 first — it becomes the tail of tcache bin 0x100 so its fd = NULL. glibc 2.35 safe-linking stores fd as PROTECT_PTR(pos, next) = pos ^ (next >> 12). With next = NULL this reduces to pos >> 12 where pos is the chunk's user-data address.

UAF read on book 1 leaks this mangled pointer. Shift left by 12 to recover chunk1_note_addr then mask the low 12 bits to get heap_base.

### Stage 2 — Libc Base Leak

Allocate a book with a 0x418-byte note. This produces a 0x420 chunk which is larger than the tcache maximum (0x410) and goes to the unsorted bin on free. The first 8 bytes of a freed unsorted bin chunk are its fd pointer which points into main_arena. UAF read gives libc_base = fd - main_arena_offset - 0x60.

All books 5 through 8 must be allocated before enchanting book3. If any book is allocated after the libc leak its malloc call for the Book struct would find the unsorted bin chunk and split it, destroying the layout we need for the payload. Pre-allocating everything means all struct allocations go to the heap top and leave the unsorted bin chunk completely intact.

### Stage 3 — Tcache Poisoning

With both bases known we build a tcache chain by freeing book7 then book6. Tcache looks like:

```
head → chunk6 → chunk7 → NULL
```

UAF write to book6's freed note replacing its fd with a mangled pointer to _IO_list_all:

```python
forged = io_list_all XOR (chunk6_addr >> 12)
edit(book6, 0xf0, p64(forged))
```

Tcache now looks like:

```
head → chunk6 → io_list_all
```

Two more allocations drain the list. The second malloc returns io_list_all and we write fake_struct_addr there. _IO_list_all now points to our fake FILE on the heap.

### Stage 4 — Building the Fake FILE

The fake _IO_FILE_plus is written into book8's note at heap+0x12d0:

```
heap+0x12d0   "/home/ph4nt0mUS3R/flag.txt\0"
heap+0x12e0   lock target (zeroed)
heap+0x12f0   fake _IO_FILE struct
heap+0x13d0   fake _IO_wide_data
heap+0x14b8   fake wide vtable
heap+0x1528   ROP chain
heap+0xe20    flag buffer (book4.note, outside payload)
```

Critical fields:

```
_flags         = pop_rsp gadget (0x433b4)
_IO_read_ptr   = rop_addr
_IO_write_base = fake_struct_addr + 0x40
_IO_write_ptr  = fake_struct_addr + 0x41  (> write_base, triggers flush)
_lock          = heap+0x12e0 (valid zeroed memory, acts as unlocked mutex)
_wide_data     = wide_addr
vtable         = _IO_wfile_jumps (inside __libc_IO_vtables, passes validation)
```

The wide_data struct has _wide_vtable pointing to our fake wide vtable which has __doallocate (slot +0x68) set to the push_rdi_pop_rsp gadget.

### Stage 5 — The Call Chain

```
exit()
  _IO_flush_all_lockp(do_lock=1)
    acquires _lock at heap+0x12e0        ← valid zeroed mutex, succeeds
    _mode=0 AND write_ptr > write_base   ← triggers _IO_OVERFLOW
    _IO_wfile_overflow(fp)               ← vtable = _IO_wfile_jumps, validated
      wide_data[0x18] = 0
      _IO_wdoallocbuf(fp)
        wide_vtable[0x68](fp)            ← push_rdi_pop_rsp, rdi = fake_struct_addr
          push rdi  → rsp = fake_struct_addr
          pop  rsp  → rsp = [fake_struct_addr + 0] = pop_rsp gadget
          ret       → jmp pop_rsp
        pop rsp     → rsp = [fake_struct_addr + 8] = rop_addr
        ret         → ROP chain
```

### The _lock Problem

_IO_flush_all_lockp acquires a mutex at fp->_lock before processing any FILE. We initially left this as zero meaning glibc dereferenced NULL and crashed inside cleanup code with no useful stack trace. Found by reading the raw disassembly of _IO_flush_all_lockp line by line. Fixed by pointing _lock at heap+0x12e0 — a valid zeroed region of our allocation that acts as an already-unlocked mutex.

### Stage 6 — ORW ROP Chain

```asm
pop rax ; 2           SYS_open
pop rdi ; flag_path
pop rsi ; 0           O_RDONLY
pop rdx ; 0
syscall               rax = real fd

xchg_edi_eax          edi = fd (critical: do not hardcode 3)

pop rax ; 0           SYS_read
pop rsi ; flag_buf    heap+0xe20, outside payload
pop rdx ; 0x40
syscall

pop rax ; 1           SYS_write
pop rdi ; 1
pop rsi ; flag_buf
pop rdx ; 0x40
syscall

pop rax ; 60          SYS_exit
pop rdi ; 0
syscall
```

### The xchg_edi_eax Problem

Locally open() returns fd=3 because only stdin, stdout, and stderr are open. On the remote server socat opens socket file descriptors before starting the binary so open() returns fd=4 or higher. The original ROP chain hardcoded pop_rdi; 3 which read from the wrong descriptor on remote and got nothing. The exploit worked perfectly locally and silently failed remotely with no error. Fixed by adding xchg eax, edi after the open syscall to move whatever open() actually returned into edi.

### The Flag Buffer Problem

The flag buffer was originally inside the payload. The flag content ends with a newline which is byte 0x0a. read_n() stops at 0x0a. When read() wrote the flag into the buffer the newline landed on a gadget address in the ROP chain and corrupted it. GDB showed the crash at RIP = 0x770a67616c66 which is literally the bytes of the flag string interpreted as a pointer. Fixed by moving the flag buffer to book4's note at heap+0xe20 — a completely separate allocation outside the payload.

### The 0x0a Constraint

read_n() stops at newline. Any byte in the payload equal to 0x0a silently truncates the write there leaving everything after as zeros. Since all pointers derive from ASLR-randomized base addresses roughly one in 256 runs produces a clean payload. The exploit checks every payload byte before sending and retries automatically on bad ASLR runs.

---

## Files

| File | Description |
|------|-------------|
| phantomlibrarian.c | Challenge source |
| phantom_librarian | Compiled binary |
| libc_patched_so.6 | Patched libc (distribute to players) |
| libc/ld-linux-x86-64.so.2 | Dynamic linker (distribute to players) |
| solve.py | Reference solution |
| flag.txt | Put on server at /home/ph4nt0mUS3R/flag.txt |

---

## Build

```bash
gcc -O0 -fstack-protector-all -fPIE -pie \
    -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack \
    -o phantom_librarian phantomlibrarian.c
```

---



Flag format: `f1_g{...}`
