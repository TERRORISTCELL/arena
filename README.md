small static lib for windows memory work.

exports:

- `arena_read_safe` checked read through the current process handle. use this when poking unknown addresses.
- `arena_read` unchecked read, segfaults on bad memory.
- `arena_write_safe` same as read_safe but for writes.
- `arena_write` unchecked write.
- `arena_spoof_init` build ret spoof tables from a PE image. returns false on bad input or missing gadgets.
- `arena_call_ret_spoofed_ex` call a function with spoofed return stack (ms x64, 0-8 integer/pointer args).
- `arena_call_ret_spoofed` convenience wrapper that returns 0 on failure.
- `arena_scan_signature_ex` pattern scan on a `(base, size)` range with resolve kind.
- `arena_scan_signature` convenience wrapper that returns 0 on failure.
- `arena_last_error` last failure message for this thread.

resolve kinds: `ARENA_RESOLVE_DIRECT_RVA`, `ARENA_RESOLVE_RIP_RELATIVE32`, `ARENA_RESOLVE_MATCH_ADDRESS`, `ARENA_RESOLVE_ABS32`, `ARENA_RESOLVE_ABS64`, `ARENA_RESOLVE_MATCH_RVA_PLUS_OFFSET`.

define `ARENA_SHORT_NAMES` before including `arena.h` if you want unprefixed names (`read_safe`, `read`, etc).

build it:

```
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

you get `build/libarena.a`. include `arena.h`, link the archive. cmake users can link the `arena` target. direct archive users should use mingw x64 and link the usual c++ runtime/kernel32 bits.

`arena_spoof_init` needs the module base before spoofed calls. spoofed calls only handle integer/pointer arguments and `uintptr_t`-sized returns; floats, vectors, and struct returns are out of scope.

license is wtfpl, see LICENSE.txt.
