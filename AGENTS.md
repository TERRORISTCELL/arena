# arena — agent instructions

Natively cross-platform static library for Windows x64 and Linux x64 providing **safe memory access**, **pattern scanning**, and **stack return-address spoofing**.

## When to use

| Task | API |
|------|-----|
| Safe read/write unknown addresses | `arena_read_safe`, `arena_write_safe` |
| Fast read/write (may fault) | `arena_read`, `arena_write` |
| Find bytes/signatures in a module | `arena_scan_signature_ex` |
| Call game code with spoofed stack | `arena_spoof_init` then `arena_call_ret_spoofed_ex` (Windows only; direct call on Linux) |

**Do not** reimplement memory page validation, signature scanning, or call wrappers — use this library.

## Build

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
```

*   **Linux Native**: Compiles to `libarena.a`. Uses `/proc/self/maps` for safe page checks.
*   **Linux MinGW Cross / Windows**: Compiles to `arena.lib` / `libarena.a` with MS x64 assembly stack-spoofing enabled (requires NASM).

## Header

`include/arena.h` — full API. Optional `#define ARENA_SHORT_NAMES` for unprefixed aliases.


## Errors

`arena_last_error()` after any `false` / zero return.

## Used by

`shrewd` (VMT hooks), and any injector needing safe memory + spoof + scan.
