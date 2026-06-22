# arena error codes

Failed API calls set a thread-local 32-bit code. Read `arena_last_error()` before retrying.
`0` means no error (or the channel was cleared).

## Memory subsystem (`memory_linux.cpp` and `memory_win32.cpp`)

| Code       | Function            | Condition |
|------------|---------------------|-----------|
| 0x01000001 | `arena_read_safe`, `arena_write_safe` | Address range overflows |
| 0x01000002 | `arena_read_safe`, `arena_write_safe` | Failed to read `/proc/self/maps` |
| 0x01000003 | `arena_read_safe`, `arena_write_safe` | Memory region is not readable |
| 0x01000004 | `arena_read_safe`, `arena_write_safe` | Memory region is not writable |
| 0x01000005 | `arena_read_safe`, `arena_write_safe` | Address is not committed / mapped |
| 0x01000006 | `arena_read_safe`   | Invalid read output |
| 0x01000007 | `arena_write_safe`  | Invalid write input |
| 0x01000008 | `arena_read_safe`, `arena_write_safe` | Address is outside user range |
| 0x01000009 | `arena_read_safe`, `arena_write_safe` | Address range overflows user range |
| 0x0100000A | `arena_read_safe`, `arena_write_safe` | `VirtualQuery` failed |
| 0x0100000B | `arena_read_safe`, `arena_write_safe` | Memory is not committed |
| 0x0100000C | `arena_read_safe`, `arena_write_safe` | Memory region did not advance |
| 0x0100000D | `arena_read_safe`   | `ReadProcessMemory` failed |
| 0x0100000E | `arena_write_safe`  | `WriteProcessMemory` failed |

## Scan subsystem (`scan.cpp`)

| Code       | Function                  | Condition |
|------------|---------------------------|-----------|
| 0x02000001 | `arena_scan_signature_ex` | Invalid pattern token |
| 0x02000002 | `arena_scan_signature_ex` | Empty pattern |
| 0x02000003 | `arena_scan_signature_ex` | Pattern is all wildcards |
| 0x02000004 | `arena_scan_signature_ex` | Match address overflow |
| 0x02000005 | `arena_scan_signature_ex` | `MATCH_RVA_PLUS_OFFSET` resolve requires params |
| 0x02000006 | `arena_scan_signature_ex` | `MATCH_RVA_PLUS_OFFSET` result overflow |
| 0x02000007 | `arena_scan_signature_ex` | `RIP_RELATIVE32` resolve requires params |
| 0x02000008 | `arena_scan_signature_ex` | RIP displacement out of range |
| 0x02000009 | `arena_scan_signature_ex` | RIP next address overflow |
| 0x0200000A | `arena_scan_signature_ex` | Invalid RIP-relative target |
| 0x0200000B | `arena_scan_signature_ex` | `ABS32` resolve requires params |
| 0x0200000C | `arena_scan_signature_ex` | `ABS32` displacement out of range |
| 0x0200000D | `arena_scan_signature_ex` | `ABS32` target overflow |
| 0x0200000E | `arena_scan_signature_ex` | `ABS64` resolve requires params |
| 0x0200000F | `arena_scan_signature_ex` | `ABS64` displacement out of range |
| 0x02000010 | `arena_scan_signature_ex` | `ABS64` target out of range |
| 0x02000011 | `arena_scan_signature_ex` | Unknown resolve kind |
| 0x02000012 | `arena_scan_signature_ex` | Invalid scan input |
| 0x02000013 | `arena_scan_signature_ex` | Scan range overflows |
| 0x02000014 | `arena_scan_signature_ex` | Pattern not found |
| 0x02000015 | `arena_scan_signature_ex` | Pattern matched multiple locations with different targets |
| 0x02000016 | `arena_scan_signature_ex` | Scan failed due to exception |

## Spoof subsystem (`spoof.cpp`)

| Code       | Function                      | Condition |
|------------|-------------------------------|-----------|
| 0x03000001 | `arena_spoof_init`            | Module base is null |
| 0x03000002 | `arena_spoof_init`            | Module DOS header is not readable |
| 0x03000003 | `arena_spoof_init`            | Invalid DOS signature |
| 0x03000004 | `arena_spoof_init`            | Invalid PE header offset |
| 0x03000005 | `arena_spoof_init`            | Module NT header is not readable |
| 0x03000006 | `arena_spoof_init`            | Invalid NT signature |
| 0x03000007 | `arena_spoof_init`            | Module is not x64 |
| 0x03000008 | `arena_spoof_init`            | Module is not PE32+ |
| 0x03000009 | `arena_spoof_init`            | Module `SizeOfImage` is zero |
| 0x0300000A | `arena_spoof_init`            | Invalid section count |
| 0x0300000B | `arena_spoof_init`            | Section table is not readable |
| 0x0300000C | `arena_spoof_init`            | Module image range overflows |
| 0x0300000D | `arena_spoof_init`            | Required spoof return slot was not found |
| 0x0300000E | `arena_spoof_init`            | Spoof init failed |
| 0x0300000F | `arena_call_ret_spoofed_ex`   | Missing spoof call output |
| 0x03000010 | `arena_call_ret_spoofed_ex`   | Spoof call target is null |
| 0x03000011 | `arena_call_ret_spoofed_ex`   | Spoof call args are null |
| 0x03000012 | `arena_call_ret_spoofed_ex`   | Spoof call supports at most 8 arguments |
| 0x03000013 | `arena_call_ret_spoofed_ex`   | Required spoof return slot is not initialized |
| 0x03000014 | `arena_spoof_init`            | Failed to find suitable return/jump gadgets in loaded ELF binaries |
| 0x03000015 | `arena_call_ret_spoofed_ex`   | Spoof is not initialized or gadgets not found |
