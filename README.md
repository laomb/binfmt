# LAOMB Binary Format ("binfmt") Specification & Format Explorer & FASMG Include

## Overview

This project contains two things:

1. A **specification** for the LAOMB Binary Format (LBF) v1.0
2. A **GUI viewer** (`LBF Viewer`) that can open an `LBF` file (`.bin` / `.drv` / `.dl`) and inspect its contents and headers.
3. A **FAMG Include files defining the LBF format** that can be used with any fasmg/fasm2 project which wishes to assemble into a lbf executable/library/driver.

---

## 1. What is LBF?

LBF ("LAOMB Binary Format") is the loadable binary format for the LAOMB OS.

Key properties:

* Target: IA-32 protected mode
* Endianness: little-endian
* Strongly segmentation-aware (segments are first-class)
* Tables are explicit and mostly flat structures
* String data is centralized in one table
* Imports/exports are explicit and relocations are segment+offset based

LBF supports:

* Executables
* Drivers
* Dynamic libraries

---

## 2. What is the LBF Viewer?

`LBF Viewer` is a small Tk-based desktop app that:

* opens an LBF file
* parses all known tables
* shows a tree view on the left (Header, Segments, Sections, etc.)
* shows decoded detail on the right (flags, addresses, names from STRTAB, etc.)

It's mainly for:

* debugging the loader
* inspecting produced binaries
* validating that toolchain output is structurally sane

---

## 3. Running the Viewer

### Requirements

* Python 3.8+
* Tkinter available (on most Linux distros it's `python3-tk`; on Windows/macOS it's typically already bundled)

### Run

```bash
python3 lbf_viewer.py                # start empty
python3 lbf_viewer.py ./mybinary.bin # open a file immediately
```

---

## 4. Important concepts in LBF

**Segments vs Sections**

* A *segment* is a loader-level thing that becomes its own descriptor in GDT/LDT.

  * Has a type like CODE_RX, DATA_RW, STACK_RW which enforces properties,
  * Has a `vlimit` (logical size / limit).
* A *section* is a region inside a segment.

  * Example: `.text`, `.rodata`, `.data`, `.bss`, `.stub`.
  * Each section says:

    * where in the file the bytes live (`file_off`, `file_sz`)
    * where in memory they go inside the owning segment (`mem_off`, `mem_sz`)
    * alignment
    * content hints (DISCARDABLE, ZERO_INIT)

The loader copies file bytes for each non-BSS section, zero-fills the rest, and then enforces access policy.

**Imports / Relocs**

* `DEPS` lists required modules (by logical name).
* `IMPORTS` lists symbols we need from those deps.
* `RELOCS` describes slots inside our code/data that need to be patched:

  * either a far pointer `{off32, sel16}`
  * or just a selector
  * can also request a selector to *our own* segment (SELF_IMPORT), so code can learn its own data selector safely.

**Exports**

* `EXPORTS` maps names and/or ordinals to `(segment, offset)` pairs.
* That's what other modules bind against.

> Note: What is referred to as a segment here, is of course the ordinal of the segment, as the on-disk file has no way of knowing what segment index will be allocated on runtime.

**Strings**

* `STRTAB` is one big UTF-8 blob of NULL-terminated strings.
* Everything refers into it by offset. Offset 0 MUST be `"\0"`.

**Symbols**

* `SYMIDX` and `SYMSTR` give (a) sorted addresses per segment and (b) their names via STRTAB offsets.
* It's meant for debug / diagnostics (backtraces) and is not needed for minimum load.

**Security**

* `SECURITY` can carry signatures.
* To be specified what algorythm shall be used.

---

## 5. Directory table types (summary)

| Type ID | Name           | Meaning                                        |
| ------: | -------------- | ---------------------------------------------- |
|       1 | LBF_T_SEGMENTS | Segment descriptors for loader                 |
|       2 | LBF_T_SECTIONS | Per-segment code/data layout                   |
|       3 | LBF_T_RELOCS   | Relocation slots to be patched at load/bind    |
|       4 | LBF_T_EXPORTS  | Symbols this binary exposes                    |
|       5 | LBF_T_DEPS     | Other modules this binary depends on           |
|       6 | LBF_T_TLS      | Reserved for future TLS template info          |
|       7 | LBF_T_SECURITY | Signature / trust metadata                     |
|       8 | LBF_T_STRTAB   | Central string table                           |
|       9 | LBF_T_IMPORTS  | Symbols we require from our dependencies       |
|      10 | LBF_T_SYMIDX   | Sorted symbol addresses per segment            |
|      11 | LBF_T_SYMSTR   | Symbol names (string offsets), parallel to idx |

---

Nothing here installs system-wide; it's intentionally self-contained and hackable.

---

## 6. Status / TODO

* Loader rules are defined, but enforcement/policy (e.g. SAFE_IMPORTS vs GATE) will evolve.
* TLS table (`LBF_T_TLS`) is reserved, not implemented.
* SECURITY table format will get more detail (alg IDs, hashing scheme, trust model).
* Viewer does not currently:

  * validate overlap / alignment constraints
  * simulate selector allocation
  * show raw section bytes/hexdump in-place

* Actually copy the fasmg header here.

These will be added later.

---

## 7. License / usage

This code and documentation is intended for internal OS/toolchain development and debugging and as such is dedicated to the public domain.
