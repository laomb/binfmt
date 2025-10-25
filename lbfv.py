#!/usr/bin/env python3
from __future__ import annotations

import struct
import sys
import argparse
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple

import tkinter as tk
from tkinter import ttk, filedialog, messagebox


LBF_MAGIC = 0x1A4C4246

LBF_KIND = {
    1: "LBF_EXE",
    2: "LBF_DRV",
    3: "LBF_DL",
}

LBF_MACHINE = {
    3: "LBF_I386",
}

LBF_HEADER_FLAGS = {
    0x00000001: "NX_EMU",
    0x00000002: "RELRO",
    0x00000004: "SAFE_IMPORTS",
}

LBF_TABLE_TYPE = {
    1: "LBF_T_SEGMENTS",
    2: "LBF_T_SECTIONS",
    3: "LBF_T_RELOCS",
    4: "LBF_T_EXPORTS",
    5: "LBF_T_DEPS",
    6: "LBF_T_TLS",
    7: "LBF_T_SECURITY",
    8: "LBF_T_STRTAB",
    9: "LBF_T_IMPORTS",
    10: "LBF_T_SYMIDX",
    11: "LBF_T_SYMSTR",
}

LBF_SEG_TYPE = {
    1: "LBF_ST_CODE_RX",
    3: "LBF_ST_DATA_RW",
    4: "LBF_ST_DATA_RO",
    5: "LBF_ST_STACK_RW",
}

LBF_SEG_FLAGS = {
    0x00000001: "SHAREABLE",
    0x00000002: "INIT_ONCE",
}

LBF_SECT_KIND = {
    1: "LBF_SK_TEXT",
    2: "LBF_SK_RODATA",
    3: "LBF_SK_DATA",
    4: "LBF_SK_BSS",
    5: "LBF_SK_TLS",
    6: "LBF_SK_STUB",
    7: "LBF_SK_OTHER",
}

LBF_CONTENT_FLAGS = {
    0x00000001: "DISCARDABLE",
    0x00000002: "ZERO_INIT",
}

LBF_IMPORT_FLAGS = {
    0x00000001: "LBF_IF_BYORD",
    0x00000002: "LBF_IF_GATE",
    0x00000004: "LBF_IF_PRIVATE",
}

LBF_RELOCS_KIND = {
    1: "LBF_RELOCS_FARPTR32",
    2: "LBF_RELOCS_SEL16",
}

RELOC_FLAG_SELF_IMPORT = 0x00000001


@dataclass
class LBFHeader:
    magic: int
    version: int
    abi_major: int
    abi_minor: int
    kind: int
    machine: int
    flags: int
    entry_sel: int
    data_sel: int
    entry: int
    n_tables: int
    dir_off: int


@dataclass
class LBFDirEnt:
    type: int
    reserved: int
    offset: int
    size: int
    count: int


@dataclass
class LBFSegDesc:
    seg_index: int
    seg_type: int
    vlimit: int
    alignment: int
    sect_start: int
    sect_count: int
    flags: int


@dataclass
class LBFSection:
    name_off: int
    seg_index: int
    sect_kind: int
    file_off: int
    file_sz: int
    mem_off: int
    mem_sz: int
    align: int
    flags: int


@dataclass
class LBFDependency:
    name_off: int
    min_ver: int


@dataclass
class LBFImportDesc:
    dep_index: int
    name_off: int
    hint: int
    flags: int


@dataclass
class LBFRELOCSEntry:
    seg_index: int
    kind: int
    slot_off: int
    import_ix: int
    flags: int


@dataclass
class LBFExport:
    name_off: int
    ordinal: int
    seg_index: int
    value: int
    flags: int


@dataclass
class SymIdxPart:
    seg_index: int
    flags: int
    addrs: List[int]


@dataclass
class SymStrPart:
    seg_index: int
    flags: int
    name_offs: List[int]


@dataclass
class LBFSecurityEntry:
    alg_id: int
    data_off: int
    data_sz: int
    flags: int
    sig_bytes: bytes = field(repr=False, default=b"")


@dataclass
class LBFFile:
    filepath: Path
    data: bytes
    header: LBFHeader
    dir_entries: List[LBFDirEnt]

    segments: List[LBFSegDesc] = field(default_factory=list)
    sections: List[LBFSection] = field(default_factory=list)
    deps: List[LBFDependency] = field(default_factory=list)
    imports: List[LBFImportDesc] = field(default_factory=list)
    relocs: List[LBFRELOCSEntry] = field(default_factory=list)
    exports: List[LBFExport] = field(default_factory=list)

    strtab: bytes = b""

    symidx_parts: List[SymIdxPart] = field(default_factory=list)
    symstr_parts: List[SymStrPart] = field(default_factory=list)

    security_entries: List[LBFSecurityEntry] = field(default_factory=list)


def align_up(val: int, align: int) -> int:
    if align <= 1:
        return val
    rem = val % align
    return val if rem == 0 else (val + (align - rem))


def flags_to_names(value: int, mapping: Dict[int, str]) -> str:
    names = []
    remaining = value
    for bitmask, nm in sorted(mapping.items()):
        if value & bitmask:
            names.append(nm)
            remaining &= ~bitmask
    if remaining:
        names.append(f"0x{remaining:08X}")
    return " | ".join(names) if names else "0"


def safe_slice(data: bytes, start: int, size: int) -> bytes:
    if start < 0 or size < 0 or start + size > len(data):
        raise ValueError("Out-of-bounds slice")
    return data[start : start + size]


def hexdump(b: bytes, max_len: int = 128) -> str:
    out_lines = []
    shown = b[:max_len]
    for ofs in range(0, len(shown), 16):
        chunk = shown[ofs : ofs + 16]
        hexpart = " ".join(f"{x:02X}" for x in chunk)
        asciipart = "".join(chr(x) if 32 <= x < 127 else "." for x in chunk)
        out_lines.append(f"{ofs:04X}  {hexpart:<48} {asciipart}")
    if len(b) > max_len:
        out_lines.append(f"... ({len(b)} bytes total)")
    return "\n".join(out_lines)


def parse_header(data: bytes) -> LBFHeader:
    fmt = "<IIHHHHIHHIII"
    needed = struct.calcsize(fmt)
    if len(data) < needed:
        raise ValueError("File too small for LBFHeader")

    (
        magic,
        version,
        abi_major,
        abi_minor,
        kind,
        machine,
        flags,
        entry_sel,
        data_sel,
        entry,
        n_tables,
        dir_off,
    ) = struct.unpack_from(fmt, data, 0)

    return LBFHeader(
        magic=magic,
        version=version,
        abi_major=abi_major,
        abi_minor=abi_minor,
        kind=kind,
        machine=machine,
        flags=flags,
        entry_sel=entry_sel,
        data_sel=data_sel,
        entry=entry,
        n_tables=n_tables,
        dir_off=dir_off,
    )


def parse_dir_entries(data: bytes, hdr: LBFHeader) -> List[LBFDirEnt]:
    fmt = "<HHIII"
    entsz = struct.calcsize(fmt)
    out: List[LBFDirEnt] = []

    base = hdr.dir_off
    for i in range(hdr.n_tables):
        off = base + i * entsz
        if off + entsz > len(data):
            raise ValueError("Directory entry out of file bounds")

        (typ, reserved, toff, tsize, cnt) = struct.unpack_from(fmt, data, off)
        out.append(
            LBFDirEnt(
                type=typ,
                reserved=reserved,
                offset=toff,
                size=tsize,
                count=cnt,
            )
        )
    return out


def parse_segments(lbf: LBFFile, de: LBFDirEnt) -> List[LBFSegDesc]:
    fmt = "<HBBIIIII"
    sz = struct.calcsize(fmt)
    raw = safe_slice(lbf.data, de.offset, de.size)
    out: List[LBFSegDesc] = []
    for i in range(de.count):
        off = i * sz
        if off + sz > len(raw):
            break
        (
            seg_index,
            seg_type,
            _reserved,
            vlimit,
            alignment,
            sect_start,
            sect_count,
            flags,
        ) = struct.unpack_from(fmt, raw, off)
        out.append(
            LBFSegDesc(
                seg_index=seg_index,
                seg_type=seg_type,
                vlimit=vlimit,
                alignment=alignment,
                sect_start=sect_start,
                sect_count=sect_count,
                flags=flags,
            )
        )
    return out


def parse_sections(lbf: LBFFile, de: LBFDirEnt) -> List[LBFSection]:
    fmt = "<IHHIIIIII"
    sz = struct.calcsize(fmt)
    raw = safe_slice(lbf.data, de.offset, de.size)
    out: List[LBFSection] = []
    for i in range(de.count):
        off = i * sz
        if off + sz > len(raw):
            break
        (
            name_off,
            seg_index,
            sect_kind,
            file_off,
            file_sz,
            mem_off,
            mem_sz,
            align,
            flags,
        ) = struct.unpack_from(fmt, raw, off)
        out.append(
            LBFSection(
                name_off=name_off,
                seg_index=seg_index,
                sect_kind=sect_kind,
                file_off=file_off,
                file_sz=file_sz,
                mem_off=mem_off,
                mem_sz=mem_sz,
                align=align,
                flags=flags,
            )
        )
    return out


def parse_deps(lbf: LBFFile, de: LBFDirEnt) -> List[LBFDependency]:
    fmt = "<II"
    sz = struct.calcsize(fmt)
    raw = safe_slice(lbf.data, de.offset, de.size)
    out: List[LBFDependency] = []
    for i in range(de.count):
        off = i * sz
        if off + sz > len(raw):
            break
        (name_off, min_ver) = struct.unpack_from(fmt, raw, off)
        out.append(LBFDependency(name_off=name_off, min_ver=min_ver))
    return out


def parse_imports(lbf: LBFFile, de: LBFDirEnt) -> List[LBFImportDesc]:
    fmt = "<IIII"
    sz = struct.calcsize(fmt)
    raw = safe_slice(lbf.data, de.offset, de.size)
    out: List[LBFImportDesc] = []
    for i in range(de.count):
        off = i * sz
        if off + sz > len(raw):
            break
        (dep_index, name_off, hint, flags) = struct.unpack_from(fmt, raw, off)
        out.append(
            LBFImportDesc(
                dep_index=dep_index, name_off=name_off, hint=hint, flags=flags
            )
        )
    return out


def parse_relocs(lbf: LBFFile, de: LBFDirEnt) -> List[LBFRELOCSEntry]:
    fmt = "<HHIII"
    sz = struct.calcsize(fmt)
    raw = safe_slice(lbf.data, de.offset, de.size)
    out: List[LBFRELOCSEntry] = []
    for i in range(de.count):
        off = i * sz
        if off + sz > len(raw):
            break
        (seg_index, kind, slot_off, import_ix, flags) = struct.unpack_from(
            fmt, raw, off
        )
        out.append(
            LBFRELOCSEntry(
                seg_index=seg_index,
                kind=kind,
                slot_off=slot_off,
                import_ix=import_ix,
                flags=flags,
            )
        )
    return out


def parse_exports(lbf: LBFFile, de: LBFDirEnt) -> List[LBFExport]:
    fmt = "<IIHHII"
    sz = struct.calcsize(fmt)
    raw = safe_slice(lbf.data, de.offset, de.size)
    out: List[LBFExport] = []
    for i in range(de.count):
        off = i * sz
        if off + sz > len(raw):
            break
        (
            name_off,
            ordinal,
            seg_index,
            _reserved,
            value,
            flags,
        ) = struct.unpack_from(fmt, raw, off)
        out.append(
            LBFExport(
                name_off=name_off,
                ordinal=ordinal,
                seg_index=seg_index,
                value=value,
                flags=flags,
            )
        )
    return out


def parse_strtab(lbf: LBFFile, de: LBFDirEnt) -> bytes:
    return safe_slice(lbf.data, de.offset, de.size)


def parse_symidx(lbf: LBFFile, de: LBFDirEnt) -> List[SymIdxPart]:
    base = de.offset
    size = de.size
    raw = safe_slice(lbf.data, base, size)
    out: List[SymIdxPart] = []

    pos = 0
    hdr_fmt = "<HHII"
    hdr_sz = struct.calcsize(hdr_fmt)
    while pos + hdr_sz <= len(raw):
        seg_index, flags, part_size, next_link = struct.unpack_from(hdr_fmt, raw, pos)
        blob_start = pos + hdr_sz
        blob_end = blob_start + part_size
        if blob_end > len(raw):
            blob_end = len(raw)
        blob = raw[blob_start:blob_end]

        addrs = [t[0] for t in struct.iter_unpack("<I", blob[: (len(blob) // 4) * 4])]

        out.append(
            SymIdxPart(
                seg_index=seg_index,
                flags=flags,
                addrs=addrs,
            )
        )

        pos = align_up(blob_end, 4)
        if pos <= blob_end:
            pos = blob_end if blob_end % 4 == 0 else align_up(blob_end, 4)

        if pos >= size:
            break

    return out


def parse_symstr(lbf: LBFFile, de: LBFDirEnt) -> List[SymStrPart]:
    base = de.offset
    size = de.size
    raw = safe_slice(lbf.data, base, size)
    out: List[SymStrPart] = []

    pos = 0
    hdr_fmt = "<HHII"
    hdr_sz = struct.calcsize(hdr_fmt)
    while pos + hdr_sz <= len(raw):
        seg_index, flags, part_size, next_link = struct.unpack_from(hdr_fmt, raw, pos)
        blob_start = pos + hdr_sz
        blob_end = blob_start + part_size
        if blob_end > len(raw):
            blob_end = len(raw)
        blob = raw[blob_start:blob_end]

        name_offs = [
            t[0] for t in struct.iter_unpack("<I", blob[: (len(blob) // 4) * 4])
        ]

        out.append(
            SymStrPart(
                seg_index=seg_index,
                flags=flags,
                name_offs=name_offs,
            )
        )

        pos = align_up(blob_end, 4)
        if pos >= size:
            break

    return out


def parse_security(lbf: LBFFile, de: LBFDirEnt) -> List[LBFSecurityEntry]:
    fmt = "<IIII"
    header_sz = struct.calcsize(fmt)

    raw = safe_slice(lbf.data, de.offset, de.size)

    if len(raw) < header_sz:
        return []

    (alg_id, data_off, data_sz, flags) = struct.unpack_from(fmt, raw, 0)

    sig = b""
    if 0 <= data_off <= len(raw) and data_off + data_sz <= len(raw):
        sig = raw[data_off : data_off + data_sz]

    entry = LBFSecurityEntry(
        alg_id=alg_id,
        data_off=data_off,
        data_sz=data_sz,
        flags=flags,
        sig_bytes=sig,
    )

    return [entry]


def build_lbf(filepath: Path, debug: bool = False) -> LBFFile:
    data = filepath.read_bytes()

    if debug:
        print(f"[build_lbf] reading {filepath} ({len(data)} bytes)")

    header = parse_header(data)
    if debug:
        print("[build_lbf] parsed header OK")
        print(pretty_header(header))
        print()

    if header.magic != LBF_MAGIC:
        raise ValueError(f"Bad magic 0x{header.magic:08X}, expected 0x{LBF_MAGIC:08X}")

    dir_entries = parse_dir_entries(data, header)
    if debug:
        print("[build_lbf] parsed directory entries OK")
        for i, de in enumerate(dir_entries):
            tname = LBF_TABLE_TYPE.get(de.type, f"UNKNOWN({de.type})")
            print(
                f"  dir[{i}]: type={de.type}({tname}) off=0x{de.offset:08X} "
                f"size={de.size} count={de.count}"
            )
        print()

    lbf = LBFFile(
        filepath=filepath,
        data=data,
        header=header,
        dir_entries=dir_entries,
    )

    for i, de in enumerate(dir_entries):
        tname = LBF_TABLE_TYPE.get(de.type, f"UNKNOWN({de.type})")
        if debug:
            print(
                f"[build_lbf] parsing table {i}: {tname} "
                f"(type={de.type}) off=0x{de.offset:08X} size={de.size} count={de.count}"
            )

        if de.offset + de.size > len(data):
            if debug:
                print("  -> SKIP: table goes past EOF?")
            continue

        if de.type == 1:
            lbf.segments = parse_segments(lbf, de)
            if debug:
                print(f"  parsed {len(lbf.segments)} segment(s)")

        elif de.type == 2:
            lbf.sections = parse_sections(lbf, de)
            if debug:
                print(f"  parsed {len(lbf.sections)} section(s)")

        elif de.type == 5:
            lbf.deps = parse_deps(lbf, de)
            if debug:
                print(f"  parsed {len(lbf.deps)} dep(s)")

        elif de.type == 9:
            lbf.imports = parse_imports(lbf, de)
            if debug:
                print(f"  parsed {len(lbf.imports)} import(s)")

        elif de.type == 3:
            lbf.relocs = parse_relocs(lbf, de)
            if debug:
                print(f"  parsed {len(lbf.relocs)} reloc slot(s)")

        elif de.type == 4:
            lbf.exports = parse_exports(lbf, de)
            if debug:
                print(f"  parsed {len(lbf.exports)} export(s)")

        elif de.type == 8:
            lbf.strtab = parse_strtab(lbf, de)
            if debug:
                print(f"  parsed strtab ({len(lbf.strtab)} bytes)")

        elif de.type == 10:
            lbf.symidx_parts = parse_symidx(lbf, de)
            if debug:
                print(f"  parsed {len(lbf.symidx_parts)} symidx part(s)")

        elif de.type == 11:
            lbf.symstr_parts = parse_symstr(lbf, de)
            if debug:
                print(f"  parsed {len(lbf.symstr_parts)} symstr part(s)")

        elif de.type == 7:
            lbf.security_entries = parse_security(lbf, de)
            if debug:
                print(f"  parsed {len(lbf.security_entries)} security entr(y/ies)")

        else:
            if debug:
                print("  -> unhandled table type, ignoring")

        if debug:
            print()

    return lbf


def pretty_header(h: LBFHeader) -> str:
    lines = []
    lines.append("== LBFHeader ==")
    lines.append(f"magic       : 0x{h.magic:08X}")
    lines.append(f"version     : {h.version}")
    lines.append(f"abi         : {h.abi_major}.{h.abi_minor}")
    lines.append(f"kind        : {h.kind} ({LBF_KIND.get(h.kind, '???')})")
    lines.append(f"machine     : {h.machine} ({LBF_MACHINE.get(h.machine, '???')})")
    lines.append(
        f"flags       : 0x{h.flags:08X} [{flags_to_names(h.flags, LBF_HEADER_FLAGS)}]"
    )
    lines.append(f"entry_sel   : {h.entry_sel}")
    lines.append(f"data_sel    : {h.data_sel}")
    lines.append(f"entry (ofs) : 0x{h.entry:08X}")
    lines.append(f"n_tables    : {h.n_tables}")
    lines.append(f"dir_off     : 0x{h.dir_off:08X}")
    return "\n".join(lines)


def pretty_dirents(lbf: LBFFile) -> str:
    lines = []
    lines.append("== Table Directory ==")
    for i, de in enumerate(lbf.dir_entries):
        lines.append(f"[{i}] type={de.type} ({LBF_TABLE_TYPE.get(de.type,'???')})")
        lines.append(f"    reserved : 0x{de.reserved:04X}")
        lines.append(f"    offset   : 0x{de.offset:08X}")
        lines.append(f"    size     : 0x{de.size:08X} ({de.size} bytes)")
        lines.append(f"    count    : {de.count}")
    return "\n".join(lines)


def pretty_segment(seg: LBFSegDesc) -> str:
    return (
        "== Segment ==\n"
        f"seg_index   : {seg.seg_index}\n"
        f"type        : {seg.seg_type} ({LBF_SEG_TYPE.get(seg.seg_type, '???')})\n"
        f"vlimit      : 0x{seg.vlimit:08X} ({seg.vlimit} bytes)\n"
        f"alignment   : {seg.alignment}\n"
        f"sect_start  : {seg.sect_start}\n"
        f"sect_count  : {seg.sect_count}\n"
        f"flags       : 0x{seg.flags:08X} [{flags_to_names(seg.flags, LBF_SEG_FLAGS)}]\n"
    )


def pretty_section(sec: LBFSection, getstr) -> str:
    nm = getstr(sec.name_off)
    return (
        "== Section ==\n"
        f"name_off    : 0x{sec.name_off:08X} '{nm}'\n"
        f"seg_index   : {sec.seg_index}\n"
        f"sect_kind   : {sec.sect_kind} ({LBF_SECT_KIND.get(sec.sect_kind, '???')})\n"
        f"file_off    : 0x{sec.file_off:08X}\n"
        f"file_sz     : 0x{sec.file_sz:08X} ({sec.file_sz} bytes)\n"
        f"mem_off     : 0x{sec.mem_off:08X}\n"
        f"mem_sz      : 0x{sec.mem_sz:08X} ({sec.mem_sz} bytes)\n"
        f"align       : {sec.align}\n"
        f"flags       : 0x{sec.flags:08X} [{flags_to_names(sec.flags, LBF_CONTENT_FLAGS)}]\n"
    )


def pretty_dep(ix: int, dep: LBFDependency, getstr) -> str:
    name = getstr(dep.name_off)
    return (
        "== Dependency ==\n"
        f"index       : {ix}\n"
        f"name_off    : 0x{dep.name_off:08X} '{name}'\n"
        f"min_ver     : {dep.min_ver}\n"
    )


def pretty_import(
    ix: int, imp: LBFImportDesc, getstr, deps: List[LBFDependency]
) -> str:
    dep_name = "<bad dep>"
    if 0 <= imp.dep_index < len(deps):
        dep_name = getstr(deps[imp.dep_index].name_off)
    sym_name = getstr(imp.name_off) if imp.name_off != 0 else "<by ordinal>"
    return (
        "== Import ==\n"
        f"index       : {ix}\n"
        f"dep_index   : {imp.dep_index} ('{dep_name}')\n"
        f"name_off    : 0x{imp.name_off:08X} '{sym_name}'\n"
        f"hint        : {imp.hint}  (ordinal if BYORD)\n"
        f"flags       : 0x{imp.flags:08X} [{flags_to_names(imp.flags, LBF_IMPORT_FLAGS)}]\n"
    )


def pretty_reloc(ix: int, rel: LBFRELOCSEntry) -> str:
    if rel.flags & RELOC_FLAG_SELF_IMPORT:
        mode = "SELF_IMPORT"
        target_desc = (
            f"seg_ordinal={rel.import_ix & 0xFFFF} "
        )
    else:
        mode = "EXTERNAL IMPORT"
        target_desc = f"imports[{rel.import_ix}]"

    return (
        "== Reloc Slot ==\n"
        f"index       : {ix}\n"
        f"seg_index   : {rel.seg_index}\n"
        f"kind        : {rel.kind} ({LBF_RELOCS_KIND.get(rel.kind, '???')})\n"
        f"slot_off    : 0x{rel.slot_off:08X}\n"
        f"import_ix   : {rel.import_ix} ({target_desc})\n"
        f"flags       : 0x{rel.flags:08X} ({mode})\n"
    )


def pretty_export(ix: int, ex: LBFExport, getstr) -> str:
    nm = getstr(ex.name_off) if ex.name_off != 0 else "<no name>"
    return (
        "== Export ==\n"
        f"index       : {ix}\n"
        f"name_off    : 0x{ex.name_off:08X} '{nm}'\n"
        f"ordinal     : {ex.ordinal}\n"
        f"seg_index   : {ex.seg_index}\n"
        f"value(off)  : 0x{ex.value:08X}\n"
        f"flags       : 0x{ex.flags:08X}\n"
    )


def pretty_strtab_preview(strtab: bytes) -> str:
    lines = []
    lines.append("== STRTAB ==")
    lines.append(f"total size: {len(strtab)} bytes")

    max_strings = 20
    off = 0
    count = 0
    while off < len(strtab) and count < max_strings:
        end = strtab.find(b"\x00", off)
        if end == -1:
            end = len(strtab)
        raw = strtab[off:end]
        try:
            s = raw.decode("utf-8", errors="replace")
        except Exception:
            s = "<decode error>"
        lines.append(f"[0x{off:08X}] '{s}'")
        off = end + 1
        count += 1
    if off < len(strtab):
        lines.append("... (truncated)")
    lines.append("\nHexdump preview:")
    lines.append(hexdump(strtab))
    return "\n".join(lines)


def pretty_symidx_part(ix: int, part: SymIdxPart) -> str:
    lines = []
    lines.append("== SYMIDX Part ==")
    lines.append(f"part #{ix}")
    lines.append(f"seg_index : {part.seg_index}")
    lines.append(f"flags     : 0x{part.flags:08X}")
    lines.append("symbol addresses (offsets within seg), sorted:")
    for j, addr in enumerate(part.addrs):
        lines.append(f"  [{j}] 0x{addr:08X}")
    return "\n".join(lines)


def pretty_symstr_part(ix: int, part: SymStrPart, getstr) -> str:
    lines = []
    lines.append("== SYMSTR Part ==")
    lines.append(f"part #{ix}")
    lines.append(f"seg_index : {part.seg_index}")
    lines.append(f"flags     : 0x{part.flags:08X}")
    lines.append("symbol names (via STRTAB offsets):")
    for j, off in enumerate(part.name_offs):
        lines.append(f"  [{j}] off=0x{off:08X} '{getstr(off)}'")
    return "\n".join(lines)


def pretty_security_entry(ix: int, sec: LBFSecurityEntry) -> str:
    lines = []
    lines.append("== SECURITY Entry ==")
    lines.append(f"index     : {ix}")
    lines.append(f"alg_id    : 0x{sec.alg_id:08X}")
    lines.append(f"data_off  : 0x{sec.data_off:08X}")
    lines.append(f"data_sz   : {sec.data_sz} bytes")
    lines.append(f"flags     : 0x{sec.flags:08X}")
    lines.append("signature preview:")
    lines.append(hexdump(sec.sig_bytes))
    return "\n".join(lines)


def make_getstr(strtab: bytes):
    def getstr(off: int) -> str:
        if off < 0 or off >= len(strtab):
            return f"<bad str off {off}>"
        end = strtab.find(b"\x00", off)
        if end == -1:
            end = len(strtab)
        return strtab[off:end].decode("utf-8", errors="replace")

    return getstr


def build_text_report(lbf: LBFFile) -> str:
    lines: List[str] = []

    getstr = make_getstr(lbf.strtab)

    lines.append(pretty_header(lbf.header))
    lines.append("")
    lines.append(pretty_dirents(lbf))
    lines.append("")

    if lbf.segments:
        for seg in lbf.segments:
            lines.append(pretty_segment(seg))
            lines.append("")

    if lbf.sections:
        for sec in lbf.sections:
            lines.append(pretty_section(sec, getstr))
            lines.append("")

    if lbf.deps:
        for ix, dep in enumerate(lbf.deps):
            lines.append(pretty_dep(ix, dep, getstr))
            lines.append("")

    if lbf.imports:
        for ix, imp in enumerate(lbf.imports):
            lines.append(pretty_import(ix, imp, getstr, lbf.deps))
            lines.append("")

    if lbf.relocs:
        for ix, rel in enumerate(lbf.relocs):
            lines.append(pretty_reloc(ix, rel))
            lines.append("")

    if lbf.exports:
        for ix, ex in enumerate(lbf.exports):
            lines.append(pretty_export(ix, ex, getstr))
            lines.append("")

    if lbf.strtab:
        lines.append(pretty_strtab_preview(lbf.strtab))
        lines.append("")

    if lbf.symidx_parts:
        for ix, part in enumerate(lbf.symidx_parts):
            lines.append(pretty_symidx_part(ix, part))
            lines.append("")

    if lbf.symstr_parts:
        for ix, part in enumerate(lbf.symstr_parts):
            lines.append(pretty_symstr_part(ix, part, getstr))
            lines.append("")

    if lbf.security_entries:
        for ix, sec in enumerate(lbf.security_entries):
            lines.append(pretty_security_entry(ix, sec))
            lines.append("")

    return "\n".join(lines)


class LBFViewerApp(tk.Tk):
    def __init__(self, initial_file: Optional[Path] = None):
        super().__init__()
        self.title("LBF Viewer (binfmt v1.0)")
        self.geometry("1000x600")

        self.lbf: Optional[LBFFile] = None
        self.node_text: Dict[str, str] = {}

        menubar = tk.Menu(self)
        filemenu = tk.Menu(menubar, tearoff=False)
        filemenu.add_command(label="Open...", command=self.cmd_open_file)
        filemenu.add_separator()
        filemenu.add_command(label="Quit", command=self.destroy)
        menubar.add_cascade(label="File", menu=filemenu)
        self.config(menu=menubar)

        paned = ttk.Panedwindow(self, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True)

        left_frame = ttk.Frame(paned)
        paned.add(left_frame, weight=1)

        self.tree = ttk.Treeview(left_frame, show="tree")
        yscroll = ttk.Scrollbar(left_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=yscroll.set)

        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        yscroll.pack(side=tk.RIGHT, fill=tk.Y)

        self.tree.bind("<<TreeviewSelect>>", self.on_tree_select)

        right_frame = ttk.Frame(paned)
        paned.add(right_frame, weight=3)

        self.text = tk.Text(right_frame, wrap="word", font=("Courier", 10))
        self.text.configure(state="disabled")
        yscroll2 = ttk.Scrollbar(
            right_frame, orient=tk.VERTICAL, command=self.text.yview
        )
        self.text.configure(yscrollcommand=yscroll2.set)

        self.text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        yscroll2.pack(side=tk.RIGHT, fill=tk.Y)

        if initial_file:
            self.load_file(initial_file)

    def cmd_open_file(self):
        fn = filedialog.askopenfilename(
            title="Open LBF file",
            filetypes=[
                ("LAOMB binaries", "*.bin *.drv *.dl"),
                ("All files", "*.*"),
            ],
        )
        if not fn:
            return
        self.load_file(Path(fn))

    def on_tree_select(self, event=None):
        sel = self.tree.selection()
        if not sel:
            return
        item_id = sel[0]
        txt = self.node_text.get(item_id, "")
        self.set_text(txt)

    def set_text(self, content: str):
        self.text.configure(state="normal")
        self.text.delete("1.0", tk.END)
        self.text.insert("1.0", content)
        self.text.configure(state="disabled")

    def clear_tree(self):
        for item in self.tree.get_children(""):
            self.tree.delete(item)
        self.node_text.clear()

    def load_file(self, path: Path):
        try:
            lbf = build_lbf(path)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to parse:\n{e}")
            return

        self.lbf = lbf
        self.title(f"LBF Viewer - {path.name}")

        self.populate_tree()

    def add_node(
        self, parent: str, label: str, detail_text: str, open_node=False
    ) -> str:
        iid = self.tree.insert(parent, "end", text=label, open=open_node)
        self.node_text[iid] = detail_text
        return iid

    def populate_tree(self):
        self.clear_tree()
        if not self.lbf:
            return

        lbf = self.lbf
        getstr = make_getstr(lbf.strtab)

        root_label = f"{lbf.filepath.name}"
        root_txt = pretty_header(lbf.header) + "\n\n" + pretty_dirents(lbf)
        root_id = self.add_node("", root_label, root_txt, open_node=True)

        hdr_id = self.add_node(root_id, "Header", pretty_header(lbf.header))

        dir_id = self.add_node(
            root_id, "Table Directory", pretty_dirents(lbf), open_node=True
        )

        if lbf.segments:
            seg_root_txt = "SEGMENTS table\n" + f"{len(lbf.segments)} segment(s)"
            seg_root_id = self.add_node(
                dir_id, f"SEGMENTS ({len(lbf.segments)})", seg_root_txt, open_node=False
            )
            for seg in lbf.segments:
                label = f"seg[{seg.seg_index}] {LBF_SEG_TYPE.get(seg.seg_type,'???')}"
                text = pretty_segment(seg)
                self.add_node(seg_root_id, label, text)

        if lbf.sections:
            sec_root_txt = "SECTIONS table\n" + f"{len(lbf.sections)} section(s)"
            sec_root_id = self.add_node(
                dir_id, f"SECTIONS ({len(lbf.sections)})", sec_root_txt, open_node=False
            )
            for idx, sec in enumerate(lbf.sections):
                label = f"sect[{idx}] {getstr(sec.name_off)}"
                text = pretty_section(sec, getstr)
                self.add_node(sec_root_id, label, text)

        if lbf.deps:
            deps_root_txt = "DEPS table\n" + f"{len(lbf.deps)} dep(s)"
            deps_root_id = self.add_node(
                dir_id, f"DEPS ({len(lbf.deps)})", deps_root_txt, open_node=False
            )
            for ix, dep in enumerate(lbf.deps):
                label = f"dep[{ix}] {getstr(dep.name_off)}"
                text = pretty_dep(ix, dep, getstr)
                self.add_node(deps_root_id, label, text)

        if lbf.imports:
            imps_root_txt = "IMPORTS table\n" + f"{len(lbf.imports)} import(s)"
            imps_root_id = self.add_node(
                dir_id, f"IMPORTS ({len(lbf.imports)})", imps_root_txt, open_node=False
            )
            for ix, imp in enumerate(lbf.imports):
                imp_name = (
                    getstr(imp.name_off) if imp.name_off != 0 else f"ord:{imp.hint}"
                )
                label = f"imp[{ix}] {imp_name}"
                text = pretty_import(ix, imp, getstr, lbf.deps)
                self.add_node(imps_root_id, label, text)

        if lbf.relocs:
            rel_root_txt = "RELOCS table\n" + f"{len(lbf.relocs)} reloc slot(s)"
            rel_root_id = self.add_node(
                dir_id, f"RELOCS ({len(lbf.relocs)})", rel_root_txt, open_node=False
            )
            for ix, rel in enumerate(lbf.relocs):
                label = f"rel[{ix}] seg{rel.seg_index}@0x{rel.slot_off:08X}"
                text = pretty_reloc(ix, rel)
                self.add_node(rel_root_id, label, text)

        if lbf.exports:
            exp_root_txt = "EXPORTS table\n" + f"{len(lbf.exports)} export(s)"
            exp_root_id = self.add_node(
                dir_id, f"EXPORTS ({len(lbf.exports)})", exp_root_txt, open_node=False
            )
            for ix, ex in enumerate(lbf.exports):
                nm = getstr(ex.name_off) if ex.name_off != 0 else f"ord:{ex.ordinal}"
                label = f"exp[{ix}] {nm}"
                text = pretty_export(ix, ex, getstr)
                self.add_node(exp_root_id, label, text)

        if lbf.strtab:
            st_txt = pretty_strtab_preview(lbf.strtab)
            self.add_node(
                dir_id, f"STRTAB ({len(lbf.strtab)} bytes)", st_txt, open_node=False
            )

        if lbf.symidx_parts:
            si_root_txt = "SYMIDX table\n" + f"{len(lbf.symidx_parts)} part(s)"
            si_root_id = self.add_node(
                dir_id,
                f"SYMIDX ({len(lbf.symidx_parts)} parts)",
                si_root_txt,
                open_node=False,
            )
            for ix, part in enumerate(lbf.symidx_parts):
                label = f"symidx_part[{ix}] seg{part.seg_index}"
                text = pretty_symidx_part(ix, part)
                self.add_node(si_root_id, label, text)

        if lbf.symstr_parts:
            ss_root_txt = "SYMSTR table\n" + f"{len(lbf.symstr_parts)} part(s)"
            ss_root_id = self.add_node(
                dir_id,
                f"SYMSTR ({len(lbf.symstr_parts)} parts)",
                ss_root_txt,
                open_node=False,
            )
            for ix, part in enumerate(lbf.symstr_parts):
                label = f"symstr_part[{ix}] seg{part.seg_index}"
                text = pretty_symstr_part(ix, part, getstr)
                self.add_node(ss_root_id, label, text)

        if lbf.security_entries:
            sec_root_txt = "SECURITY table (signature block)"
            sec_root_id = self.add_node(
                dir_id,
                "SECURITY",
                sec_root_txt,
                open_node=False,
            )
            for ix, sec in enumerate(lbf.security_entries):
                label = f"alg=0x{sec.alg_id:08X}, {sec.data_sz} bytes"
                text = pretty_security_entry(ix, sec)
                self.add_node(sec_root_id, label, text)


        self.tree.selection_set(root_id)
        self.on_tree_select()


def main():
    parser = argparse.ArgumentParser(
        description="LBF Viewer / Dumper (LAOMB binfmt v1.0)"
    )
    parser.add_argument(
        "--text",
        action="store_true",
        help="Parse FILE, dump debug info while parsing, then print full report to stdout (no GUI).",
    )
    parser.add_argument(
        "file",
        nargs="?",
        help="LBF file to open (for --text mode or initial GUI load)",
    )

    args = parser.parse_args()

    if args.text:
        if not args.file:
            parser.error("FILE required in --text mode")
        p = Path(args.file)
        try:
            lbf = build_lbf(p, debug=True)
        except Exception as e:
            print(f"[ERROR] Failed to parse: {e}", file=sys.stderr)
            sys.exit(1)

        print()
        print("===== FINAL STRUCTURED DUMP =====")
        print(build_text_report(lbf))
        return

    initial: Optional[Path] = Path(args.file) if args.file else None
    app = LBFViewerApp(initial_file=initial)
    app.mainloop()


if __name__ == "__main__":
    main()
