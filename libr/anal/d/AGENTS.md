# Analysis data directory

This directory contains `k=v` source files for code analysis and type propagation, compiled into SDB databases and optionally generated C sources.

## Source and generator navigation

- `spec.sdb.txt` maps format modifiers such as `%p`, `%d` and `%s` to types for type propagation.
- `types.sdb.txt` defines basic C-like types.
- Target-specific `types-*.sdb.txt` files provide additional type definitions, including structs and enums; examples include `types-linux.sdb.txt` and `types-x86-windows-32.sdb.txt`.
- `cc-${arch}-${bits}.sdb.txt` files define calling conventions, including the `dlang` entries in `cc-x86-64.sdb.txt`.
- `windows/` contains source fragments combined into generated `types-windows.sdb.txt`.
- `Makefile` concatenates the Windows fragments and invokes `sdb -r .` to generate the databases, installed under the versioned `fcnsign` data directory.
- `meson.build` lists the database inputs and Windows fragments, generates the databases, and includes generated C sources when `sdb_cgen` is enabled.

Actual C tags use `tags/NAME`, `tags/struct.NAME`, `tags/union.NAME` or `tags/enum.NAME` query paths in serialized source records. The host loader places those records in the existing SDB `tags` child map. Ordinary typedefs and named analysis records remain in the parent map; source references to tags retain their explicit C tag spelling. Do not infer a tag or add a typedef from a record's display name. The shared APIs in `libr/util/utype.c` and `libr/anal/type.c` own lookup, replacement, deletion and serialization.

## dlang calling convention example

- narg = 1: edi
- narg = 2: esi, edi
- narg = 3: edx, esi, edi
- narg = 4: ecx, edx, esi, edi
- narg = 5: r8d, ecx, edx, esi, edi
- narg = 6: r9d, r8d, ecx, edx, esi, edi
- narg = 7: push, r9d, r8d, ecx, edx, esi, edi

```asm
mov     R9D,1
mov     R8D,2
mov     ECX,3
mov     EDX,4
mov     ESI,5
mov     EDI,6

mov     R8D,1
mov     ECX,2
mov     EDX,3
mov     ESI,4
mov     EDI,5

push    1
push    2
mov     R9D,3
mov     R8D,4
mov     ECX,5
mov     EDX,6
mov     ESI,7
mov     EDI,8
call      int example.square(int, int, int, int, int, int, int, int)@PLT32
add     RSP,010h
```
