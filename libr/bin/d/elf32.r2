pfo elf_enums.r2
pf.elf_ident [4]z[1]E[1]E[1]E.:: magic (enum elf_class)class (enum elf_data)data (enum elf_hdr_version)version
pf.elf_header ?[2]E[2]E[4]ExxxxN2N2N2N2N2N2 (elf_ident)ident (enum elf_type)type (enum elf_machine)machine (enum elf_obj_version)version entry phoff shoff flags ehsize phentsize phnum shentsize shnum shstrndx
pf.elf_phdr [4]Exxxxx[4]Ex (enum elf_p_type)type offset vaddr paddr filesz memsz (enum elf_p_flags)flags align
pf.elf_shdr x[4]E[4]Exxxxxxx name (enum elf_s_type)type (enum elf_s_flags_32)flags addr offset size link info addralign entsize
