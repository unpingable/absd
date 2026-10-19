# Licensing

ABSD's own source (the kernel, the platform, the tools and the tests written
for it) is licensed under the **Apache License, Version 2.0**. The text is in
`LICENSE`, and in `LICENSES/Apache-2.0.txt` in each component.

Not everything in this tree is ABSD's own:

- Third-party files carried in the tree keep their own licences. They are
  listed in `THIRD-PARTY.md`, which is generated from the `provenance.toml`
  record in each component (the per-file record of what applies to what);
  licence texts are in each component's `LICENSES/` directory or beside the
  files.
- Libraries downloaded at build time keep theirs. Each component lists them
  per built image under `provenance/inventory/`.
- `docs/rc1/notices/` carries verbatim third-party notice texts separately
  from ABSD's license: Picolibc's complete copyright aggregate, FreeBSD's
  `if_em.c` BSD-2-Clause notice, libm's LICENSE and retained per-file notices,
  and the LLVM compiler-rt notice/Apache text. TEXT-PROVENANCE.json records
  exact upstream identities and extraction scope. This directory also
  contains ABSD's generated inventory and correspondence receipts.

The boot images the build produces also contain GRUB (GPL-3.0-or-later) and a
font from the host's GRUB package. The source tree does not carry them; a
built image does, and redistributing an image carries GRUB's obligations.

Files written for ABSD carry no licence header and no copyright line yet;
`provenance.toml` and `REUSE.toml` in each component are the record. ABSD was
written largely by AI coding agents directed by one developer. What copyright
subsists in such code is an open legal question, and the licence grant does
not settle it.
