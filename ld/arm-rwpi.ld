/*
 * Phoenix-RTOS
 *
 * Linker script for Rust (ROPI/RWPI) programs on MMU-less ARM targets
 *
 * Copyright 2026 Phoenix Systems
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*
 * LLVM's RWPI reaches data as r9 + R_ARM_SBREL32 offset, which lld resolves
 * against the start of the read-write LOAD segment. The kernel sets r9 to the
 * ELF's .got (hal_cpuSetGot()), so there must be a single read-write segment
 * (explicit PHDRS, no RELRO) that begins with .got.
 *
 * Segments must not overlap: process_relocate() finds a segment by address.
 */

ENTRY(_start)

PHDRS
{
	text   PT_LOAD FLAGS(5);           /* R E */
	data   PT_LOAD FLAGS(6);           /* RW  */
	tls    PT_TLS;
	exidx  0x70000001;                 /* PT_ARM_EXIDX */
}

SECTIONS
{
	/* gcc/GNU ld layout, but with .got first in the read-write segment */
	. = 0x1000;

	.init : { KEEP(*(.init)) } :text
	.text : { *(.text .text.*) } :text
	.fini : { KEEP(*(.fini)) } :text

	/* process_load() skips LOAD segments that are neither PF_X nor PF_W */
	.rodata : { *(.rodata .rodata.*) } :text
	.ARM.exidx : { *(.ARM.exidx .ARM.exidx.*) } :text :exidx
	.ARM.extab : { *(.ARM.extab*) } :text
	.eh_frame_hdr : { *(.eh_frame_hdr) } :text
	.eh_frame : { *(.eh_frame) } :text

	. = ALIGN(0x1000);

	.got : { *(.got) *(.got.plt) } :data

	/*
	 * Align TLS to 8 at both ends (.tdata is 4-aligned, .tbss 8-aligned):
	 * - start: thread-pointer offsets assume an 8-aligned segment, but the
	 *   kernel copies the image from .tdata's actual address,
	 * - end: the kernel sizes the block as tdata_sz + tbss_sz, so a gap
	 *   between them would leave the tail of .tbss unzeroed.
	 * The kernel assumes p_align <= 8 (tp = tls_base - 8).
	 */
	.tdata : ALIGN(8) { *(.tdata .tdata.*) . = ALIGN(8); } :data :tls
	.tbss  : { *(.tbss .tbss.*) *(.tcommon) } :data :tls

	.init_array : {
		*(SORT_BY_INIT_PRIORITY(.init_array.*))
		*(.init_array)
	} :data
	.fini_array : {
		*(SORT_BY_INIT_PRIORITY(.fini_array.*))
		*(.fini_array)
	} :data

	.data.rel.ro : { *(.data.rel.ro .data.rel.ro.*) } :data
	.data : { *(.data .data.*) } :data
	.bss : { *(.bss .bss.*) *(COMMON) } :data

	/DISCARD/ : { *(.note.GNU-stack) *(.gnu_debuglink) }
}
