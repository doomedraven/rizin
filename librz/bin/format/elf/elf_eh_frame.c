// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"
#include <rz_util/ht_uu.h>

#define DW_EH_PE_absptr   0x00
#define DW_EH_PE_uleb128  0x01
#define DW_EH_PE_udata2   0x02
#define DW_EH_PE_udata4   0x03
#define DW_EH_PE_udata8   0x04
#define DW_EH_PE_sleb128  0x09
#define DW_EH_PE_sdata2   0x0a
#define DW_EH_PE_sdata4   0x0b
#define DW_EH_PE_sdata8   0x0c
#define DW_EH_PE_pcrel    0x10
#define DW_EH_PE_textrel  0x20
#define DW_EH_PE_datarel  0x30
#define DW_EH_PE_aligned  0x50
#define DW_EH_PE_indirect 0x80
#define DW_EH_PE_omit     0xff

typedef struct {
	ELFOBJ *bin;
	ut8 default_addr_size;
	ut64 text_vaddr;
	ut64 datarel_vaddr;
	bool big_endian;
} EhFrameCtx;

static bool read_uleb128_bounded(const ut8 *data, size_t *pos, size_t end, ut64 *out) {
	ut64 val = 0;
	unsigned int shift = 0;
	while (*pos < end) {
		ut8 b = data[(*pos)++];
		if (shift >= 64 || (shift == 63 && (b & 0x7e))) {
			return false;
		}
		val |= (ut64)(b & 0x7f) << shift;
		if (!(b & 0x80)) {
			if (out) {
				*out = val;
			}
			return true;
		}
		shift += 7;
	}
	return false;
}

static bool read_sleb128_bounded(const ut8 *data, size_t *pos, size_t end, st64 *out) {
	ut64 val = 0;
	unsigned int shift = 0;
	ut8 b = 0;
	while (*pos < end) {
		b = data[(*pos)++];
		if (shift >= 64) {
			return false;
		}
		val |= (ut64)(b & 0x7f) << shift;
		shift += 7;
		if (!(b & 0x80)) {
			if (shift < 64 && (b & 0x40)) {
				val |= (~0ULL) << shift;
			}
			if (out) {
				*out = (st64)val;
			}
			return true;
		}
	}
	return false;
}

static bool read_eh_raw(const ut8 *data, size_t *pos, size_t end, ut8 fmt, ut8 addr_size, bool be, ut64 *out) {
	size_t p = *pos;
	switch (fmt) {
	case DW_EH_PE_absptr:
		if (addr_size == 4) {
			if (p + 4 > end) {
				return false;
			}
			*out = rz_read_ble32(data + p, be);
			*pos = p + 4;
			return true;
		}
		if (addr_size == 8) {
			if (p + 8 > end) {
				return false;
			}
			*out = rz_read_ble64(data + p, be);
			*pos = p + 8;
			return true;
		}
		return false;
	case DW_EH_PE_uleb128:
		return read_uleb128_bounded(data, pos, end, out);
	case DW_EH_PE_udata2:
		if (p + 2 > end) {
			return false;
		}
		*out = rz_read_ble16(data + p, be);
		*pos = p + 2;
		return true;
	case DW_EH_PE_udata4:
		if (p + 4 > end) {
			return false;
		}
		*out = rz_read_ble32(data + p, be);
		*pos = p + 4;
		return true;
	case DW_EH_PE_udata8:
		if (p + 8 > end) {
			return false;
		}
		*out = rz_read_ble64(data + p, be);
		*pos = p + 8;
		return true;
	case DW_EH_PE_sleb128: {
		st64 sv = 0;
		if (!read_sleb128_bounded(data, pos, end, &sv)) {
			return false;
		}
		*out = (ut64)sv;
		return true;
	}
	case DW_EH_PE_sdata2:
		if (p + 2 > end) {
			return false;
		}
		*out = (ut64)(st64)(st16)rz_read_ble16(data + p, be);
		*pos = p + 2;
		return true;
	case DW_EH_PE_sdata4:
		if (p + 4 > end) {
			return false;
		}
		*out = (ut64)(st64)(st32)rz_read_ble32(data + p, be);
		*pos = p + 4;
		return true;
	case DW_EH_PE_sdata8:
		if (p + 8 > end) {
			return false;
		}
		*out = rz_read_ble64(data + p, be);
		*pos = p + 8;
		return true;
	default:
		return false;
	}
}

static bool read_eh_ptr(const EhFrameCtx *ctx, const ut8 *data, size_t *pos, size_t end, ut8 enc, ut8 addr_size, ut64 field_vaddr, ut64 datarel_base, ut64 *out) {
	if (enc == DW_EH_PE_omit) {
		return false;
	}
	ut8 fmt = enc & 0x0f;
	ut8 app = enc & 0x70;
	if (app == DW_EH_PE_aligned) {
		if (!addr_size) {
			return false;
		}
		size_t rem = *pos % addr_size;
		if (rem) {
			size_t pad = addr_size - rem;
			if (*pos + pad > end) {
				return false;
			}
			*pos += pad;
		}
		field_vaddr += rem ? (addr_size - rem) : 0;
	}
	ut64 raw = 0;
	if (!read_eh_raw(data, pos, end, fmt, addr_size, ctx->big_endian, &raw)) {
		return false;
	}
	if (!out) {
		return true;
	}
	ut64 val = 0;
	switch (app) {
	case DW_EH_PE_absptr:
	case DW_EH_PE_aligned:
		val = raw;
		break;
	case DW_EH_PE_pcrel:
		val = field_vaddr + raw;
		if (addr_size == 4) {
			val &= UT32_MAX;
		}
		break;
	case DW_EH_PE_textrel:
		if (ctx->text_vaddr == UT64_MAX) {
			return false;
		}
		val = ctx->text_vaddr + raw;
		if (addr_size == 4) {
			val &= UT32_MAX;
		}
		break;
	case DW_EH_PE_datarel:
		if (datarel_base == UT64_MAX) {
			return false;
		}
		val = datarel_base + raw;
		if (addr_size == 4) {
			val &= UT32_MAX;
		}
		break;
	default:
		return false;
	}
	if (enc & DW_EH_PE_indirect) {
		ut64 paddr = Elf_(rz_bin_elf_v2p)(ctx->bin, val);
		if (paddr == UT64_MAX) {
			return false;
		}
		if (addr_size == 4) {
			ut32 v32 = 0;
			if (!rz_buf_read_ble32_at(ctx->bin->b, paddr, &v32, ctx->big_endian)) {
				return false;
			}
			val = v32;
		} else if (addr_size == 8) {
			ut64 v64 = 0;
			if (!rz_buf_read_ble64_at(ctx->bin->b, paddr, &v64, ctx->big_endian)) {
				return false;
			}
			val = v64;
		} else {
			return false;
		}
	}
	if (out) {
		*out = val;
	}
	return true;
}

static bool is_plt_section(const RzBinElfSection *sec) {
	if (!sec) {
		return false;
	}
	if (sec->type == RZ_BIN_ELF_SECTION_TYPE_PLT) {
		return true;
	}
	if (!sec->name) {
		return false;
	}
	return !strcmp(sec->name, ".plt") ||
		!strcmp(sec->name, ".plt.got") ||
		!strcmp(sec->name, ".plt.sec") ||
		!strcmp(sec->name, ".iplt") ||
		!strcmp(sec->name, ".MIPS.stubs");
}

static bool is_valid_elf_code_range(ELFOBJ *bin, ut64 start, ut64 end, bool has_exec_sections) {
	if (has_exec_sections) {
		RzBinElfSection *sec;
		rz_bin_elf_foreach_sections(bin, sec) {
			if (!sec->is_valid || sec->rva == UT64_MAX || !sec->size) {
				continue;
			}
			if (!(sec->flags & SHF_EXECINSTR)) {
				continue;
			}
			if (UT64_ADD_OVFCHK(sec->rva, sec->size)) {
				continue;
			}
			if (start >= sec->rva && start < sec->rva + sec->size) {
				if (is_plt_section(sec)) {
					return false;
				}
				return end <= sec->rva + sec->size;
			}
		}
		return false;
	}

	RzBinElfSegment *seg;
	rz_bin_elf_foreach_segments(bin, seg) {
		if (!seg->is_valid || seg->data.p_type != PT_LOAD || !(seg->data.p_flags & PF_X) || !seg->data.p_memsz) {
			continue;
		}
		ut64 seg_start = seg->data.p_vaddr;
		if (UT64_ADD_OVFCHK(seg_start, seg->data.p_memsz)) {
			continue;
		}
		ut64 seg_end = seg_start + seg->data.p_memsz;
		if (start >= seg_start && end <= seg_end) {
			return true;
		}
	}
	return false;
}

static bool locate_eh_frame_from_phdr(const EhFrameCtx *ctx, ut64 buf_size, ut64 *eh_paddr, ut64 *eh_vaddr, ut64 *eh_size) {
	ELFOBJ *bin = ctx->bin;
	RzBinElfSegment *hdr_seg = Elf_(rz_bin_elf_get_segment_with_type)(bin, PT_GNU_EH_FRAME);
	if (!hdr_seg || !hdr_seg->is_valid || hdr_seg->data.p_filesz < 4 || hdr_seg->data.p_offset >= buf_size) {
		return false;
	}
	ut64 hdr_avail = RZ_MIN(hdr_seg->data.p_filesz, buf_size - hdr_seg->data.p_offset);
	size_t hdr_read_sz = (size_t)RZ_MIN(hdr_avail, (ut64)32);
	ut8 hdr[32] = { 0 };
	if (rz_buf_read_at(bin->b, hdr_seg->data.p_offset, hdr, hdr_read_sz) != (st64)hdr_read_sz) {
		return false;
	}
	if (hdr[0] != 1) {
		return false;
	}
	ut8 eh_frame_ptr_enc = hdr[1];
	size_t pos = 4;
	ut64 frame_vaddr = 0;
	if (!read_eh_ptr(ctx, hdr, &pos, hdr_read_sz, eh_frame_ptr_enc, ctx->default_addr_size, hdr_seg->data.p_vaddr + 4, hdr_seg->data.p_vaddr, &frame_vaddr)) {
		return false;
	}
	ut64 frame_paddr = Elf_(rz_bin_elf_v2p)(bin, frame_vaddr);
	if (frame_paddr == UT64_MAX || frame_paddr >= buf_size) {
		return false;
	}
	RzBinElfSegment *seg;
	rz_bin_elf_foreach_segments(bin, seg) {
		if (!seg->is_valid || seg->data.p_type != PT_LOAD || !seg->data.p_filesz) {
			continue;
		}
		if (UT64_ADD_OVFCHK(seg->data.p_offset, seg->data.p_filesz)) {
			continue;
		}
		ut64 seg_file_end = RZ_MIN(buf_size, seg->data.p_offset + seg->data.p_filesz);
		if (frame_paddr >= seg->data.p_offset && frame_paddr < seg_file_end) {
			*eh_paddr = frame_paddr;
			*eh_vaddr = frame_vaddr;
			*eh_size = seg_file_end - frame_paddr;
			return *eh_size >= 4;
		}
	}
	return false;
}

static bool parse_cie_entry(const EhFrameCtx *ctx, const ut8 *data, size_t content_start, size_t rec_end, ut64 eh_vaddr, ut8 *out_fde_enc, ut8 *out_addr_size) {
	size_t pos = content_start + 4;
	if (pos >= rec_end) {
		return false;
	}
	ut8 version = data[pos++];
	if (version != 1 && version != 3 && version != 4) {
		return false;
	}
	size_t aug_start = pos;
	while (pos < rec_end && data[pos] != '\0') {
		pos++;
	}
	if (pos >= rec_end) {
		return false;
	}
	const char *aug = (const char *)(data + aug_start);
	pos++; /* NUL terminator */

	ut8 addr_size = ctx->default_addr_size;
	if (version >= 4) {
		if (pos + 2 > rec_end) {
			return false;
		}
		addr_size = data[pos++];
		pos++; /* segment_selector_size */
		if (addr_size != 4 && addr_size != 8) {
			return false;
		}
	}

	/* code_alignment_factor (ULEB128) and data_alignment_factor (SLEB128) */
	if (!read_uleb128_bounded(data, &pos, rec_end, NULL) ||
		!read_sleb128_bounded(data, &pos, rec_end, NULL)) {
		return false;
	}
	/* return_address_register */
	if (version == 1) {
		if (pos >= rec_end) {
			return false;
		}
		pos++;
	} else {
		if (!read_uleb128_bounded(data, &pos, rec_end, NULL)) {
			return false;
		}
	}

	ut8 fde_enc = DW_EH_PE_absptr;
	if (aug[0] == 'z') {
		ut64 aug_len = 0;
		if (!read_uleb128_bounded(data, &pos, rec_end, &aug_len) ||
			aug_len > rec_end - pos) {
			return false;
		}
		size_t aug_end = pos + (size_t)aug_len;
		for (const char *p = aug + 1; *p && pos <= aug_end; p++) {
			switch (*p) {
			case 'L':
				if (pos >= aug_end) {
					return false;
				}
				pos++;
				break;
			case 'P': {
				if (pos >= aug_end) {
					return false;
				}
				ut8 pers_enc = data[pos++];
				if (pers_enc != DW_EH_PE_omit &&
					!read_eh_ptr(ctx, data, &pos, aug_end, pers_enc, addr_size, eh_vaddr + pos, ctx->datarel_vaddr, NULL)) {
					return false;
				}
				break;
			}
			case 'R':
				if (pos >= aug_end) {
					return false;
				}
				fde_enc = data[pos++];
				break;
			case 'S':
			case 'B':
			case 'G':
				break;
			default:
				/* Unknown augmentation letter: stop parsing augmentation data */
				pos = aug_end;
				break;
			}
		}
	}

	*out_fde_enc = fde_enc;
	*out_addr_size = addr_size;
	return true;
}

/**
 * \brief Extract function address ranges from ELF `.eh_frame` (or `PT_GNU_EH_FRAME` fallback).
 *
 * \param bf Binary file
 * \return Owned vector of RzBinFunctionRange pointers, or NULL if unavailable
 */
RZ_OWN RzPVector /*<RzBinFunctionRange *>*/ *Elf_(rz_bin_elf_get_function_ranges)(RZ_NONNULL RzBinFile *bf) {
	if (!bf || !bf->o || !bf->o->bin_obj) {
		return NULL;
	}
	ELFOBJ *bin = bf->o->bin_obj;
	if (!bin->b || Elf_(rz_bin_elf_is_relocatable)(bin) || bin->ehdr.e_type == ET_CORE) {
		return NULL;
	}

	ut64 buf_size = rz_buf_size(bin->b);
	if (buf_size < 4) {
		return NULL;
	}

	EhFrameCtx ctx = {
		.bin = bin,
		.default_addr_size = (bin->ehdr.e_ident[EI_CLASS] == ELFCLASS64) ? 8 : 4,
		.text_vaddr = UT64_MAX,
		.datarel_vaddr = UT64_MAX,
		.big_endian = bin->big_endian,
	};

	bool has_exec_sections = false;
	RzBinElfSection *sec;
	rz_bin_elf_foreach_sections(bin, sec) {
		if (!sec->is_valid || sec->rva == UT64_MAX || !sec->size) {
			continue;
		}
		if (sec->flags & SHF_EXECINSTR) {
			has_exec_sections = true;
		}
		if (sec->name) {
			if (!strcmp(sec->name, ".text") && ctx.text_vaddr == UT64_MAX) {
				ctx.text_vaddr = sec->rva;
			} else if ((!strcmp(sec->name, ".got.plt") || !strcmp(sec->name, ".got")) && ctx.datarel_vaddr == UT64_MAX) {
				ctx.datarel_vaddr = sec->rva;
			}
		}
	}
	if (ctx.datarel_vaddr == UT64_MAX) {
		ut64 got_addr = 0;
		if (Elf_(rz_bin_elf_get_dt_info)(bin, DT_PLTGOT, &got_addr)) {
			ctx.datarel_vaddr = got_addr;
		}
	}

	ut64 eh_paddr = UT64_MAX;
	ut64 eh_vaddr = UT64_MAX;
	ut64 eh_size = 0;
	RzBinElfSection *eh_sec = Elf_(rz_bin_elf_get_section_with_name)(bin, ".eh_frame");
	if (eh_sec && eh_sec->type != SHT_NOBITS && eh_sec->rva != UT64_MAX && eh_sec->size >= 4 && eh_sec->offset < buf_size) {
		eh_paddr = eh_sec->offset;
		eh_vaddr = eh_sec->rva;
		eh_size = RZ_MIN(eh_sec->size, buf_size - eh_paddr);
	} else if (!locate_eh_frame_from_phdr(&ctx, buf_size, &eh_paddr, &eh_vaddr, &eh_size)) {
		return NULL;
	}

	if (eh_size < 4 || eh_size > SIZE_MAX) {
		return NULL;
	}
	ut8 *data = malloc((size_t)eh_size);
	if (!data) {
		return NULL;
	}
	if (rz_buf_read_at(bin->b, eh_paddr, data, (size_t)eh_size) != (st64)eh_size) {
		free(data);
		return NULL;
	}

	RzPVector /*<RzBinFunctionRange *>*/ *res = rz_pvector_new((RzPVectorFree)rz_bin_function_range_free);
	HtUU *cie_map = ht_uu_new();
	if (!res || !cie_map) {
		rz_pvector_free(res);
		ht_uu_free(cie_map);
		free(data);
		return NULL;
	}

	bool thumb_capable = Elf_(rz_bin_elf_is_arm_binary_supporting_thumb)(bin);
	size_t total = (size_t)eh_size;
	size_t rec_off = 0;

	while (rec_off + 4 <= total) {
		ut32 len32 = rz_read_ble32(data + rec_off, ctx.big_endian);
		if (!len32) {
			break;
		}
		size_t content_start = 0;
		ut64 rec_len = 0;
		if (len32 == UT32_MAX) {
			if (rec_off + 12 > total) {
				break;
			}
			rec_len = rz_read_ble64(data + rec_off + 4, ctx.big_endian);
			content_start = rec_off + 12;
		} else {
			rec_len = len32;
			content_start = rec_off + 4;
		}
		if (rec_len < 4 || rec_len > total - content_start) {
			break;
		}
		size_t rec_end = content_start + (size_t)rec_len;
		ut32 cie_id = rz_read_ble32(data + content_start, ctx.big_endian);

		if (cie_id == 0) {
			ut8 fde_enc = DW_EH_PE_absptr;
			ut8 addr_size = ctx.default_addr_size;
			if (parse_cie_entry(&ctx, data, content_start, rec_end, eh_vaddr, &fde_enc, &addr_size)) {
				ht_uu_update(cie_map, rec_off, ((ut64)addr_size << 8) | fde_enc);
			}
		} else if (cie_id <= content_start) {
			ut64 cie_off = content_start - cie_id;
			bool found = false;
			ut64 packed = ht_uu_find(cie_map, cie_off, &found);
			if (found) {
				ut8 fde_enc = (ut8)(packed & 0xff);
				ut8 addr_size = (ut8)((packed >> 8) & 0xff);
				size_t pos = content_start + 4;
				ut64 pc_begin = 0;
				ut64 pc_range = 0;
				if (read_eh_ptr(&ctx, data, &pos, rec_end, fde_enc, addr_size, eh_vaddr + pos, ctx.datarel_vaddr, &pc_begin) &&
					read_eh_raw(data, &pos, rec_end, fde_enc & 0x0f, addr_size, ctx.big_endian, &pc_range) &&
					pc_begin && pc_range && !UT64_ADD_OVFCHK(pc_begin, pc_range)) {
					if (thumb_capable && (pc_begin & 1)) {
						pc_begin &= ~1ULL;
					}
					ut64 pc_end = pc_begin + pc_range;
					if (is_valid_elf_code_range(bin, pc_begin, pc_end, has_exec_sections)) {
						ut64 start = rz_bin_object_addr_with_base(bf->o, pc_begin);
						ut64 end = rz_bin_object_addr_with_base(bf->o, pc_end);
						if (end > start) {
							RzBinFunctionRange *fr = rz_bin_function_range_new(start, end);
							if (!fr) {
								break;
							}
							if (!rz_pvector_push(res, fr)) {
								rz_bin_function_range_free(fr);
								break;
							}
						}
					}
				}
			}
		}
		rec_off = rec_end;
	}

	ht_uu_free(cie_map);
	free(data);
	return res;
}
