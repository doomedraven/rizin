// SPDX-FileCopyrightText: 2025 KarlisS <karlis3p70l1ij@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include "../unit/minunit.h"
#include "rz_analysis.h"
#include "rz_config.h"
#include "rz_types_base.h"

/**
 * Test the function analysis on >64K function.
 */
static bool test_analysis_fcn_large() {
	RzCore *core = rz_core_new();
	mu_assert_notnull(core, "init core");
	RzCoreFile *cf = rz_core_file_open(core, "malloc://240000", RZ_PERM_RWX, 0);
	mu_assert_notnull(cf, "open 0 file");
	rz_core_bin_load(core, NULL, 0);
	rz_config_set(core->config, "asm.arch", "x86");
	rz_config_set_i(core->config, "asm.bits", 64);

	rz_core_analysis_fcn(core, 0, -1, RZ_ANALYSIS_XREF_TYPE_NULL, 5);

	RzAnalysisFunction *f = rz_analysis_get_function_at(core->analysis, 0);
	mu_assert_notnull(f, "Function not found");

	// no point in rest of test if some sanity check limited function size smaller than this
	mu_assert_eq(rz_analysis_function_linear_size(f), 240000, "function cut short");

	mu_assert_eq(rz_core_prevop_addr_force(core, 0x22202, 1), 0x22200, "Prev not working");

	ut64 end = 0;
	RzAnalysisBlock *block = rz_analysis_fcn_bbget_at(core->analysis, f, 0);
	while (block) {
		end = RZ_MAX(end, block->addr + block->size);
		if (block->jump != UT64_MAX) {
			mu_assert_eq(block->jump, block->addr + block->size, "blocks aren't chained");
			block = rz_analysis_fcn_bbget_at(core->analysis, f, block->jump);
		} else {
			block = NULL;
		}
	}
	mu_assert_eq(end, 240000, "Blocks don't cover whole function");

	rz_core_free(core);
	mu_end;
}

static bool always_valid(RzIO *io, ut64 addr, int r) {
	return true;
}

static bool test_analysis_xrefs_comment() {
	RzCore *core = rz_core_new();
	mu_assert_notnull(core, "rz_core_new failed");

	mu_assert_notnull(rz_core_file_open(core, "malloc://1024", RZ_PERM_RWX, 0), "file open failed");

	RzAnalysis *analysis = core->analysis;
	mu_assert_notnull(analysis, "analysis is null");
	RzIOBind *iob = rz_analysis_get_io_bind(analysis);
	iob->is_valid_offset = always_valid;

	mu_assert_true(rz_analysis_set_bits(analysis, 64), "set bits failed");
	mu_assert_true(rz_analysis_use(analysis, "x86"), "use x86 failed");

	RzAnalysisFunction *f_src = rz_analysis_create_function(analysis, "src_fcn", 0x100, RZ_ANALYSIS_FCN_TYPE_FCN);
	mu_assert_notnull(f_src, "create src function");
	ut64 target = 0x200;

	rz_analysis_xrefs_set(analysis, 0x100, target, RZ_ANALYSIS_XREF_TYPE_CODE);
	char *res = rz_core_get_xref_comment(core, target);
	mu_assert_streq(res, "; CODE XREF from src_fcn @ ", "xref prefix failed");
	free(res);

	rz_analysis_xrefs_set(analysis, 0x102, target, RZ_ANALYSIS_XREF_TYPE_CODE);
	res = rz_core_get_xref_comment(core, target);
	mu_assert_streq(res, "; CODE XREFS from src_fcn @ , +0x2", "xref join failed");
	free(res);

	rz_analysis_xrefs_set(analysis, 0x104, target, RZ_ANALYSIS_XREF_TYPE_CODE);
	rz_config_set_i(core->config, "asm.xrefs.max", 2);
	res = rz_core_get_xref_comment(core, target);
	mu_assert_streq(res, "; XREFS(3)", "asm.xrefs.max failed");
	free(res);

	rz_config_set_i(core->config, "asm.xrefs.max", 10);
	rz_config_set_i(core->config, "asm.xrefs.fold", 2);

	res = rz_core_get_xref_comment(core, target);
	const char *exp = "; XREFS: CODE 0x00000100  CODE 0x00000102  CODE 0x00000104  ";
	mu_assert_streq(res, exp, "asm.xrefs.fold failed");
	free(res);

	rz_core_free(core);
	mu_end;
}

static bool test_af_function_range_bounds(void) {
	/* 1. Real PE64 (.pdata): standalone af @ 0x140001310 clamps tail-jmp to 0x140001329
	 *    while still recursing into direct callees and restoring unset analysis limits. */
	RzCore *core = rz_core_new();
	mu_assert_notnull(core, "rz_core_new");
	RzCoreFile *f = rz_core_file_open(core, "bins/pe/seh_x64.exe", RZ_PERM_R, 0);
	mu_assert_notnull(f, "open bins/pe/seh_x64.exe");
	mu_assert_true(rz_core_bin_load(core, NULL, UT64_MAX), "load bins/pe/seh_x64.exe");

	RzBinFile *bf = rz_bin_cur(core->bin);
	mu_assert_notnull(bf, "cur binfile");
	const RzPVector *franges = rz_bin_file_get_function_ranges(bf);
	mu_assert_notnull(franges, "function ranges vector");
	mu_assert_eq(rz_pvector_len(franges), 31, "31 .pdata ranges");
	for (size_t i = 1; i < rz_pvector_len(franges); i++) {
		const RzBinFunctionRange *prev = rz_pvector_at(franges, i - 1);
		const RzBinFunctionRange *curr = rz_pvector_at(franges, i);
		mu_assert_true(prev->start <= curr->start, "function ranges sorted by start");
	}

	/* Entry 7 [0x140001310, 0x140001329): calls 0x1400019d4 and tail-jmps 0x140001ce4 */
	rz_core_analysis_fcn(core, 0x140001310ULL, UT64_MAX, RZ_ANALYSIS_XREF_TYPE_NULL, 4);
	RzAnalysisFunction *fcn = rz_analysis_get_function_at(core->analysis, 0x140001310ULL);
	mu_assert_notnull(fcn, "af creates function at 0x140001310");
	mu_assert_true(rz_analysis_function_max_addr(fcn) <= 0x140001329ULL,
		"standalone af clamps tail-jmp function to fr->end");
	mu_assert_notnull(rz_analysis_get_function_at(core->analysis, 0x1400019d4ULL),
		"standalone af restores limits before recursing into direct callee");
	mu_assert_false(rz_analysis_has_valid_limits(core->analysis),
		"analysis limits restored to unset after af");

	/* Entry 4 [0x1400011f0, 0x140001245): calls unlisted leaf function at 0x140001000 */
	rz_core_analysis_fcn(core, 0x1400011f0ULL, UT64_MAX, RZ_ANALYSIS_XREF_TYPE_NULL, 4);
	RzAnalysisFunction *fcn4 = rz_analysis_get_function_at(core->analysis, 0x1400011f0ULL);
	mu_assert_notnull(fcn4, "af creates function at 0x1400011f0");
	mu_assert_true(rz_analysis_function_max_addr(fcn4) <= 0x140001245ULL,
		"entry 4 bounded by fr->end");
	mu_assert_notnull(rz_analysis_get_function_at(core->analysis, 0x140001000ULL),
		"standalone af recurses into unlisted leaf callee");

	/* 2. Tighter user analysis.limits is honored and restored */
	rz_analysis_function_delete_all(core->analysis);
	rz_analysis_set_limits(core->analysis, 0x140001310ULL, 0x14000131eULL);
	rz_core_analysis_fcn(core, 0x140001310ULL, UT64_MAX, RZ_ANALYSIS_XREF_TYPE_NULL, 1);
	fcn = rz_analysis_get_function_at(core->analysis, 0x140001310ULL);
	mu_assert_notnull(fcn, "af with tighter user limits");
	mu_assert_true(rz_analysis_function_max_addr(fcn) <= 0x14000131eULL,
		"tighter user limit honored");
	ut64 lim_from = 0, lim_to = 0;
	rz_analysis_get_limits(core->analysis, &lim_from, &lim_to);
	mu_assert_eq(lim_from, 0x140001310ULL, "tighter user limit from restored");
	mu_assert_eq(lim_to, 0x14000131eULL, "tighter user limit to restored");

	/* Wider user analysis.limits is tightened to fr->end during af and restored afterward */
	rz_analysis_function_delete_all(core->analysis);
	rz_analysis_set_limits(core->analysis, 0x140000000ULL, 0x140005000ULL);
	rz_core_analysis_fcn(core, 0x140001310ULL, UT64_MAX, RZ_ANALYSIS_XREF_TYPE_NULL, 1);
	fcn = rz_analysis_get_function_at(core->analysis, 0x140001310ULL);
	mu_assert_notnull(fcn, "af with wider user limits");
	mu_assert_true(rz_analysis_function_max_addr(fcn) <= 0x140001329ULL,
		"wider user limit tightened to fr->end");
	rz_analysis_get_limits(core->analysis, &lim_from, &lim_to);
	mu_assert_eq(lim_from, 0x140000000ULL, "wider user limit from restored");
	mu_assert_eq(lim_to, 0x140005000ULL, "wider user limit to restored");

	/* Out-of-range user analysis.limits rejects af */
	rz_analysis_function_delete_all(core->analysis);
	rz_analysis_set_limits(core->analysis, 0x140002000ULL, 0x140003000ULL);
	rz_core_analysis_fcn(core, 0x140001310ULL, UT64_MAX, RZ_ANALYSIS_XREF_TYPE_NULL, 1);
	mu_assert_null(rz_analysis_get_function_at(core->analysis, 0x140001310ULL),
		"out-of-range user limit rejects af");
	rz_core_free(core);

	/* 3. io.va=false with shifted base clamps standalone af @ paddr 0x710 to <= 0x729 */
	core = rz_core_new();
	rz_config_set_b(core->config, "io.va", false);
	f = rz_core_file_open(core, "bins/pe/seh_x64.exe", RZ_PERM_R, 0);
	mu_assert_notnull(f, "open bins/pe/seh_x64.exe for io.va=false");
	mu_assert_true(rz_core_bin_load(core, NULL, 0x200000000ULL),
		"load seh_x64.exe shifted base io.va=false");
	rz_core_analysis_fcn(core, 0x710, UT64_MAX, RZ_ANALYSIS_XREF_TYPE_NULL, 1);
	fcn = rz_analysis_get_function_at(core->analysis, 0x710);
	mu_assert_notnull(fcn, "af creates entry 7 in io.va=false");
	mu_assert_true(rz_analysis_function_max_addr(fcn) <= 0x729,
		"io.va=false af clamps entry 7 to paddr end");
	rz_core_free(core);

	/* 4. Unsorted .pdata entries in real PE64 (via io.pcache.write swap) are sorted on load */
	core = rz_core_new();
	rz_config_set_b(core->config, "io.pcache.write", true);
	f = rz_core_file_open(core, "bins/pe/seh_x64.exe", RZ_PERM_R, 0);
	mu_assert_notnull(f, "open bins/pe/seh_x64.exe for unsorted .pdata check");
	ut8 pdata_pair[24] = { 0 };
	mu_assert_true(rz_io_pread_at(core->io, 0x2400, pdata_pair, sizeof(pdata_pair)),
		"read first two .pdata entries");
	ut8 swapped[24];
	memcpy(swapped, pdata_pair + 12, 12);
	memcpy(swapped + 12, pdata_pair, 12);
	mu_assert_true(rz_io_pwrite_at(core->io, 0x2400, swapped, sizeof(swapped)),
		"swap first two .pdata entries in pcache");
	mu_assert_true(rz_core_bin_load(core, NULL, UT64_MAX),
		"load seh_x64.exe with swapped .pdata");
	bf = rz_bin_cur(core->bin);
	franges = rz_bin_file_get_function_ranges(bf);
	mu_assert_notnull(franges, "sorted function ranges after swap");
	mu_assert_eq(rz_pvector_len(franges), 31, "31 sorted ranges after swap");
	const RzBinFunctionRange *fr0 = rz_pvector_at(franges, 0);
	const RzBinFunctionRange *fr1 = rz_pvector_at(franges, 1);
	mu_assert_eq(fr0->start, 0x140001010ULL, "sorted range 0 start");
	mu_assert_eq(fr1->start, 0x1400010b0ULL, "sorted range 1 start");
	rz_core_free(core);
	mu_end;
}

bool all_tests() {
	mu_run_test(test_analysis_fcn_large);
	mu_run_test(test_analysis_xrefs_comment);
	mu_run_test(test_af_function_range_bounds);
	return tests_passed != tests_run;
}

mu_main(all_tests)
