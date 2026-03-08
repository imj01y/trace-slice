use trace_slice::scanner;
use trace_slice::slicer;
use trace_slice::types::RegId;

fn fixture_path(name: &str) -> String {
    format!("{}/tests/fixtures/{}", env!("CARGO_MANIFEST_DIR"), name)
}

fn run_slice(fixture: &str, target_reg: RegId, data_only: bool) -> Vec<usize> {
    let path = fixture_path(fixture);
    let trace =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("failed to read {}: {}", path, e));
    let state = scanner::scan_from_string(&trace, data_only).unwrap();
    let start = vec![*state
        .reg_last_def
        .get(&target_reg)
        .unwrap_or_else(|| panic!("{:?} not found in trace", target_reg))];
    let marked = slicer::bfs_slice(&state, &start);
    marked
        .iter()
        .enumerate()
        .filter(|(_, b)| **b)
        .map(|(i, _)| i)
        .collect()
}

#[test]
fn test_basic_chain_full_slice() {
    let marked = run_slice("basic_chain.trace", RegId::X0, false);
    assert_eq!(marked, vec![0, 1, 2, 3, 4]);
}

#[test]
fn test_dead_code_excluded() {
    let marked = run_slice("dead_code.trace", RegId::X0, false);
    assert_eq!(marked, vec![0, 3]);
}

#[test]
fn test_control_dep_included() {
    let marked = run_slice("control_dep.trace", RegId::X0, false);
    assert_eq!(marked, vec![0, 1, 2, 3]);
}

#[test]
fn test_control_dep_excluded_data_only() {
    let marked = run_slice("control_dep.trace", RegId::X0, true);
    assert_eq!(marked, vec![3]);
}

// =========================================================================
// Part A: batch 2a-2b integration tests
// =========================================================================

#[test]
fn test_alu_flags_csel_nzcv_chain() {
    // adds → nzcv → csel chain, dead code excluded
    let marked = run_slice("alu_flags_csel.trace", RegId::X0, false);
    assert_eq!(marked, vec![0, 1, 3]);
}

#[test]
fn test_alu_flags_csel_data_only() {
    // In data-only mode, same result (nzcv is data dep not control dep)
    let marked = run_slice("alu_flags_csel.trace", RegId::X0, true);
    assert_eq!(marked, vec![0, 1, 3]);
}

#[test]
fn test_scalar_rmw_movk_old_value() {
    // movk reads old Rd value — movz must be pulled in
    let marked = run_slice("scalar_rmw.trace", RegId::X0, false);
    assert_eq!(marked, vec![0, 1, 2]);
}

#[test]
fn test_multiply_extend_full_chain() {
    // madd 3 sources + ubfx + sxtw → full chain
    let marked = run_slice("multiply_extend.trace", RegId::X0, false);
    assert_eq!(marked, vec![0, 1, 2, 3, 4, 5]);
}

// =========================================================================
// Part B: batch 2c LoadPair/StorePair integration tests
// =========================================================================

#[test]
fn test_load_store_pair_mem_dependency() {
    // stp → ldp via memory dependency, with pre-index writeback
    // x0 ← x1 (ldp half1) ← stp half1 (x29) ← mov x29. x30 (half2) excluded.
    let marked = run_slice("load_store_pair.trace", RegId::X0, false);
    assert_eq!(marked, vec![0, 2, 3, 4]);
}

#[test]
fn test_load_store_pair_second_reg() {
    // Slice on x3 (second register of ldp half2) → stp half2 (x30) → mov x30. x29 excluded.
    let marked = run_slice("load_store_pair.trace", RegId::X3, false);
    assert_eq!(marked, vec![1, 2, 3]);
}

#[test]
fn test_vector_pair_full_chain() {
    // Vector stp/ldp q → umov extraction, data-only
    // x0 ← umov v2 (ldp half1) ← stp half1 (q0) ← movi v0. movi v1 (half2) excluded.
    let marked = run_slice("vector_pair.trace", RegId::X0, true);
    assert_eq!(marked, vec![0, 2, 3, 4]);
}

// =========================================================================
// Part C: batch 2d-2g integration tests
// =========================================================================

#[test]
fn test_simd_lane_load_full_chain() {
    // ld1 lane (SimdLaneLoad RMW) → st1 → ldr (mem dep) → mov
    let marked = run_slice("simd_lane_load.trace", RegId::X0, true);
    assert_eq!(marked, vec![0, 1, 2, 3, 4]);
}

#[test]
fn test_branch_variants_data_only() {
    // data-only: cbz control dep excluded, bl irrelevant, only x9 chain
    let marked = run_slice("branch_variants.trace", RegId::X0, true);
    assert_eq!(marked, vec![3, 4]);
}

#[test]
fn test_branch_variants_with_control_dep() {
    // with control dep: cbz sets lastCondBranch, mov x9 picks it up
    let marked = run_slice("branch_variants.trace", RegId::X0, false);
    assert_eq!(marked, vec![0, 1, 3, 4]);
}

#[test]
fn test_sysreg_float_full_chain() {
    // fmov d0 → fmov d1 → fcmp (FlagSet, DEF nzcv) → fcsel (FlagUse, USE nzcv) → fmov x0
    let marked = run_slice("sysreg_float.trace", RegId::X0, true);
    assert_eq!(marked, vec![0, 1, 2, 3, 4]);
}

#[test]
fn test_simd_rmw_ins_chain() {
    // movi v0 → mov x8 → ins v0 (SimdRMW, USE v0 old + w8) → umov x0
    let marked = run_slice("simd_rmw.trace", RegId::X0, true);
    assert_eq!(marked, vec![0, 1, 2, 3]);
}

// =========================================================================
// FromSpec 扩展集成测试
// =========================================================================

#[test]
fn test_slice_with_mem_last() {
    let path = fixture_path("mem_last.trace");
    let trace = std::fs::read_to_string(&path).unwrap();
    let state = scanner::scan_from_string(&trace, true).unwrap();

    // mem 0x10 的最后写入应该是 str (line 2)
    let &(line, _) = state
        .mem_last_def
        .get(&0x10u64)
        .expect("addr 0x10 not found");
    assert_eq!(line, 2);
    let start = vec![line];

    let marked = slicer::bfs_slice(&state, &start);
    let lines: Vec<usize> = marked
        .iter()
        .enumerate()
        .filter(|(_, b)| **b)
        .map(|(i, _)| i)
        .collect();
    // str (line 2) depends on mov x8 (line 0) and mov x9 (line 1)
    assert_eq!(lines, vec![0, 1, 2]);
}

#[test]
fn test_slice_with_reg_at() {
    use std::collections::HashMap;
    use trace_slice::types::LineTarget;

    let path = fixture_path("reg_at.trace");
    let trace = std::fs::read_to_string(&path).unwrap();

    let mut targets = HashMap::new();
    targets.insert(2u32, vec![LineTarget::Reg(RegId::X0)]);

    let state = scanner::scan_from_string_with_targets(&trace, true, 0, None, &targets).unwrap();

    let start = vec![2u32];
    let marked = slicer::bfs_slice(&state, &start);
    let lines: Vec<usize> = marked
        .iter()
        .enumerate()
        .filter(|(_, b)| **b)
        .map(|(i, _)| i)
        .collect();
    // add x0 (line 2) → dep on mov x8 (line 0) + mov x9 (line 1)
    assert_eq!(lines, vec![0, 1, 2]);
}

#[test]
fn test_slice_with_seq_range() {
    let path = fixture_path("seq_range.trace");
    let trace = std::fs::read_to_string(&path).unwrap();

    let state = scanner::scan_from_string_with_range(&trace, true, 2, Some(3)).unwrap();

    // x0 last def should be line 3 (not line 4 which is out of range)
    assert_eq!(state.reg_last_def.get(&RegId::X0), Some(&3));

    let start = vec![*state.reg_last_def.get(&RegId::X0).unwrap()];
    let marked = slicer::bfs_slice(&state, &start);
    let lines: Vec<usize> = marked
        .iter()
        .enumerate()
        .filter(|(_, b)| **b)
        .map(|(i, _)| i)
        .collect();
    // x0 (line 3) depends on x10 (line 2), but x8/x9 not in range
    assert_eq!(lines, vec![2, 3]);
}

#[test]
fn test_slice_with_reg_at_fallback() {
    use std::collections::HashMap;
    use trace_slice::types::LineTarget;

    let path = fixture_path("reg_at_fallback.trace");
    let trace = std::fs::read_to_string(&path).unwrap();

    // Target x8 at line 2 (str instruction — x8 is USE not DEF)
    let mut targets = HashMap::new();
    targets.insert(2u32, vec![LineTarget::Reg(RegId::X8)]);

    let state = scanner::scan_from_string_with_targets(&trace, true, 0, None, &targets).unwrap();

    // Should resolve to line 0 (mov x8)
    let resolved = state.resolved_targets.get(&(2, LineTarget::Reg(RegId::X8)));
    assert_eq!(resolved, Some(&0), "should fall back to line 0");

    let start = vec![*resolved.unwrap()];
    let marked = slicer::bfs_slice(&state, &start);
    let lines: Vec<usize> = marked
        .iter()
        .enumerate()
        .filter(|(_, b)| **b)
        .map(|(i, _)| i)
        .collect();
    // mov x8 (line 0) has no deps, so only line 0 is marked
    assert_eq!(lines, vec![0]);
}

// =========================================================================
// 精度损失验证：ldp/stp 场景
// =========================================================================

/// Case 1 (ldp 侧): 两个独立 str 写入，ldp 读取 16B，只切片 x8（第二个寄存器）
/// 当前行为：x8 的切片会包含 str x5 和 mov x5（过近似）
/// 理想行为：只包含 str x6 + mov x6 路径
#[test]
fn test_ldp_precision_loss_separate_stores() {
    // line 0: mov x5, #0xaaaa        (IRRELEVANT — only feeds sp+0..7)
    // line 1: mov x6, #0xbbbb        (RELEVANT — feeds sp+8..15 → x8)
    // line 2: str x5, [sp]           (WRITE 8B to sp+0..7, IRRELEVANT)
    // line 3: str x6, [sp, #8]       (WRITE 8B to sp+8..15, RELEVANT)
    // line 4: ldp x9, x8, [sp]      (READ 16B: x9←sp+0..7, x8←sp+8..15)
    let marked = run_slice("ldp_precision_separate_stores.trace", RegId::X8, true);

    // Approach A: bit-tagged pair precision — ldp half2 only follows second-half mem deps
    assert_eq!(marked, vec![1, 3, 4],
        "ldp half2 should only include str x6 path, not str x5 path");
}

/// Case 2 (stp 侧): stp 写入 16B，后续 ldr 只读前 8B（x5 的部分）
/// 当前行为：stp 的 USE 包含 x5 和 x6，x6 路径被错误纳入
/// 理想行为：只包含 x5 路径
#[test]
fn test_stp_precision_loss_partial_read() {
    // line 0: mov x5, #0xaaaa        (RELEVANT — contributes to sp+0..7 → x8)
    // line 1: mov x6, #0xbbbb        (IRRELEVANT — contributes to sp+8..15)
    // line 2: stp x5, x6, [sp]       (WRITE 16B)
    // line 3: ldr x8, [sp]           (READ 8B from sp+0..7, only first half)
    let marked = run_slice("stp_precision_partial_read.trace", RegId::X8, true);

    // Approach A: bit-tagged pair precision — stp half1 only follows first source reg
    assert_eq!(marked, vec![0, 2, 3],
        "ldr reads only first half of stp, should exclude mov x6");
}

/// Case 3 (双侧): stp→ldp 全配对，只切片 x8（ldp 的第二个寄存器）
/// 同时存在 ldp 侧和 stp 侧的精度损失
#[test]
fn test_stp_ldp_precision_loss_second_reg() {
    // line 0: mov x5, #0xaaaa        (IRRELEVANT)
    // line 1: mov x6, #0xbbbb        (RELEVANT — feeds stp second half → ldp x8)
    // line 2: stp x5, x6, [sp]       (WRITE 16B)
    // line 3: ldp x9, x8, [sp]       (READ 16B: x9←first, x8←second)
    let marked = run_slice("stp_ldp_precision_second_reg.trace", RegId::X8, true);

    // Approach A: bit-tagged pair precision — ldp half2 → stp half2 → mov x6 only
    assert_eq!(marked, vec![1, 2, 3],
        "ldp x8 (half2) through stp should only include mov x6, not mov x5");
}

// =========================================================================
// 值相等性剪枝 (pass-through pruning) 集成测试
// =========================================================================

/// Pass-through: str x8 → ldr x0，值相等（0x42），地址计算链被剪
#[test]
fn test_pass_through_prunes_addr_deps() {
    // line 0: mov x8, #0x42          (data source)
    // line 1: mov x9, #addr          (address reg — should be pruned)
    // line 2: add x10, x9, #0        (address calc — should be pruned)
    // line 3: str x8, [x9]           (store x8=0x42)
    // line 4: ldr x0, [x10]          (load x0=0x42, same value → pass-through)
    let marked = run_slice("pass_through.trace", RegId::X0, true);

    // x0 ← ldr (line 4) ← str (line 3) via mem ← mov x8 (line 0), x9 (line 1)
    // LOAD's address dep (x10 → line 2) is pruned; STORE's address dep (x9 → line 1) kept
    assert_eq!(marked, vec![0, 1, 3, 4],
        "pass-through LOAD should prune its address dep (line 2) but keep STORE's addr dep (line 1)");
}

/// Non-pass-through: ldrb from a different address (init mem), address deps preserved
#[test]
fn test_non_pass_through_preserves_addr_deps() {
    // line 7: ldrb w1, [x10, #1] — reads addr 0xbffff011 from init mem (not stored)
    // Address dep on x10 should be preserved
    let path = fixture_path("pass_through.trace");
    let trace = std::fs::read_to_string(&path).unwrap();
    let state = scanner::scan_from_string(&trace, true).unwrap();
    let start = vec![*state.reg_last_def.get(&RegId(1)).unwrap()]; // x1
    let marked = slicer::bfs_slice(&state, &start);
    let lines: Vec<usize> = marked.iter().enumerate()
        .filter(|(_, b)| **b).map(|(i, _)| i).collect();

    // ldrb w1 (line 7) reads init mem, so it keeps address dep on x10 (line 2) → x9 (line 1)
    assert!(lines.contains(&7), "ldrb line should be included");
    assert!(lines.contains(&2), "address calc (add x10) should be included for init mem load");
    assert!(lines.contains(&1), "address source (mov x9) should be included");
}

/// Non-pass-through: ldr x2 from an address not matching the store → address deps preserved
#[test]
fn test_non_pass_through_different_store_preserves_deps() {
    // line 12: ldr x2, [x13] — reads from addr 0x300 which was never stored
    // This is init mem, so all deps (including address) should be preserved
    let path = fixture_path("pass_through.trace");
    let trace = std::fs::read_to_string(&path).unwrap();
    let state = scanner::scan_from_string(&trace, true).unwrap();
    let start = vec![*state.reg_last_def.get(&RegId(2)).unwrap()]; // x2
    let marked = slicer::bfs_slice(&state, &start);
    let lines: Vec<usize> = marked.iter().enumerate()
        .filter(|(_, b)| **b).map(|(i, _)| i).collect();

    // ldr x2 (line 12) from init mem → keeps x13 dep → add x13 (line 10) → x12 (line 8), x13 (line 9)
    assert!(lines.contains(&12), "ldr line should be included");
    assert!(lines.contains(&10), "address calc should be included for init mem");
}

/// Pass-through with --no-prune: address deps should NOT be pruned
#[test]
fn test_no_prune_preserves_all_deps() {
    let path = fixture_path("pass_through.trace");
    let trace = std::fs::read_to_string(&path).unwrap();
    let state = scanner::scan_pass1_bytes(
        trace.as_bytes(), true, 0, None, &Default::default(), false, true,
    ).unwrap();
    let start = vec![*state.reg_last_def.get(&RegId::X0).unwrap()]; // x0
    let marked = slicer::bfs_slice(&state, &start);
    let lines: Vec<usize> = marked.iter().enumerate()
        .filter(|(_, b)| **b).map(|(i, _)| i).collect();

    // With --no-prune, address deps on ldr x0 (line 4) should be preserved
    // x10 (line 2) → x9 (line 1) should appear
    assert!(lines.contains(&1), "with --no-prune, address source should be included");
    assert!(lines.contains(&2), "with --no-prune, address calc should be included");
}
