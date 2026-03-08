use crate::insn_class::InsnClass;
use crate::types::{Operand, ParsedLine, RegId};
use smallvec::SmallVec;

/// Determine the DEF (written) and USE (read) registers for a parsed instruction.
///
/// This function explicitly matches ALL 42 InsnClass variants with no wildcard `_ =>`
/// fallback, ensuring compile-time exhaustiveness checking. Each variant encodes a
/// unique DEF/USE pattern derived from the ARM64 ISA semantics (design doc v9).
///
/// Returns `(defs, uses)` as SmallVec with capacity 4 (covers most instructions).
pub fn determine_def_use(
    class: InsnClass,
    line: &ParsedLine,
) -> (SmallVec<[RegId; 4]>, SmallVec<[RegId; 4]>) {
    let mut defs: SmallVec<[RegId; 4]> = SmallVec::new();
    let mut uses: SmallVec<[RegId; 4]> = SmallVec::new();
    let ops = &line.operands;

    match class {
        // =====================================================================
        // Standard pure-write pattern: DEF=ops[0], USE=ops[1..]
        // Covers: ALU, Multiply, Move, Bitfield, Extend, FloatArith,
        //         SimdArith, SimdMisc, SimdMove
        // =====================================================================
        InsnClass::AluReg
        | InsnClass::AluImm
        | InsnClass::AluShift
        | InsnClass::Multiply
        | InsnClass::Move
        | InsnClass::Bitfield
        | InsnClass::Extend
        | InsnClass::FloatArith
        | InsnClass::SimdArith
        | InsnClass::SimdMisc
        | InsnClass::SimdMove => {
            if let Some(rd) = first_reg_non_zero(ops) {
                defs.push(rd);
            }
            collect_uses_from(ops, 1, &mut uses);
        }

        // =====================================================================
        // E: FlagSet — cmp, cmn, tst, fcmp, fcmpe
        // DEF=nzcv, USE=all operands (Rn, Rm or imm)
        // =====================================================================
        InsnClass::FlagSet => {
            defs.push(RegId::NZCV);
            collect_uses_from(ops, 0, &mut uses);
        }

        // =====================================================================
        // E: CondFlagSet — ccmp, ccmn, cfinv
        // DEF=nzcv, USE=nzcv + operand registers
        // =====================================================================
        InsnClass::CondFlagSet => {
            defs.push(RegId::NZCV);
            uses.push(RegId::NZCV);
            collect_uses_from(ops, 0, &mut uses);
        }

        // =====================================================================
        // F: AluFlags — adds, subs, ands, bics, negs
        // DEF=Rd + nzcv, USE=ops[1..]
        // =====================================================================
        InsnClass::AluFlags => {
            if let Some(rd) = first_reg_non_zero(ops) {
                defs.push(rd);
            }
            defs.push(RegId::NZCV);
            collect_uses_from(ops, 1, &mut uses);
        }

        // =====================================================================
        // F: FlagUse — csel, csinc, csinv, csneg, fcsel
        // F: AluCarry — adc, sbc, ngc
        // DEF=Rd, USE=ops[1..] + nzcv
        // =====================================================================
        InsnClass::FlagUse | InsnClass::AluCarry => {
            if let Some(rd) = first_reg_non_zero(ops) {
                defs.push(rd);
            }
            collect_uses_from(ops, 1, &mut uses);
            uses.push(RegId::NZCV);
        }

        // =====================================================================
        // F: AluCarryFlags — adcs, sbcs, ngcs
        // DEF=Rd + nzcv, USE=ops[1..] + nzcv
        // =====================================================================
        InsnClass::AluCarryFlags => {
            if let Some(rd) = first_reg_non_zero(ops) {
                defs.push(rd);
            }
            defs.push(RegId::NZCV);
            collect_uses_from(ops, 1, &mut uses);
            uses.push(RegId::NZCV);
        }

        // =====================================================================
        // D: ScalarRMW — movk, bfi, bfxil, bfc
        // M: SimdRMW — ins, bsl, bit, bif, mla, mls, fmov Vd.D[1]
        // DEF=Rd, USE=Rd(old) + ops[1..]
        // =====================================================================
        InsnClass::ScalarRMW | InsnClass::SimdRMW => {
            if let Some(rd) = first_reg_non_zero(ops) {
                defs.push(rd);
                uses.push(rd); // old value is a USE
            }
            collect_uses_from(ops, 1, &mut uses);
        }

        // =====================================================================
        // G: LoadReg — ldr, ldrb, ldrh, ldrsw, etc.
        // DEF=Rt [+ base if writeback], USE=base + mem
        // =====================================================================
        InsnClass::LoadReg => {
            if let Some(rt) = first_reg_non_zero(ops) {
                defs.push(rt);
            }
            collect_uses_from(ops, 1, &mut uses);
            if line.writeback {
                if let Some(base) = line.base_reg {
                    defs.push(base);
                }
            }
        }

        // =====================================================================
        // G: LoadPair — ldp, ldpsw, ldnp
        // DEF=Rt1 + Rt2 [+ base if writeback], USE=base + mem
        // =====================================================================
        InsnClass::LoadPair => {
            // First two operands are destinations
            for op in ops.iter().take(2) {
                if let Some(r) = op.as_reg().filter(|r| !r.is_zero()) {
                    defs.push(r);
                }
            }
            collect_uses_from(ops, 2, &mut uses);
            if line.writeback {
                if let Some(base) = line.base_reg {
                    defs.push(base);
                }
            }
        }

        // =====================================================================
        // H: StoreReg — str, strb, strh, stlr, etc.
        // H: StorePair — stp, stnp
        // M: SimdStore — st1, st2, str Dt/Qt, etc.
        // DEF=[base if writeback], USE=all operands
        // =====================================================================
        InsnClass::StoreReg | InsnClass::StorePair | InsnClass::SimdStore => {
            collect_uses_from(ops, 0, &mut uses);
            if line.writeback {
                if let Some(base) = line.base_reg {
                    defs.push(base);
                }
            }
        }

        // =====================================================================
        // H: StoreExcl — stxr, stlxr, stxp, stlxp
        // DEF=Ws(status reg = ops[0]), USE=ops[1..]
        // =====================================================================
        InsnClass::StoreExcl => {
            if let Some(ws) = first_reg_non_zero(ops) {
                defs.push(ws);
            }
            collect_uses_from(ops, 1, &mut uses);
        }

        // =====================================================================
        // H: AtomicLoadOp — ldadd, ldclr, ldset, ldeor, swp, etc.
        // Layout: <Xs>, <Xt>, [<Xn>]
        // DEF=Xt(ops[1], old mem value), USE=Xs(ops[0])+Xn(ops[2])
        // =====================================================================
        InsnClass::AtomicLoadOp => {
            if let Some(rt) = ops.get(1).and_then(|o| o.as_reg()).filter(|r| !r.is_zero()) {
                defs.push(rt);
            }
            if let Some(rs) = ops
                .first()
                .and_then(|o| o.as_reg())
                .filter(|r| !r.is_zero())
            {
                uses.push(rs);
            }
            if let Some(rn) = ops.get(2).and_then(|o| o.as_reg()).filter(|r| !r.is_zero()) {
                uses.push(rn);
            }
        }

        // =====================================================================
        // H: CompareAndSwap — cas, casa, casal, casl
        // Layout: <Ws>, <Wt>, [<Xn>]
        // DEF=Ws(ops[0], RMW), USE=Ws(expected)+Wt(ops[1])+Xn(ops[2])
        // =====================================================================
        InsnClass::CompareAndSwap => {
            if let Some(ws) = ops
                .first()
                .and_then(|o| o.as_reg())
                .filter(|r| !r.is_zero())
            {
                defs.push(ws);
                uses.push(ws);
            }
            if let Some(wt) = ops.get(1).and_then(|o| o.as_reg()).filter(|r| !r.is_zero()) {
                uses.push(wt);
            }
            if let Some(rn) = ops.get(2).and_then(|o| o.as_reg()).filter(|r| !r.is_zero()) {
                uses.push(rn);
            }
        }

        // =====================================================================
        // I: CondBranchNzcv — b.cond (b.eq, b.ne, etc.)
        // DEF=none, USE=nzcv
        // =====================================================================
        InsnClass::CondBranchNzcv => {
            uses.push(RegId::NZCV);
        }

        // =====================================================================
        // I: CondBranchReg — cbz, cbnz, tbz, tbnz
        // DEF=none, USE=Rt
        // =====================================================================
        InsnClass::CondBranchReg => {
            if let Some(rt) = first_reg_non_zero(ops) {
                uses.push(rt);
            }
        }

        // =====================================================================
        // J: Branch — b (unconditional)
        // No DEF/USE
        // =====================================================================
        InsnClass::Branch => {}

        // =====================================================================
        // J: BranchLink — bl
        // DEF=x30 (link register)
        // =====================================================================
        InsnClass::BranchLink => {
            defs.push(RegId::X30);
        }

        // =====================================================================
        // K: BranchReg — br
        // USE=Rn (target register)
        // =====================================================================
        InsnClass::BranchReg => {
            if let Some(rn) = first_reg_non_zero(ops) {
                uses.push(rn);
            }
        }

        // =====================================================================
        // K: BranchLinkReg — blr
        // DEF=x30, USE=Rn
        // =====================================================================
        InsnClass::BranchLinkReg => {
            defs.push(RegId::X30);
            if let Some(rn) = first_reg_non_zero(ops) {
                uses.push(rn);
            }
        }

        // =====================================================================
        // K: Return — ret
        // USE=x30 (implicit)
        // =====================================================================
        InsnClass::Return => {
            uses.push(RegId::X30);
        }

        // =====================================================================
        // Nop / Svc — no DEF/USE
        // =====================================================================
        InsnClass::Nop => {}

        // svc 的寄存器副作用从 trace 的 => 箭头数据推断
        InsnClass::Svc => {
            if let Some(ref post) = line.post_arrow_regs {
                for &(reg, _) in post.iter() {
                    if !reg.is_zero() {
                        defs.push(reg);
                    }
                }
            }
        }

        // =====================================================================
        // L2: SysRegRead — mrs Rd, sysreg
        // DEF=Rd
        // =====================================================================
        InsnClass::SysRegRead => {
            if let Some(rd) = ops.first().and_then(|o| o.as_reg()) {
                defs.push(rd);
            }
        }

        // =====================================================================
        // L2: SysRegNzcvRead — mrs Rd, nzcv
        // DEF=Rd, USE=nzcv
        // =====================================================================
        InsnClass::SysRegNzcvRead => {
            if let Some(rd) = ops.first().and_then(|o| o.as_reg()) {
                defs.push(rd);
            }
            uses.push(RegId::NZCV);
        }

        // =====================================================================
        // L2: SysRegWrite — msr sysreg, Rn
        // USE=Rn (first register operand)
        // =====================================================================
        InsnClass::SysRegWrite => {
            if let Some(rn) = ops.first().and_then(|o| o.as_reg()) {
                uses.push(rn);
            }
        }

        // =====================================================================
        // L2: SysRegNzcvWrite — msr nzcv, Rn
        // DEF=nzcv, USE=Rn
        // =====================================================================
        InsnClass::SysRegNzcvWrite => {
            defs.push(RegId::NZCV);
            if let Some(rn) = ops.first().and_then(|o| o.as_reg()) {
                uses.push(rn);
            }
        }

        // =====================================================================
        // M: SimdLoad — ld1 full, ld2, ldr Dt/Qt, etc.
        // DEF=Vt [+ base if writeback], USE=base registers
        // =====================================================================
        InsnClass::SimdLoad => {
            // base_reg 之前的操作数全部作为 DEF（支持多寄存器 ld1 {v0, v1, ...}）
            // 当 base_reg 未设置时，回退到旧行为：仅 ops[0] 为 DEF
            if let Some(base) = line.base_reg {
                for op in ops.iter() {
                    if let Some(r) = op.as_reg() {
                        if r == base {
                            break;
                        }
                        defs.push(r);
                    }
                }
                // base_reg 作为 USE
                uses.push(base);
            } else {
                // 回退：无 base_reg 时，仅第一个寄存器为 DEF，其余为 USE
                if let Some(vt) = ops.first().and_then(|o| o.as_reg()) {
                    defs.push(vt);
                }
                collect_uses_from(ops, 1, &mut uses);
            }
            // writeback: base_reg 也是 DEF
            if line.writeback {
                if let Some(base) = line.base_reg {
                    defs.push(base);
                }
            }
        }

        // =====================================================================
        // M: SimdLaneLoad — ld1 lane load (read-modify-write)
        // DEF=Vt [+ base if writeback], USE=Vt(old) + base + mem
        // =====================================================================
        InsnClass::SimdLaneLoad => {
            if let Some(vt) = ops.first().and_then(|o| o.as_reg()) {
                defs.push(vt);
                uses.push(vt); // old value is a USE (read-modify-write)
            }
            collect_uses_from(ops, 1, &mut uses);
            if line.writeback {
                if let Some(base) = line.base_reg {
                    defs.push(base);
                }
            }
        }
    }

    (defs, uses)
}

/// Extract the first operand's RegId, filtering out xzr.
fn first_reg_non_zero(ops: &[Operand]) -> Option<RegId> {
    ops.first()
        .and_then(|o| o.as_reg())
        .filter(|r| !r.is_zero())
}

/// Collect register USEs from ops[start..], filtering out xzr and immediates.
fn collect_uses_from(ops: &[Operand], start: usize, uses: &mut SmallVec<[RegId; 4]>) {
    for op in ops.iter().skip(start) {
        if let Some(r) = op.as_reg().filter(|r| !r.is_zero()) {
            uses.push(r);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::insn_class::InsnClass;
    use crate::types::*;

    /// Helper to build a ParsedLine from a slice of Operands.
    fn make_line(ops: &[Operand]) -> ParsedLine {
        ParsedLine {
            mnemonic: Mnemonic::default(),
            operands: ops.iter().cloned().collect(),
            mem_op: None,
            has_arrow: true,
            base_reg: None,
            writeback: false,
            lane_index: None,
            pre_arrow_regs: None,
            post_arrow_regs: None,
        }
    }

    /// Helper to build a ParsedLine with writeback and base_reg set.
    fn make_line_wb(ops: &[Operand], base: RegId) -> ParsedLine {
        ParsedLine {
            mnemonic: Mnemonic::default(),
            operands: ops.iter().cloned().collect(),
            mem_op: None,
            has_arrow: true,
            base_reg: Some(base),
            writeback: true,
            lane_index: None,
            pre_arrow_regs: None,
            post_arrow_regs: None,
        }
    }

    // =========================================================================
    // C: Move
    // =========================================================================

    #[test]
    fn test_move_def_use() {
        let line = make_line(&[Operand::Reg(RegId::X8), Operand::Reg(RegId::X9)]);
        let (defs, uses) = determine_def_use(InsnClass::Move, &line);
        assert_eq!(defs.as_slice(), &[RegId::X8]);
        assert_eq!(uses.as_slice(), &[RegId::X9]);
    }

    #[test]
    fn test_move_xzr_def_skipped() {
        let line = make_line(&[Operand::Reg(RegId::XZR), Operand::Reg(RegId::X9)]);
        let (defs, uses) = determine_def_use(InsnClass::Move, &line);
        assert!(defs.is_empty());
        assert_eq!(uses.as_slice(), &[RegId::X9]);
    }

    #[test]
    fn test_move_imm_source() {
        let line = make_line(&[Operand::Reg(RegId::X8), Operand::Imm(0x1234)]);
        let (defs, uses) = determine_def_use(InsnClass::Move, &line);
        assert_eq!(defs.as_slice(), &[RegId::X8]);
        assert!(uses.is_empty());
    }

    // =========================================================================
    // A: AluReg
    // =========================================================================

    #[test]
    fn test_alu_reg_def_use() {
        let line = make_line(&[
            Operand::Reg(RegId::X8),
            Operand::Reg(RegId::X9),
            Operand::Reg(RegId::X10),
        ]);
        let (defs, uses) = determine_def_use(InsnClass::AluReg, &line);
        assert_eq!(defs.as_slice(), &[RegId::X8]);
        assert_eq!(uses.as_slice(), &[RegId::X9, RegId::X10]);
    }

    #[test]
    fn test_alu_reg_with_imm() {
        let line = make_line(&[
            Operand::Reg(RegId::X8),
            Operand::Reg(RegId::X9),
            Operand::Imm(5),
        ]);
        let (defs, uses) = determine_def_use(InsnClass::AluReg, &line);
        assert_eq!(defs.as_slice(), &[RegId::X8]);
        assert_eq!(uses.as_slice(), &[RegId::X9]);
    }

    // =========================================================================
    // B: Multiply
    // =========================================================================

    #[test]
    fn test_multiply_madd() {
        // madd Xd, Xn, Xm, Xa
        let line = make_line(&[
            Operand::Reg(RegId::X0),
            Operand::Reg(RegId::X1),
            Operand::Reg(RegId::X2),
            Operand::Reg(RegId::X3),
        ]);
        let (defs, uses) = determine_def_use(InsnClass::Multiply, &line);
        assert_eq!(defs.as_slice(), &[RegId::X0]);
        assert_eq!(uses.as_slice(), &[RegId::X1, RegId::X2, RegId::X3]);
    }

    // =========================================================================
    // E: FlagSet
    // =========================================================================

    #[test]
    fn test_flag_set_def_use() {
        let line = make_line(&[Operand::Reg(RegId::X8), Operand::Reg(RegId::X9)]);
        let (defs, uses) = determine_def_use(InsnClass::FlagSet, &line);
        assert_eq!(defs.as_slice(), &[RegId::NZCV]);
        assert_eq!(uses.as_slice(), &[RegId::X8, RegId::X9]);
    }

    #[test]
    fn test_flag_set_cmp_imm() {
        let line = make_line(&[Operand::Reg(RegId::X8), Operand::Imm(0)]);
        let (defs, uses) = determine_def_use(InsnClass::FlagSet, &line);
        assert_eq!(defs.as_slice(), &[RegId::NZCV]);
        assert_eq!(uses.as_slice(), &[RegId::X8]);
    }

    // =========================================================================
    // E: CondFlagSet
    // =========================================================================

    #[test]
    fn test_cond_flag_set() {
        // ccmp Xn, Xm, #nzcv, cond
        let line = make_line(&[
            Operand::Reg(RegId::X1),
            Operand::Reg(RegId::X2),
            Operand::Imm(0),
        ]);
        let (defs, uses) = determine_def_use(InsnClass::CondFlagSet, &line);
        assert_eq!(defs.as_slice(), &[RegId::NZCV]);
        // nzcv (implicit) + X1 + X2
        assert!(uses.contains(&RegId::NZCV));
        assert!(uses.contains(&RegId::X1));
        assert!(uses.contains(&RegId::X2));
    }

    // =========================================================================
    // F: AluFlags
    // =========================================================================

    #[test]
    fn test_alu_flags() {
        let line = make_line(&[
            Operand::Reg(RegId::X0),
            Operand::Reg(RegId::X1),
            Operand::Reg(RegId::X2),
        ]);
        let (defs, uses) = determine_def_use(InsnClass::AluFlags, &line);
        assert_eq!(defs.as_slice(), &[RegId::X0, RegId::NZCV]);
        assert_eq!(uses.as_slice(), &[RegId::X1, RegId::X2]);
    }

    // =========================================================================
    // F: FlagUse
    // =========================================================================

    #[test]
    fn test_flag_use_csel() {
        // csel Xd, Xn, Xm, cond
        let line = make_line(&[
            Operand::Reg(RegId::X0),
            Operand::Reg(RegId::X1),
            Operand::Reg(RegId::X2),
        ]);
        let (defs, uses) = determine_def_use(InsnClass::FlagUse, &line);
        assert_eq!(defs.as_slice(), &[RegId::X0]);
        assert_eq!(uses.as_slice(), &[RegId::X1, RegId::X2, RegId::NZCV]);
    }

    // =========================================================================
    // F: AluCarry
    // =========================================================================

    #[test]
    fn test_alu_carry() {
        let line = make_line(&[
            Operand::Reg(RegId::X0),
            Operand::Reg(RegId::X1),
            Operand::Reg(RegId::X2),
        ]);
        let (defs, uses) = determine_def_use(InsnClass::AluCarry, &line);
        assert_eq!(defs.as_slice(), &[RegId::X0]);
        assert_eq!(uses.as_slice(), &[RegId::X1, RegId::X2, RegId::NZCV]);
    }

    // =========================================================================
    // F: AluCarryFlags
    // =========================================================================

    #[test]
    fn test_alu_carry_flags() {
        let line = make_line(&[
            Operand::Reg(RegId::X0),
            Operand::Reg(RegId::X1),
            Operand::Reg(RegId::X2),
        ]);
        let (defs, uses) = determine_def_use(InsnClass::AluCarryFlags, &line);
        assert_eq!(defs.as_slice(), &[RegId::X0, RegId::NZCV]);
        assert_eq!(uses.as_slice(), &[RegId::X1, RegId::X2, RegId::NZCV]);
    }

    // =========================================================================
    // D: ScalarRMW
    // =========================================================================

    #[test]
    fn test_scalar_rmw() {
        // movk X8, #0x1234
        let line = make_line(&[Operand::Reg(RegId::X8), Operand::Imm(0x1234)]);
        let (defs, uses) = determine_def_use(InsnClass::ScalarRMW, &line);
        assert_eq!(defs.as_slice(), &[RegId::X8]);
        // X8 old value is a USE
        assert_eq!(uses.as_slice(), &[RegId::X8]);
    }

    #[test]
    fn test_scalar_rmw_bfi() {
        // bfi Xd, Xn, #lsb, #width
        let line = make_line(&[
            Operand::Reg(RegId::X8),
            Operand::Reg(RegId::X9),
            Operand::Imm(4),
            Operand::Imm(8),
        ]);
        let (defs, uses) = determine_def_use(InsnClass::ScalarRMW, &line);
        assert_eq!(defs.as_slice(), &[RegId::X8]);
        assert_eq!(uses.as_slice(), &[RegId::X8, RegId::X9]); // X8 old + X9 source
    }

    // =========================================================================
    // G: LoadReg
    // =========================================================================

    #[test]
    fn test_load_reg_def_use() {
        let line = make_line(&[Operand::Reg(RegId::X0), Operand::Reg(RegId::X8)]);
        let (defs, uses) = determine_def_use(InsnClass::LoadReg, &line);
        assert_eq!(defs.as_slice(), &[RegId::X0]);
        assert_eq!(uses.as_slice(), &[RegId::X8]);
    }

    #[test]
    fn test_load_reg_writeback() {
        let line = make_line_wb(
            &[Operand::Reg(RegId::X0), Operand::Reg(RegId::X8)],
            RegId::X8,
        );
        let (defs, uses) = determine_def_use(InsnClass::LoadReg, &line);
        // DEF: X0 (loaded value) + X8 (writeback)
        assert_eq!(defs.as_slice(), &[RegId::X0, RegId::X8]);
        assert_eq!(uses.as_slice(), &[RegId::X8]);
    }

    // =========================================================================
    // G: LoadPair
    // =========================================================================

    #[test]
    fn test_load_pair() {
        let line = make_line(&[
            Operand::Reg(RegId::X0),
            Operand::Reg(RegId::X1),
            Operand::Reg(RegId::X8),
        ]);
        let (defs, uses) = determine_def_use(InsnClass::LoadPair, &line);
        assert_eq!(defs.as_slice(), &[RegId::X0, RegId::X1]);
        assert_eq!(uses.as_slice(), &[RegId::X8]);
    }

    #[test]
    fn test_load_pair_writeback() {
        let line = make_line_wb(
            &[
                Operand::Reg(RegId::X0),
                Operand::Reg(RegId::X1),
                Operand::Reg(RegId::X8),
            ],
            RegId::X8,
        );
        let (defs, uses) = determine_def_use(InsnClass::LoadPair, &line);
        assert_eq!(defs.as_slice(), &[RegId::X0, RegId::X1, RegId::X8]);
        assert_eq!(uses.as_slice(), &[RegId::X8]);
    }

    // =========================================================================
    // H: StoreReg
    // =========================================================================

    #[test]
    fn test_store_reg_def_use() {
        let line = make_line(&[Operand::Reg(RegId::X0), Operand::Reg(RegId::X8)]);
        let (defs, uses) = determine_def_use(InsnClass::StoreReg, &line);
        assert!(defs.is_empty());
        assert_eq!(uses.as_slice(), &[RegId::X0, RegId::X8]);
    }

    #[test]
    fn test_store_reg_writeback() {
        let line = make_line_wb(
            &[Operand::Reg(RegId::X0), Operand::Reg(RegId::X8)],
            RegId::X8,
        );
        let (defs, uses) = determine_def_use(InsnClass::StoreReg, &line);
        assert_eq!(defs.as_slice(), &[RegId::X8]); // writeback
        assert_eq!(uses.as_slice(), &[RegId::X0, RegId::X8]);
    }

    // =========================================================================
    // H: StorePair
    // =========================================================================

    #[test]
    fn test_store_pair() {
        let line = make_line(&[
            Operand::Reg(RegId::X0),
            Operand::Reg(RegId::X1),
            Operand::Reg(RegId::X8),
        ]);
        let (defs, uses) = determine_def_use(InsnClass::StorePair, &line);
        assert!(defs.is_empty());
        assert_eq!(uses.as_slice(), &[RegId::X0, RegId::X1, RegId::X8]);
    }

    // =========================================================================
    // H: StoreExcl
    // =========================================================================

    #[test]
    fn test_store_excl() {
        // stxr Ws, Xt, [Xn]
        let line = make_line(&[
            Operand::Reg(RegId::X0), // Ws status
            Operand::Reg(RegId::X1), // Xt data
            Operand::Reg(RegId::X8), // Xn base
        ]);
        let (defs, uses) = determine_def_use(InsnClass::StoreExcl, &line);
        assert_eq!(defs.as_slice(), &[RegId::X0]);
        assert_eq!(uses.as_slice(), &[RegId::X1, RegId::X8]);
    }

    // =========================================================================
    // I: CondBranchNzcv
    // =========================================================================

    #[test]
    fn test_cond_branch_nzcv() {
        let line = make_line(&[]);
        let (defs, uses) = determine_def_use(InsnClass::CondBranchNzcv, &line);
        assert!(defs.is_empty());
        assert_eq!(uses.as_slice(), &[RegId::NZCV]);
    }

    // =========================================================================
    // I: CondBranchReg
    // =========================================================================

    #[test]
    fn test_cond_branch_reg() {
        let line = make_line(&[Operand::Reg(RegId::X0)]);
        let (defs, uses) = determine_def_use(InsnClass::CondBranchReg, &line);
        assert!(defs.is_empty());
        assert_eq!(uses.as_slice(), &[RegId::X0]);
    }

    // =========================================================================
    // J: Branch
    // =========================================================================

    #[test]
    fn test_branch_no_def_use() {
        let line = make_line(&[]);
        let (defs, uses) = determine_def_use(InsnClass::Branch, &line);
        assert!(defs.is_empty());
        assert!(uses.is_empty());
    }

    // =========================================================================
    // J: BranchLink
    // =========================================================================

    #[test]
    fn test_branch_link_implicit_x30() {
        let line = make_line(&[]);
        let (defs, uses) = determine_def_use(InsnClass::BranchLink, &line);
        assert_eq!(defs.as_slice(), &[RegId::X30]);
        assert!(uses.is_empty());
    }

    // =========================================================================
    // K: BranchReg
    // =========================================================================

    #[test]
    fn test_branch_reg() {
        let line = make_line(&[Operand::Reg(RegId::X16)]);
        let (defs, uses) = determine_def_use(InsnClass::BranchReg, &line);
        assert!(defs.is_empty());
        assert_eq!(uses.as_slice(), &[RegId::X16]);
    }

    // =========================================================================
    // K: BranchLinkReg
    // =========================================================================

    #[test]
    fn test_branch_link_reg() {
        let line = make_line(&[Operand::Reg(RegId::X16)]);
        let (defs, uses) = determine_def_use(InsnClass::BranchLinkReg, &line);
        assert_eq!(defs.as_slice(), &[RegId::X30]);
        assert_eq!(uses.as_slice(), &[RegId::X16]);
    }

    // =========================================================================
    // K: Return
    // =========================================================================

    #[test]
    fn test_return_implicit_x30() {
        let line = make_line(&[]);
        let (defs, uses) = determine_def_use(InsnClass::Return, &line);
        assert!(defs.is_empty());
        assert_eq!(uses.as_slice(), &[RegId::X30]);
    }

    // =========================================================================
    // Nop / Svc
    // =========================================================================

    #[test]
    fn test_nop_no_def_use() {
        let line = make_line(&[]);
        let (defs, uses) = determine_def_use(InsnClass::Nop, &line);
        assert!(defs.is_empty());
        assert!(uses.is_empty());
    }

    #[test]
    fn test_svc_def_from_arrow() {
        let line = ParsedLine {
            mnemonic: Mnemonic::new("svc"),
            operands: smallvec::smallvec![Operand::Imm(0)],
            post_arrow_regs: Some(Box::new(smallvec::smallvec![
                (RegId::X0, 0),
                (RegId::X30, 0x40001234),
            ])),
            ..Default::default()
        };
        let (defs, uses) = determine_def_use(InsnClass::Svc, &line);
        assert_eq!(defs.as_slice(), &[RegId::X0, RegId::X30]);
        assert!(uses.is_empty());
    }

    #[test]
    fn test_svc_no_arrow_no_def() {
        let line = ParsedLine {
            mnemonic: Mnemonic::new("svc"),
            operands: smallvec::smallvec![Operand::Imm(0)],
            ..Default::default()
        };
        let (defs, uses) = determine_def_use(InsnClass::Svc, &line);
        assert!(defs.is_empty());
        assert!(uses.is_empty());
    }

    #[test]
    fn test_svc_xzr_filtered() {
        let line = ParsedLine {
            mnemonic: Mnemonic::new("svc"),
            operands: smallvec::smallvec![Operand::Imm(0)],
            post_arrow_regs: Some(Box::new(smallvec::smallvec![
                (RegId::XZR, 0),
                (RegId::X0, 42),
            ])),
            ..Default::default()
        };
        let (defs, _uses) = determine_def_use(InsnClass::Svc, &line);
        assert_eq!(defs.as_slice(), &[RegId::X0]);
    }

    // =========================================================================
    // L2: System registers
    // =========================================================================

    #[test]
    fn test_sys_reg_read() {
        let line = make_line(&[Operand::Reg(RegId::X0)]);
        let (defs, uses) = determine_def_use(InsnClass::SysRegRead, &line);
        assert_eq!(defs.as_slice(), &[RegId::X0]);
        assert!(uses.is_empty());
    }

    #[test]
    fn test_sys_reg_nzcv_read() {
        let line = make_line(&[Operand::Reg(RegId::X0)]);
        let (defs, uses) = determine_def_use(InsnClass::SysRegNzcvRead, &line);
        assert_eq!(defs.as_slice(), &[RegId::X0]);
        assert_eq!(uses.as_slice(), &[RegId::NZCV]);
    }

    #[test]
    fn test_sys_reg_write() {
        let line = make_line(&[Operand::Reg(RegId::X0)]);
        let (defs, uses) = determine_def_use(InsnClass::SysRegWrite, &line);
        assert!(defs.is_empty());
        assert_eq!(uses.as_slice(), &[RegId::X0]);
    }

    #[test]
    fn test_sys_reg_nzcv_write() {
        let line = make_line(&[Operand::Reg(RegId::X0)]);
        let (defs, uses) = determine_def_use(InsnClass::SysRegNzcvWrite, &line);
        assert_eq!(defs.as_slice(), &[RegId::NZCV]);
        assert_eq!(uses.as_slice(), &[RegId::X0]);
    }

    // =========================================================================
    // M: SIMD
    // =========================================================================

    #[test]
    fn test_simd_arith() {
        let line = make_line(&[
            Operand::Reg(RegId::V0),
            Operand::Reg(RegId::V1),
            Operand::Reg(RegId::V2),
        ]);
        let (defs, uses) = determine_def_use(InsnClass::SimdArith, &line);
        assert_eq!(defs.as_slice(), &[RegId::V0]);
        assert_eq!(uses.as_slice(), &[RegId::V1, RegId::V2]);
    }

    #[test]
    fn test_simd_rmw() {
        // ins Vd.B[lane], Vn.B[lane] — Vd is both DEF and USE
        let line = make_line(&[Operand::Reg(RegId::V0), Operand::Reg(RegId::V1)]);
        let (defs, uses) = determine_def_use(InsnClass::SimdRMW, &line);
        assert_eq!(defs.as_slice(), &[RegId::V0]);
        assert_eq!(uses.as_slice(), &[RegId::V0, RegId::V1]); // V0 old + V1 source
    }

    #[test]
    fn test_simd_move() {
        // movi Vd.4S, #imm
        let line = make_line(&[Operand::Reg(RegId::V0), Operand::Imm(0)]);
        let (defs, uses) = determine_def_use(InsnClass::SimdMove, &line);
        assert_eq!(defs.as_slice(), &[RegId::V0]);
        assert!(uses.is_empty());
    }

    #[test]
    fn test_simd_load() {
        let line = make_line(&[Operand::Reg(RegId::V0), Operand::Reg(RegId::X8)]);
        let (defs, uses) = determine_def_use(InsnClass::SimdLoad, &line);
        assert_eq!(defs.as_slice(), &[RegId::V0]);
        assert_eq!(uses.as_slice(), &[RegId::X8]);
    }

    #[test]
    fn test_simd_load_writeback() {
        // ldr d0, [x20], #8 — post-index writeback
        let line = make_line_wb(
            &[Operand::Reg(RegId::V0), Operand::Reg(RegId::X20)],
            RegId::X20,
        );
        let (defs, uses) = determine_def_use(InsnClass::SimdLoad, &line);
        assert_eq!(defs.as_slice(), &[RegId::V0, RegId::X20]); // V0 + writeback
        assert_eq!(uses.as_slice(), &[RegId::X20]);
    }

    #[test]
    fn test_simd_load_multi_register() {
        // ld1 {v0, v1}, [x0]  → DEF=v0,v1  USE=x0
        let line = ParsedLine {
            mnemonic: Mnemonic::new("ld1"),
            operands: smallvec::smallvec![
                Operand::Reg(RegId::V0),
                Operand::Reg(RegId::V1),
                Operand::Reg(RegId::X0),
            ],
            base_reg: Some(RegId::X0),
            ..Default::default()
        };
        let (defs, uses) = determine_def_use(InsnClass::SimdLoad, &line);
        assert!(defs.contains(&RegId::V0), "v0 should be DEF");
        assert!(defs.contains(&RegId::V1), "v1 should be DEF");
        assert!(
            !defs.contains(&RegId::X0),
            "x0 should not be DEF (no writeback)"
        );
        assert!(uses.contains(&RegId::X0), "x0 should be USE");
        assert!(!uses.contains(&RegId::V0), "v0 should not be USE");
        assert!(!uses.contains(&RegId::V1), "v1 should not be USE");
    }

    #[test]
    fn test_simd_load_multi_register_writeback() {
        // ld1 {v0, v1}, [x0], #32  → DEF=v0,v1,x0  USE=x0
        let line = ParsedLine {
            mnemonic: Mnemonic::new("ld1"),
            operands: smallvec::smallvec![
                Operand::Reg(RegId::V0),
                Operand::Reg(RegId::V1),
                Operand::Reg(RegId::X0),
            ],
            base_reg: Some(RegId::X0),
            writeback: true,
            ..Default::default()
        };
        let (defs, uses) = determine_def_use(InsnClass::SimdLoad, &line);
        assert!(defs.contains(&RegId::V0), "v0 should be DEF");
        assert!(defs.contains(&RegId::V1), "v1 should be DEF");
        assert!(defs.contains(&RegId::X0), "x0 should be DEF (writeback)");
        assert!(uses.contains(&RegId::X0), "x0 should be USE");
    }

    #[test]
    fn test_simd_lane_load() {
        let line = make_line(&[Operand::Reg(RegId::V0), Operand::Reg(RegId::X8)]);
        let (defs, uses) = determine_def_use(InsnClass::SimdLaneLoad, &line);
        assert_eq!(defs.as_slice(), &[RegId::V0]);
        assert_eq!(uses.as_slice(), &[RegId::V0, RegId::X8]); // V0 old + X8 base
    }

    #[test]
    fn test_simd_lane_load_writeback() {
        let line = make_line_wb(
            &[Operand::Reg(RegId::V0), Operand::Reg(RegId::X9)],
            RegId::X9,
        );
        let (defs, uses) = determine_def_use(InsnClass::SimdLaneLoad, &line);
        assert_eq!(defs.as_slice(), &[RegId::V0, RegId::X9]); // V0 + writeback
        assert_eq!(uses.as_slice(), &[RegId::V0, RegId::X9]); // V0 old + X9 base
    }

    #[test]
    fn test_simd_store() {
        let line = make_line(&[Operand::Reg(RegId::V0), Operand::Reg(RegId::X8)]);
        let (defs, uses) = determine_def_use(InsnClass::SimdStore, &line);
        assert!(defs.is_empty());
        assert_eq!(uses.as_slice(), &[RegId::V0, RegId::X8]);
    }

    #[test]
    fn test_simd_store_writeback() {
        let line = make_line_wb(
            &[Operand::Reg(RegId::V0), Operand::Reg(RegId::X8)],
            RegId::X8,
        );
        let (defs, uses) = determine_def_use(InsnClass::SimdStore, &line);
        assert_eq!(defs.as_slice(), &[RegId::X8]); // writeback
        assert_eq!(uses.as_slice(), &[RegId::V0, RegId::X8]);
    }

    // =========================================================================
    // N: FloatArith
    // =========================================================================

    #[test]
    fn test_float_arith() {
        let line = make_line(&[
            Operand::Reg(RegId::V0),
            Operand::Reg(RegId::V1),
            Operand::Reg(RegId::V2),
        ]);
        let (defs, uses) = determine_def_use(InsnClass::FloatArith, &line);
        assert_eq!(defs.as_slice(), &[RegId::V0]);
        assert_eq!(uses.as_slice(), &[RegId::V1, RegId::V2]);
    }

    // =========================================================================
    // O: Bitfield
    // =========================================================================

    #[test]
    fn test_bitfield() {
        let line = make_line(&[
            Operand::Reg(RegId::X0),
            Operand::Reg(RegId::X1),
            Operand::Imm(4),
            Operand::Imm(8),
        ]);
        let (defs, uses) = determine_def_use(InsnClass::Bitfield, &line);
        assert_eq!(defs.as_slice(), &[RegId::X0]);
        assert_eq!(uses.as_slice(), &[RegId::X1]);
    }

    // =========================================================================
    // P: Extend
    // =========================================================================

    #[test]
    fn test_extend() {
        let line = make_line(&[Operand::Reg(RegId::X0), Operand::Reg(RegId::X1)]);
        let (defs, uses) = determine_def_use(InsnClass::Extend, &line);
        assert_eq!(defs.as_slice(), &[RegId::X0]);
        assert_eq!(uses.as_slice(), &[RegId::X1]);
    }

    // =========================================================================
    // Edge cases: xzr filtering
    // =========================================================================

    #[test]
    fn test_xzr_use_filtered() {
        // add X0, XZR, X1 — xzr should not appear in uses
        let line = make_line(&[
            Operand::Reg(RegId::X0),
            Operand::Reg(RegId::XZR),
            Operand::Reg(RegId::X1),
        ]);
        let (defs, uses) = determine_def_use(InsnClass::AluReg, &line);
        assert_eq!(defs.as_slice(), &[RegId::X0]);
        assert_eq!(uses.as_slice(), &[RegId::X1]);
    }

    #[test]
    fn test_store_xzr_source() {
        // str XZR, [X8] — xzr should not appear in uses
        let line = make_line(&[Operand::Reg(RegId::XZR), Operand::Reg(RegId::X8)]);
        let (defs, uses) = determine_def_use(InsnClass::StoreReg, &line);
        assert!(defs.is_empty());
        assert_eq!(uses.as_slice(), &[RegId::X8]);
    }

    #[test]
    fn test_branch_reg_filters_xzr() {
        let line = make_line(&[Operand::Reg(RegId::XZR)]);
        let (defs, uses) = determine_def_use(InsnClass::BranchReg, &line);
        assert!(defs.is_empty());
        assert!(uses.is_empty(), "br xzr should not USE xzr");
    }

    #[test]
    fn test_branch_link_reg_filters_xzr() {
        let line = make_line(&[Operand::Reg(RegId::XZR)]);
        let (defs, uses) = determine_def_use(InsnClass::BranchLinkReg, &line);
        assert_eq!(defs.as_slice(), &[RegId::X30]);
        assert!(uses.is_empty(), "blr xzr should not USE xzr");
    }

    // =========================================================================
    // H: AtomicLoadOp
    // =========================================================================

    #[test]
    fn test_atomic_load_op() {
        // ldadd Xs, Xt, [Xn]: DEF=Xt, USE=Xs+Xn
        let line = make_line(&[
            Operand::Reg(RegId::X1), // Xs
            Operand::Reg(RegId::X2), // Xt
            Operand::Reg(RegId::X8), // Xn
        ]);
        let (defs, uses) = determine_def_use(InsnClass::AtomicLoadOp, &line);
        assert_eq!(defs.as_slice(), &[RegId::X2]);
        assert_eq!(uses.as_slice(), &[RegId::X1, RegId::X8]);
    }

    #[test]
    fn test_atomic_load_op_xzr_dest() {
        let line = make_line(&[
            Operand::Reg(RegId::X1),
            Operand::Reg(RegId::XZR),
            Operand::Reg(RegId::X8),
        ]);
        let (defs, uses) = determine_def_use(InsnClass::AtomicLoadOp, &line);
        assert!(defs.is_empty());
        assert_eq!(uses.as_slice(), &[RegId::X1, RegId::X8]);
    }

    // =========================================================================
    // H: CompareAndSwap
    // =========================================================================

    #[test]
    fn test_compare_and_swap() {
        let line = make_line(&[
            Operand::Reg(RegId::X0), // Ws
            Operand::Reg(RegId::X1), // Wt
            Operand::Reg(RegId::X8), // Xn
        ]);
        let (defs, uses) = determine_def_use(InsnClass::CompareAndSwap, &line);
        assert_eq!(defs.as_slice(), &[RegId::X0]);
        assert_eq!(uses.as_slice(), &[RegId::X0, RegId::X1, RegId::X8]);
    }
}
