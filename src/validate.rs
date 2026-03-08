use smallvec::SmallVec;
use std::io::BufRead;

use crate::def_use;
use crate::insn_class::{self, InsnClass};
use crate::parser;
use crate::types::*;

/// 自验证结果
pub struct ValidationResult {
    /// 有 => 且被检查的行数
    pub total_checked: u64,
    /// 无 => 或不可解析的行数（跳过）
    pub skipped: u64,
    /// R1: DEF 寄存器不在 post_arrow_regs 中
    pub r1_violations: u64,
    /// R2: post_arrow 中的寄存器不在 DEF 中且不是已知例外
    pub r2_violations: u64,
    /// R3: USE 寄存器不在 pre_arrow_regs 中（软警告）
    pub r3_warnings: u64,
    /// 前 N 个 R1 违规示例
    pub r1_examples: Vec<String>,
    /// 前 N 个 R2 违规示例
    pub r2_examples: Vec<String>,
}

impl std::fmt::Display for ValidationResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "=== 自验证结果 ===")?;
        writeln!(f, "已检查行数:  {}", self.total_checked)?;
        writeln!(f, "跳过行数:    {}", self.skipped)?;
        writeln!(f)?;

        writeln!(f, "R1 违规 (DEF 不在 => 右侧):  {}", self.r1_violations)?;
        writeln!(f, "R2 违规 (=> 右侧非 DEF):     {}", self.r2_violations)?;
        writeln!(f, "R3 警告 (USE 不在 => 左侧):  {}", self.r3_warnings)?;
        writeln!(f)?;

        if !self.r1_examples.is_empty() {
            writeln!(f, "=== R1 违规示例 ===")?;
            for ex in &self.r1_examples {
                writeln!(f, "  {}", ex)?;
            }
            writeln!(f)?;
        }

        if !self.r2_examples.is_empty() {
            writeln!(f, "=== R2 违规示例 ===")?;
            for ex in &self.r2_examples {
                writeln!(f, "  {}", ex)?;
            }
            writeln!(f)?;
        }

        let total = self.total_checked;
        let violations = self.r1_violations + self.r2_violations;
        let pct = if total > 0 {
            (total - violations) as f64 / total as f64 * 100.0
        } else {
            0.0
        };
        write!(
            f,
            "=== 验证通过率: {:.4}% ({}/{}) ===",
            pct,
            total - violations,
            total
        )?;

        Ok(())
    }
}

const MAX_EXAMPLES: usize = 20;

/// R1 例外：DEF 寄存器可以不在 post_arrow_regs 中的情况
fn is_r1_exception(class: InsnClass, reg: RegId) -> bool {
    // bl/blr: DEF=X30，但 trace 中不一定显示
    matches!(class, InsnClass::BranchLink | InsnClass::BranchLinkReg if reg == RegId::X30)
}

/// R2 例外：post_arrow 中非 DEF 寄存器是正常的情况
///
/// 精细化版本：根据具体寄存器和指令上下文判断，而非整个 InsnClass 豁免。
fn is_r2_exception(class: InsnClass, reg: RegId, line: &crate::types::ParsedLine) -> bool {
    match class {
        // 存储指令：所有操作数都是 USE，post_arrow 的值全是回显
        InsnClass::StoreReg
        | InsnClass::StorePair
        | InsnClass::StoreExcl
        | InsnClass::SimdStore => true,
        // FlagSet (cmp/tst): 所有操作数值回显
        InsnClass::FlagSet => true,
        // CondFlagSet (ccmp): 操作数值回显
        InsnClass::CondFlagSet => true,
        // ScalarRMW/SimdRMW: Rd 旧值回显
        InsnClass::ScalarRMW | InsnClass::SimdRMW => true,
        // AluFlags (adds/subs): 只豁免非首操作数（ops[1..] 中出现的源操作数回显）
        InsnClass::AluFlags => line
            .operands
            .iter()
            .skip(1)
            .any(|o| matches!(o, crate::types::Operand::Reg(r) if *r == reg)),
        // LoadReg/LoadPair: 仅豁免 base_reg（基址寄存器值回显）
        InsnClass::LoadReg | InsnClass::LoadPair => line.base_reg == Some(reg),
        // SimdLoad/SimdLaneLoad: 仅豁免 base_reg
        InsnClass::SimdLoad | InsnClass::SimdLaneLoad => line.base_reg == Some(reg),
        // Svc: 仅豁免 X30（unidbg artifact）
        InsnClass::Svc => reg == RegId::X30,
        _ => false,
    }
}

/// 运行自验证，检查 R1/R2/R3 规则
pub fn validate_trace<R: BufRead>(mut reader: R) -> ValidationResult {
    let mut result = ValidationResult {
        total_checked: 0,
        skipped: 0,
        r1_violations: 0,
        r2_violations: 0,
        r3_warnings: 0,
        r1_examples: Vec::new(),
        r2_examples: Vec::new(),
    };

    let mut line_no: u64 = 0;

    let mut buf = String::with_capacity(512);
    loop {
        buf.clear();
        match reader.read_line(&mut buf) {
            Ok(0) => break,
            Ok(_) => {}
            Err(_) => {
                line_no += 1;
                result.skipped += 1;
                continue;
            }
        }
        let raw_line = buf.trim_end_matches(['\n', '\r']);
        line_no += 1;

        let Some(line) = parser::parse_line_full(raw_line) else {
            result.skipped += 1;
            continue;
        };

        // 无 arrow 的行跳过 — 没有 post_arrow 数据可检查
        if !line.has_arrow {
            result.skipped += 1;
            continue;
        }

        // 分类 + 精化
        let class = insn_class::classify_and_refine(&line);

        // Nop/Svc 跳过 — 无有意义的 DEF/USE
        if class == InsnClass::Nop || class == InsnClass::Svc {
            result.skipped += 1;
            continue;
        }

        let (defs, uses) = def_use::determine_def_use(class, &line);
        result.total_checked += 1;

        // post_arrow 和 pre_arrow 的 RegId 集合
        let empty = SmallVec::new();
        let post_arrow = line.post_arrow_regs.as_deref().unwrap_or(&empty);
        let pre_arrow = line.pre_arrow_regs.as_deref().unwrap_or(&empty);
        let post_regs: SmallVec<[RegId; 4]> =
            post_arrow.iter().map(|(r, _)| *r).collect();
        let pre_regs: SmallVec<[RegId; 4]> = pre_arrow.iter().map(|(r, _)| *r).collect();

        // --- R1: 每个 DEF 必须在 post_arrow 中 ---
        for def_reg in &defs {
            if !post_regs.contains(def_reg) && !is_r1_exception(class, *def_reg) {
                result.r1_violations += 1;
                if result.r1_examples.len() < MAX_EXAMPLES {
                    result.r1_examples.push(format!(
                        "L{}: {} [{:?}] DEF={:?} not in post_arrow {:?}",
                        line_no,
                        line.mnemonic,
                        class,
                        def_reg,
                        post_regs
                    ));
                }
            }
        }

        // --- R2: post_arrow 中每个寄存器必须在 DEF 中或属于已知例外 ---
        for post_reg in &post_regs {
            if !defs.contains(post_reg) && !is_r2_exception(class, *post_reg, &line) {
                result.r2_violations += 1;
                if result.r2_examples.len() < MAX_EXAMPLES {
                    result.r2_examples.push(format!(
                        "L{}: {} [{:?}] post_arrow {:?} not in DEF {:?}",
                        line_no,
                        line.mnemonic,
                        class,
                        post_reg,
                        defs
                    ));
                }
            }
        }

        // --- R3: 每个 USE 应在 pre_arrow 中（软警告） ---
        for use_reg in &uses {
            if !pre_regs.contains(use_reg) {
                result.r3_warnings += 1;
            }
        }

        // 每 1M 行进度报告
        if line_no.is_multiple_of(1_000_000) {
            eprintln!("  [validate] {} M lines...", line_no / 1_000_000);
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_validate(lines: &[&str]) -> ValidationResult {
        let trace = lines.join("\n");
        let reader = std::io::BufReader::new(trace.as_bytes());
        validate_trace(reader)
    }

    #[test]
    fn test_validate_standard_alu_passes() {
        let result = run_validate(&[
            r#"[00:00:00 001][lib.so 0x100] [8b090108] 0x40000108: "add x8, x8, x9" x8=0x5 x9=0xa => x8=0xf"#,
        ]);
        assert_eq!(
            result.r1_violations, 0,
            "add: DEF x8 should be in post_arrow"
        );
        assert_eq!(
            result.r2_violations, 0,
            "add: no unexpected regs in post_arrow"
        );
        assert_eq!(result.total_checked, 1);
    }

    #[test]
    fn test_validate_cmp_nzcv_passes() {
        let result = run_validate(&[
            r#"[00:00:00 001][lib.so 0x300] [6b09011f] 0x40000300: "cmp x8, x9" x8=0x5 x9=0xa => nzcv=0x80000000"#,
        ]);
        assert_eq!(
            result.r1_violations, 0,
            "cmp: DEF nzcv should be in post_arrow"
        );
    }

    #[test]
    fn test_validate_store_rt_echo_is_exception() {
        let result = run_validate(&[
            r#"[00:00:00 001][lib.so 0x10c] [f9000be8] 0x4000010c: "str x8, [sp, #0x10]" ; mem[WRITE] abs=0xbffff010 x8=0xf sp=0xbffff000 => x8=0xf"#,
        ]);
        assert_eq!(
            result.r2_violations, 0,
            "str: x8 in post_arrow is known echo"
        );
    }

    #[test]
    fn test_validate_no_arrow_skipped() {
        let result = run_validate(&[
            r#"[00:00:00 001][lib.so 0x200] [14000010] 0x40000200: "b #0x40000240""#,
        ]);
        assert_eq!(result.total_checked, 0);
        assert_eq!(result.skipped, 1);
    }

    #[test]
    fn test_validate_bl_no_arrow_skipped() {
        let result = run_validate(&[
            r#"[00:00:00 001][lib.so 0x11c] [94000010] 0x4000011c: "bl #0x4000015c""#,
        ]);
        assert_eq!(result.r1_violations, 0);
        assert_eq!(result.skipped, 1);
    }

    #[test]
    fn test_validate_blr_hook_with_arrow() {
        let result = run_validate(&[
            r#"[00:00:00 001][lib.so 0x200] [d63f0100] 0x40000200: "blr x8" x8=0xfffe0000 => x30=0x40000204"#,
        ]);
        assert_eq!(
            result.r1_violations, 0,
            "blr hook: x30 in post_arrow matches DEF"
        );
    }

    #[test]
    fn test_validate_mov_passes() {
        let result = run_validate(&[
            r#"[00:00:00 001][lib.so 0x100] [d2800108] 0x40000100: "mov x8, #5" => x8=0x5"#,
        ]);
        assert_eq!(result.r1_violations, 0);
        assert_eq!(result.r2_violations, 0);
    }

    #[test]
    fn test_validate_movk_rmw_passes() {
        let result = run_validate(&[
            r#"[00:00:00 001][lib.so 0x100] [f2a02468] 0x40000100: "movk x8, #0x1234, lsl #16" x8=0x5 => x8=0x12340005"#,
        ]);
        assert_eq!(result.r1_violations, 0);
        assert_eq!(result.r2_violations, 0);
    }

    #[test]
    fn test_validate_ldr_passes() {
        let result = run_validate(&[
            r#"[00:00:00 001][lib.so 0x110] [f9400be0] 0x40000110: "ldr x0, [sp, #0x10]" ; mem[READ] abs=0xbffff010 sp=0xbffff000 => x0=0xf"#,
        ]);
        assert_eq!(result.r1_violations, 0);
        assert_eq!(result.r2_violations, 0);
    }

    #[test]
    fn test_validate_nop_skipped() {
        let result =
            run_validate(&[r#"[00:00:00 001][lib.so 0x100] [d503201f] 0x40000100: "nop""#]);
        assert_eq!(result.total_checked, 0);
        assert_eq!(result.skipped, 1);
    }

    #[test]
    fn test_validate_r1_violation_detected() {
        // mov x8, #5 → DEF=x8, but post_arrow is empty → R1 violation
        // The "=>" is present (has_arrow=true) but no registers after it
        let result = run_validate(&[
            r#"[00:00:00 001][lib.so 0x100] [d2800108] 0x40000100: "mov x8, #5" => "#,
        ]);
        assert_eq!(
            result.r1_violations, 1,
            "mov with empty post_arrow should trigger R1"
        );
        assert_eq!(result.total_checked, 1);
    }

    #[test]
    fn test_validate_r2_violation_detected() {
        // add x8, x8, x9 => x8=0xf x10=0x1
        // DEF=x8, but x10 appears in post_arrow and is NOT a DEF, NOT an exception → R2 violation
        let result = run_validate(&[
            r#"[00:00:00 001][lib.so 0x100] [8b090108] 0x40000100: "add x8, x8, x9" x8=0x5 x9=0xa => x8=0xf x10=0x1"#,
        ]);
        assert_eq!(
            result.r2_violations, 1,
            "x10 in post_arrow of add should trigger R2"
        );
    }

    #[test]
    fn test_validate_r3_warning_counted() {
        // add x8, x8, x9: USE=x8,x9 but pre_arrow only has x8 → x9 triggers R3
        let result = run_validate(&[
            r#"[00:00:00 001][lib.so 0x100] [8b090108] 0x40000100: "add x8, x8, x9" x8=0x5 => x8=0xf"#,
        ]);
        assert!(
            result.r3_warnings >= 1,
            "USE x9 not in pre_arrow should trigger R3 warning, got {}",
            result.r3_warnings
        );
    }

    #[test]
    fn test_validate_mixed_trace() {
        let result = run_validate(&[
            r#"[00:00:00 001][lib.so 0x100] [d2800108] 0x40000100: "mov x8, #5" => x8=0x5"#,
            r#"[00:00:00 001][lib.so 0x104] [8b090108] 0x40000104: "add x8, x8, x9" x8=0x5 x9=0xa => x8=0xf"#,
            r#"[00:00:00 001][lib.so 0x108] [6b09011f] 0x40000108: "cmp x8, x9" x8=0x5 x9=0xa => nzcv=0x80000000"#,
            r#"[00:00:00 001][lib.so 0x10c] [f9000be8] 0x4000010c: "str x8, [sp, #0x10]" ; mem[WRITE] abs=0xbffff010 x8=0xf sp=0xbffff000 => x8=0xf"#,
            r#"[00:00:00 001][lib.so 0x200] [14000010] 0x40000200: "b #0x40000240""#,
        ]);
        assert_eq!(result.total_checked, 4); // mov, add, cmp, str (b is skipped)
        assert_eq!(result.skipped, 1); // b
        assert_eq!(result.r1_violations, 0);
        assert_eq!(result.r2_violations, 0);
    }
}
