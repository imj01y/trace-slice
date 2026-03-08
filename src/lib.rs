//! ARM64 trace 后向切片分析器。
//!
//! 从 unidbg 格式的指令 trace 中，通过后向数据流分析（backward slicing）
//! 提取与指定寄存器或内存地址相关的最小指令子集。
//!
//! ## 核心流程
//!
//! 1. **Pass 1 扫描** ([`scanner`])：逐行解析 trace，构建寄存器/内存依赖图
//! 2. **BFS 切片** ([`slicer`])：从起点反向遍历依赖图，标记相关行
//! 3. **Pass 2 输出** ([`slicer`])：仅输出标记行，生成精简 trace

pub mod def_use;
pub mod insn_class;
pub mod parser;
pub mod scanner;
pub mod slicer;
pub mod types;
pub mod validate;

use anyhow::{bail, Result};
use memmap2::Mmap;
use std::collections::HashMap;
use std::io::{BufReader, Write};
use std::time::Instant;
use types::{parse_reg, FromSpec, LineTarget};

/// 执行完整的后向切片流程。
///
/// 1. 解析 `from_args` 为 [`FromSpec`] 切片起点规范
/// 2. 内存映射 trace 文件，执行 Pass 1 扫描构建依赖图
/// 3. BFS 反向遍历，标记所有相关行
/// 4. Pass 2 输出切片结果到文件或 stdout
pub fn run(
    trace_path: &str,
    from_args: &[String],
    data_only: bool,
    start_seq: u32,
    end_seq: Option<u32>,
    output_path: Option<&str>,
    profile: bool,
    no_prune: bool,
) -> Result<()> {
    // Validate seq range
    if let Some(end) = end_seq {
        if start_seq > end {
            bail!("--start-seq ({}) must be <= --end-seq ({})", start_seq, end);
        }
    }

    // 1. Parse --from args
    let specs = parse_from_specs(from_args)?;

    // 2. Extract @LINE targets for scanner validation
    let mut line_targets: HashMap<u32, Vec<LineTarget>> = HashMap::new();
    for spec in &specs {
        match spec {
            FromSpec::RegAt(reg, line) => {
                line_targets
                    .entry(*line)
                    .or_default()
                    .push(LineTarget::Reg(*reg));
            }
            FromSpec::MemAt(addr, line) => {
                line_targets
                    .entry(*line)
                    .or_default()
                    .push(LineTarget::Mem(*addr));
            }
            _ => {}
        }
    }

    // 3. Memory-map the trace file once (shared by scan + output)
    let total_start = Instant::now();
    let file = std::fs::File::open(trace_path)?;
    // SAFETY: read-only access; file is not modified concurrently
    let mmap = unsafe { Mmap::map(&file)? };

    eprintln!("[扫描] 正在解析 {}...", trace_path);
    let t = Instant::now();
    let state = scanner::scan_pass1_bytes(
        &mmap,
        data_only,
        start_seq,
        end_seq,
        &line_targets,
        profile,
        no_prune,
    )?;
    eprintln!(
        "[扫描] 完成：{} 行，{} 个内存地址 ({:.1}s)",
        state.line_count,
        state.mem_last_def.len(),
        t.elapsed().as_secs_f64()
    );

    // 4. Resolve start indices
    let start_indices = resolve_starts(&specs, &state)?;
    eprintln!(
        "[扫描] 切片起点 (1-based): {:?}",
        start_indices.iter().map(|i| i + 1).collect::<Vec<_>>()
    );

    // 5. BFS traversal
    let t = Instant::now();
    let mut marked = slicer::bfs_slice(&state, &start_indices);

    // 5b. Include original target lines (when fallback occurred, the user's
    //     specified line is after the resolved DEF and won't be in the BFS set)
    for spec in &specs {
        let (line, target) = match spec {
            FromSpec::RegAt(reg, line) => (*line, LineTarget::Reg(*reg)),
            FromSpec::MemAt(addr, line) => (*line, LineTarget::Mem(*addr)),
            _ => continue,
        };
        if let Some(&resolved) = state.resolved_targets.get(&(line, target)) {
            if resolved != line && (line as usize) < marked.len() {
                marked.set(line as usize, true);
            }
        }
    }

    let marked_count = marked.count_ones();
    eprintln!(
        "[切片] 标记 {} / {} 行 ({:.1}%) ({:.1}s)",
        marked_count,
        state.line_count,
        marked_count as f64 / state.line_count as f64 * 100.0,
        t.elapsed().as_secs_f64()
    );

    // 6. Pass 2: output sliced trace (reuse the same mmap — no second file read)
    let t = Instant::now();
    let (count, dest) = if let Some(path) = output_path {
        let out_file = std::fs::File::create(path)?;
        let mut writer = std::io::BufWriter::with_capacity(8 * 1024 * 1024, out_file);
        let c = slicer::write_sliced_bytes(&mmap, &marked, &state.init_mem_loads, &mut writer)?;
        (c, format!("写入到 {}", path))
    } else {
        let stdout = std::io::stdout();
        let mut writer = std::io::BufWriter::with_capacity(8 * 1024 * 1024, stdout.lock());
        let c = slicer::write_sliced_bytes(&mmap, &marked, &state.init_mem_loads, &mut writer)?;
        (c, "到 stdout".to_string())
    };
    eprintln!(
        "[输出] {} 行{} ({:.1}s)",
        count,
        dest,
        t.elapsed().as_secs_f64()
    );

    // 7. 未知助记符摘要
    if !state.unknown_mnemonics.is_empty() {
        let mut sorted: Vec<_> = state.unknown_mnemonics.iter().collect();
        sorted.sort_by_key(|(_, (_, count))| std::cmp::Reverse(*count));
        let total_kinds = sorted.len();
        let total_count: u32 = sorted.iter().map(|(_, (_, c))| c).sum();

        let summary = {
            let mut s = format!(
                "[未知助记符] 共 {} 种 {} 次（已按 Nop 处理，可能丢失依赖）\n",
                total_kinds, total_count
            );
            for (mnemonic, (first_line, count)) in &sorted {
                s.push_str(&format!(
                    "  {:<12}: 首次出现 line {}, 共 {} 次\n",
                    mnemonic,
                    first_line + 1,
                    count
                ));
            }
            s
        };

        match output_path {
            Some(path) => {
                let summary_path = format!("{}.summary.txt", path);
                std::fs::write(&summary_path, &summary)?;
                eprintln!("[摘要] 未知助记符写入 {}", summary_path);
            }
            None => {
                eprint!("{}", summary);
            }
        }
    }

    eprintln!("总耗时：{:.1}s", total_start.elapsed().as_secs_f64());
    Ok(())
}

/// Parse the suffix after '@' as a 1-based line number, returning 0-based index.
fn parse_line_suffix(suffix: &str, arg: &str) -> Result<u32> {
    let line: u32 = suffix
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid line number '{}' in: {}", suffix, arg))?;
    if line == 0 {
        bail!("line number must be >= 1 (1-based) in: {}", arg);
    }
    Ok(line - 1)
}

fn parse_from_specs(args: &[String]) -> Result<Vec<FromSpec>> {
    let mut specs = Vec::new();
    for arg in args {
        if let Some(rest) = arg.strip_prefix("reg:") {
            let (name, suffix) = rest
                .rsplit_once('@')
                .ok_or_else(|| anyhow::anyhow!("missing @ in reg spec: {}", arg))?;
            let reg =
                parse_reg(name).ok_or_else(|| anyhow::anyhow!("unknown register: {}", name))?;
            if suffix == "last" {
                specs.push(FromSpec::RegLast(reg));
            } else {
                specs.push(FromSpec::RegAt(reg, parse_line_suffix(suffix, arg)?));
            }
        } else if let Some(rest) = arg.strip_prefix("mem:") {
            let (addr_str, suffix) = rest
                .rsplit_once('@')
                .ok_or_else(|| anyhow::anyhow!("missing @ in mem spec: {}", arg))?;
            let addr_str = addr_str.strip_prefix("0x").unwrap_or(addr_str);
            let addr = u64::from_str_radix(addr_str, 16)
                .map_err(|_| anyhow::anyhow!("invalid hex address '{}' in: {}", addr_str, arg))?;
            if suffix == "last" {
                specs.push(FromSpec::MemLast(addr));
            } else {
                specs.push(FromSpec::MemAt(addr, parse_line_suffix(suffix, arg)?));
            }
        } else {
            bail!(
                "unsupported from-spec format: {} (expected reg:NAME@... or mem:ADDR@...)",
                arg
            );
        }
    }
    Ok(specs)
}

fn resolve_starts(specs: &[FromSpec], state: &scanner::ScanState) -> Result<Vec<u32>> {
    let mut indices = Vec::new();
    for spec in specs {
        match spec {
            FromSpec::RegLast(reg) => {
                let line = state
                    .reg_last_def
                    .get(reg)
                    .ok_or_else(|| anyhow::anyhow!("register {:?} never defined in trace", reg))?;
                indices.push(*line);
            }
            FromSpec::MemLast(addr) => {
                let &(line, _) = state.mem_last_def.get(addr).ok_or_else(|| {
                    anyhow::anyhow!("address 0x{:x} never written in trace", addr)
                })?;
                indices.push(line);
            }
            FromSpec::RegAt(reg, line) => {
                let resolved = state
                    .resolved_targets
                    .get(&(*line, LineTarget::Reg(*reg)))
                    .ok_or_else(|| {
                        anyhow::anyhow!("no resolved target for reg {:?} at line {}", reg, line + 1)
                    })?;
                indices.push(*resolved);
            }
            FromSpec::MemAt(addr, line) => {
                let resolved = state
                    .resolved_targets
                    .get(&(*line, LineTarget::Mem(*addr)))
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "no resolved target for mem 0x{:x} at line {}",
                            addr,
                            line + 1
                        )
                    })?;
                indices.push(*resolved);
            }
        }
    }
    Ok(indices)
}

/// Run validation mode: check DEF/USE consistency against trace arrow data.
pub fn run_validate(trace_path: &str, output_path: Option<&str>) -> Result<()> {
    eprintln!("[validate] Opening {}...", trace_path);
    let file = std::fs::File::open(trace_path)?;
    let reader = BufReader::with_capacity(8 * 1024 * 1024, file);

    let vr = validate::validate_trace(reader);
    eprintln!(
        "[validate] Done: {} checked, {} skipped",
        vr.total_checked, vr.skipped
    );

    let out_str = format!("{}\n", vr);

    match output_path {
        Some(path) => {
            let mut file = std::fs::File::create(path)?;
            file.write_all(out_str.as_bytes())?;
            eprintln!("[validate] Written to {}", path);
        }
        None => {
            print!("{}", out_str);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use types::RegId;

    #[test]
    fn test_parse_reg_last() {
        let args = vec!["reg:x0@last".to_string()];
        let specs = parse_from_specs(&args).unwrap();
        assert_eq!(specs.len(), 1);
        assert!(matches!(&specs[0], FromSpec::RegLast(r) if *r == RegId::X0));
    }

    #[test]
    fn test_parse_reg_at_line() {
        let args = vec!["reg:x8@5000".to_string()];
        let specs = parse_from_specs(&args).unwrap();
        assert_eq!(specs.len(), 1);
        assert!(matches!(&specs[0], FromSpec::RegAt(r, 4999) if *r == RegId::X8));
    }

    #[test]
    fn test_parse_mem_last() {
        let args = vec!["mem:0xbffff010@last".to_string()];
        let specs = parse_from_specs(&args).unwrap();
        assert_eq!(specs.len(), 1);
        assert!(matches!(&specs[0], FromSpec::MemLast(addr) if *addr == 0xbffff010));
    }

    #[test]
    fn test_parse_mem_at_line() {
        let args = vec!["mem:0xbffff010@1234".to_string()];
        let specs = parse_from_specs(&args).unwrap();
        assert_eq!(specs.len(), 1);
        assert!(matches!(&specs[0], FromSpec::MemAt(addr, 1233) if *addr == 0xbffff010));
    }

    #[test]
    fn test_parse_mem_no_0x_prefix() {
        let args = vec!["mem:bffff010@last".to_string()];
        let specs = parse_from_specs(&args).unwrap();
        assert!(matches!(&specs[0], FromSpec::MemLast(addr) if *addr == 0xbffff010));
    }

    #[test]
    fn test_parse_multiple_specs() {
        let args = vec!["reg:x0@last".to_string(), "mem:0x1000@5000".to_string()];
        let specs = parse_from_specs(&args).unwrap();
        assert_eq!(specs.len(), 2);
        assert!(matches!(&specs[0], FromSpec::RegLast(_)));
        assert!(matches!(&specs[1], FromSpec::MemAt(0x1000, 4999)));
    }

    #[test]
    fn test_parse_invalid_format() {
        let args = vec!["foo:bar".to_string()];
        assert!(parse_from_specs(&args).is_err());
    }

    #[test]
    fn test_parse_unknown_register() {
        let args = vec!["reg:x99@last".to_string()];
        assert!(parse_from_specs(&args).is_err());
    }

    #[test]
    fn test_parse_invalid_mem_addr() {
        let args = vec!["mem:not_hex@last".to_string()];
        assert!(parse_from_specs(&args).is_err());
    }
}
