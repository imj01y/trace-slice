use anyhow::Result;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "trace-slice", about = "ARM64 动态后向切片器")]
struct Cli {
    /// trace 文件路径
    trace_file: String,

    /// 切片起点（可多次指定）
    #[arg(long = "from", required_unless_present = "validate")]
    from: Vec<String>,

    /// 启用控制依赖追踪（默认仅数据依赖）
    #[arg(long)]
    with_control_dep: bool,

    /// 扫描起始行号（1-based，跳过该行之前的行）
    #[arg(long)]
    start_seq: Option<u32>,

    /// 扫描结束行号（1-based，含该行，之后的行跳过）
    #[arg(long)]
    end_seq: Option<u32>,

    /// 输出文件路径（默认 stdout）
    #[arg(short, long)]
    output: Option<String>,

    /// 自验证模式：检查 DEF/USE 语义表与 trace 的一致性
    #[arg(long)]
    validate: bool,

    /// 禁用值相等性剪枝（保留完整地址依赖链）
    #[arg(long)]
    no_prune: bool,

    /// 输出扫描阶段内部耗时分解（profiling）
    #[arg(long)]
    profile: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    if cli.validate {
        trace_slice::run_validate(&cli.trace_file, cli.output.as_deref())
    } else {
        trace_slice::run(
            &cli.trace_file,
            &cli.from,
            !cli.with_control_dep,
            cli.start_seq.map(|n| n.saturating_sub(1)).unwrap_or(0),
            cli.end_seq.map(|n| n.saturating_sub(1)),
            cli.output.as_deref(),
            cli.profile,
            cli.no_prune,
        )
    }
}
