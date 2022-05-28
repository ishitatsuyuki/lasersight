use aya_bpf::{
    bindings::pt_regs,
    helpers::bpf_probe_read,
    macros::{kprobe, perf_event, tracepoint},
    maps::{Array, HashMap},
    programs::{PerfEventContext, ProbeContext, TracePointContext},
    BpfContext,
};
#[tracepoint]
pub fn sched_switch(ctx: TracePointContext) -> u32 {
    0
}
