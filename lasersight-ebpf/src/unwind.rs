// Unwind code from https://github.com/dvc94ch/cargo-trace
use aya_bpf::{
    bindings::pt_regs,
    helpers::bpf_probe_read,
    macros::{kprobe, perf_event, tracepoint},
    maps::{Array, HashMap},
    programs::{PerfEventContext, ProbeContext, TracePointContext},
    BpfContext,
};
use aya_log_ebpf::info;

#[tracepoint]
pub fn lasersight(ctx: TracePointContext) -> u32 {
    match unsafe { try_lasersight(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_lasersight(ctx: TracePointContext) -> Result<u32, u32> {
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

// absolute maximum would be 512 byte stack size limit / 8 byte address = 64. but since
// we need some stack for other variables this needs to be lower.
const MAX_STACK_DEPTH: usize = 48;
const MAX_BIN_SEARCH_DEPTH: usize = 24;
const EHFRAME_ENTRIES: u32 = 0xff_ffff;

#[derive(Clone, Copy)]
#[repr(C)]
pub struct Instruction {
    op: u64,
    offset: i64,
}

static mut CONFIG: Array<u32> = Array::with_max_entries(2, 0);
static mut PC: Array<u64> = Array::with_max_entries(EHFRAME_ENTRIES, 0);
static mut RIP: Array<Instruction> = Array::with_max_entries(EHFRAME_ENTRIES, 0);
static mut RSP: Array<Instruction> = Array::with_max_entries(EHFRAME_ENTRIES, 0);

static mut USER_STACK: HashMap<[u64; MAX_STACK_DEPTH], u32> = HashMap::with_max_entries(1024, 0);

#[perf_event]
fn perf_event(args: PerfEventContext) {
    unsafe {
        increment_stack_counter(&*(args.as_ptr() as *mut pt_regs)); // TODO: change when the regs field is implemented in aya
    }
}

#[kprobe]
fn kprobe(args: ProbeContext) {
    increment_stack_counter(unsafe { &*args.regs });
}

fn increment_stack_counter(regs: &pt_regs) {
    unsafe {
        let mut stack = [0; MAX_STACK_DEPTH];
        backtrace(regs, &mut stack);
        let mut count = USER_STACK.get(&stack).map(|x| *x).unwrap_or_default();
        count += 1;
        let _ = USER_STACK.insert(&stack, &count, 0);
    }
}

unsafe fn backtrace(regs: &pt_regs, stack: &mut [u64; MAX_STACK_DEPTH]) {
    let mut rip = regs.rip;
    let mut rsp = regs.rsp;
    for d in 0..MAX_STACK_DEPTH {
        stack[d] = rip;
        if rip == 0 {
            break;
        }
        let i = binary_search(rip);

        let ins = if let Some(ins) = RSP.get(i) {
            ins
        } else {
            break;
        };
        let cfa = if let Some(cfa) = execute_instruction(&ins, rip, rsp, 0) {
            cfa
        } else {
            break;
        };

        let ins = if let Some(ins) = RIP.get(i) {
            ins
        } else {
            break;
        };
        rip = execute_instruction(&ins, rip, rsp, cfa).unwrap_or_default();
        rsp = cfa;
    }
}

unsafe fn binary_search(rip: u64) -> u32 {
    let mut left = 0;
    let mut right = CONFIG.get(0).copied().unwrap_or(1) - 1;
    let mut i = 0;
    for _ in 0..MAX_BIN_SEARCH_DEPTH {
        if left > right {
            break;
        }
        i = (left + right) / 2;
        let pc = PC.get(i).copied().unwrap_or(u64::MAX);
        if pc < rip {
            left = i;
        } else {
            right = i;
        }
    }
    i
}

fn execute_instruction(ins: &Instruction, rip: u64, rsp: u64, cfa: u64) -> Option<u64> {
    match ins.op {
        1 => {
            let unsafe_ptr = (cfa as i64 + ins.offset as i64) as *const core::ffi::c_void;
            unsafe { bpf_probe_read(unsafe_ptr as *const u64).ok() }
        }
        2 => Some((rip as i64 + ins.offset as i64) as u64),
        3 => Some((rsp as i64 + ins.offset as i64) as u64),
        _ => None,
    }
}
