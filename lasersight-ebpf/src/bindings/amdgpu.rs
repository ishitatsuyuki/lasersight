/* automatically generated by rust-bindgen 0.59.2 */

#[repr(C)]
#[derive(Default)]
pub struct __IncompleteArrayField<T>(::core::marker::PhantomData<T>, [T; 0]);
impl<T> __IncompleteArrayField<T> {
    #[inline]
    pub const fn new() -> Self {
        __IncompleteArrayField(::core::marker::PhantomData, [])
    }
    #[inline]
    pub fn as_ptr(&self) -> *const T {
        self as *const _ as *const T
    }
    #[inline]
    pub fn as_mut_ptr(&mut self) -> *mut T {
        self as *mut _ as *mut T
    }
    #[inline]
    pub unsafe fn as_slice(&self, len: usize) -> &[T] {
        ::core::slice::from_raw_parts(self.as_ptr(), len)
    }
    #[inline]
    pub unsafe fn as_mut_slice(&mut self, len: usize) -> &mut [T] {
        ::core::slice::from_raw_parts_mut(self.as_mut_ptr(), len)
    }
}
impl<T> ::core::fmt::Debug for __IncompleteArrayField<T> {
    fn fmt(&self, fmt: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        fmt.write_str("__IncompleteArrayField")
    }
}
pub type __s64 = ::aya_bpf::cty::c_longlong;
pub type __u64 = ::aya_bpf::cty::c_ulonglong;
pub type u64_ = __u64;
pub type bool_ = bool;
pub type __u8 = ::aya_bpf::cty::c_uchar;
pub type __u16 = ::aya_bpf::cty::c_ushort;
pub type __u32 = ::aya_bpf::cty::c_uint;
pub type u8_ = __u8;
pub type u16_ = __u16;
pub type u32_ = __u32;
#[repr(C)]
#[derive(Copy, Clone)]
pub struct atomic_t {
    pub counter: ::aya_bpf::cty::c_int,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct list_head {
    pub next: *mut list_head,
    pub prev: *mut list_head,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct callback_head {
    pub next: *mut callback_head,
    pub func: ::core::option::Option<unsafe extern "C" fn(arg1: *mut callback_head)>,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct qspinlock {
    pub __bindgen_anon_1: qspinlock__bindgen_ty_1,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union qspinlock__bindgen_ty_1 {
    pub val: atomic_t,
    pub __bindgen_anon_1: qspinlock__bindgen_ty_1__bindgen_ty_1,
    pub __bindgen_anon_2: qspinlock__bindgen_ty_1__bindgen_ty_2,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct qspinlock__bindgen_ty_1__bindgen_ty_1 {
    pub locked: u8_,
    pub pending: u8_,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct qspinlock__bindgen_ty_1__bindgen_ty_2 {
    pub locked_pending: u16_,
    pub tail: u16_,
}
pub type arch_spinlock_t = qspinlock;
#[repr(C)]
#[derive(Copy, Clone)]
pub struct raw_spinlock {
    pub raw_lock: arch_spinlock_t,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct spinlock {
    pub __bindgen_anon_1: spinlock__bindgen_ty_1,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union spinlock__bindgen_ty_1 {
    pub rlock: raw_spinlock,
}
pub type spinlock_t = spinlock;
pub type s64 = __s64;
#[repr(C)]
#[derive(Copy, Clone)]
pub struct refcount_struct {
    pub refs: atomic_t,
}
pub type refcount_t = refcount_struct;
pub type ktime_t = s64;
#[repr(C)]
#[derive(Copy, Clone)]
pub struct kref {
    pub refcount: refcount_t,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct trace_entry {
    pub type_: ::aya_bpf::cty::c_ushort,
    pub flags: ::aya_bpf::cty::c_uchar,
    pub preempt_count: ::aya_bpf::cty::c_uchar,
    pub pid: ::aya_bpf::cty::c_int,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct dma_fence {
    pub lock: *mut spinlock_t,
    pub ops: *const dma_fence_ops,
    pub __bindgen_anon_1: dma_fence__bindgen_ty_1,
    pub context: u64_,
    pub seqno: u64_,
    pub flags: ::aya_bpf::cty::c_ulong,
    pub refcount: kref,
    pub error: ::aya_bpf::cty::c_int,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union dma_fence__bindgen_ty_1 {
    pub cb_list: list_head,
    pub timestamp: ktime_t,
    pub rcu: callback_head,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct dma_fence_ops {
    pub use_64bit_seqno: bool_,
    pub get_driver_name: ::core::option::Option<
        unsafe extern "C" fn(arg1: *mut dma_fence) -> *const ::aya_bpf::cty::c_char,
    >,
    pub get_timeline_name: ::core::option::Option<
        unsafe extern "C" fn(arg1: *mut dma_fence) -> *const ::aya_bpf::cty::c_char,
    >,
    pub enable_signaling:
        ::core::option::Option<unsafe extern "C" fn(arg1: *mut dma_fence) -> bool_>,
    pub signaled: ::core::option::Option<unsafe extern "C" fn(arg1: *mut dma_fence) -> bool_>,
    pub wait: ::core::option::Option<
        unsafe extern "C" fn(
            arg1: *mut dma_fence,
            arg2: bool_,
            arg3: ::aya_bpf::cty::c_long,
        ) -> ::aya_bpf::cty::c_long,
    >,
    pub release: ::core::option::Option<unsafe extern "C" fn(arg1: *mut dma_fence)>,
    pub fence_value_str: ::core::option::Option<
        unsafe extern "C" fn(
            arg1: *mut dma_fence,
            arg2: *mut ::aya_bpf::cty::c_char,
            arg3: ::aya_bpf::cty::c_int,
        ),
    >,
    pub timeline_value_str: ::core::option::Option<
        unsafe extern "C" fn(
            arg1: *mut dma_fence,
            arg2: *mut ::aya_bpf::cty::c_char,
            arg3: ::aya_bpf::cty::c_int,
        ),
    >,
}
#[repr(C)]
pub struct trace_event_raw_amdgpu_cs_ioctl {
    pub ent: trace_entry,
    pub sched_job_id: u64,
    pub __data_loc_timeline: u32_,
    pub context: ::aya_bpf::cty::c_uint,
    pub seqno: ::aya_bpf::cty::c_uint,
    pub fence: *mut dma_fence,
    pub __data_loc_ring: u32_,
    pub num_ibs: u32_,
    pub __data: __IncompleteArrayField<::aya_bpf::cty::c_char>,
}
#[repr(C)]
pub struct trace_event_raw_amdgpu_sched_run_job {
    pub ent: trace_entry,
    pub sched_job_id: u64,
    pub __data_loc_timeline: u32_,
    pub context: ::aya_bpf::cty::c_uint,
    pub seqno: ::aya_bpf::cty::c_uint,
    pub __data_loc_ring: u32_,
    pub num_ibs: u32_,
    pub __data: __IncompleteArrayField<::aya_bpf::cty::c_char>,
}
#[repr(C)]
pub struct trace_event_raw_amdgpu_vm_flush {
    pub ent: trace_entry,
    pub __data_loc_ring: u32_,
    pub vmid: u32_,
    pub vm_hub: u32_,
    pub pd_addr: u64_,
    pub __data: __IncompleteArrayField<::aya_bpf::cty::c_char>,
}

