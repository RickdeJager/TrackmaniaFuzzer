// General imports
use libafl::{
    inputs::Input,
    state::{HasMetadata},
};

// Qemu imports
use libafl_qemu::{
    Emulator, QemuHelper, QemuHelperTuple, QemuHooks, SyscallHookResult, Regs
};

// TODO; Pull these from qemu instead
const SYS_gettimeofday: i32 = 78;
const SYS_clockgettime: i32 = 265;
const SYS_brk: i32 = 45;

pub fn step_emu(emu: &Emulator) {
    let eip: u32 = emu.read_reg(Regs::Eip).unwrap();
    for i in 1..8 {
        emu.set_breakpoint(eip+i);
    }
    unsafe{emu.run();}
    for i in 1..8 {
        emu.remove_breakpoint(eip+i);
    }
}

#[derive(Default, Debug)]
pub struct QemuTimeFreezeHelper {
    // time of snapshot
// ...
}

impl<I, S> QemuHelper<I, S> for QemuTimeFreezeHelper
where
    I: Input,
    S: HasMetadata,
{
    fn init_hooks<'a, QT>(&self, hooks: &QemuHooks<'a, I, QT, S>)
    where
        QT: QemuHelperTuple<I, S>,
    {
       // hooks.syscalls(hook_time_syscalls::<I, QT, S>);
    }
}

/*
#[allow(clippy::too_many_arguments)]
pub fn hook_time_syscalls<I, QT, S>(
    emulator: &Emulator,
    helpers: &mut QT,
    _state: Option<&mut S>,
    sys_num: i32,
    a0: u64,
    a1: u64,
    a2: u64,
    a3: u64,
    _a4: u64,
    _a5: u64,
    _a6: u64,
    _a7: u64,
) -> SyscallHookResult
where
    I: Input,
    QT: QemuHelperTuple<I, S>,
{
    //  println!("Hooked {}", sys_num);
    //  let eip: u32 = emulator.read_reg(Regs::Eip).unwrap();
    //  println!("eip {:x}", eip);
    match sys_num {
        SYS_gettimeofday => SyscallHookResult::new(Some(-1i64 as u64)),
        SYS_clockgettime => SyscallHookResult::new(Some(-1i64 as u64)),
        _ => SyscallHookResult::new(None),
    }
}
*/

// wrapper around general purpose register resets, mimics AFL_QEMU_PERSISTENT_GPR
///   ref: https://github.com/AFLplusplus/AFLplusplus/blob/stable/qemu_mode/README.persistent.md#24-resetting-the-register-state
#[derive(Default, Debug)]
pub struct QemuGPRegisterHelper {
    /// vector of values representing each registers saved value
    register_state: Vec<u32>,
}

/// implement the QemuHelper trait for QemuGPRegisterHelper
impl<I, S> QemuHelper<I, S> for QemuGPRegisterHelper
where
    I: libafl::inputs::Input,
    S: HasMetadata,
{
    /// prepare helper for fuzz case; called before every fuzz case
    fn pre_exec(&mut self, emulator: &Emulator, _input: &I) {
        self.restore(emulator);
    }
}

/// QemuGPRegisterHelper implementation
impl QemuGPRegisterHelper {
    /// given an `Emulator`, save off all known register values
    pub fn new(emulator: &Emulator) -> Self {
        let register_state = (0..emulator.num_regs())
            .map(|reg_idx| emulator.read_reg(reg_idx).unwrap())
            .collect::<Vec<_>>();

        Self { register_state }
    }

    /// restore emulator's registers to previously saved values
    fn restore(&self, emulator: &Emulator) {
        self.register_state
            .iter()
            .enumerate()
            .for_each(|(reg_idx, reg_val)| {
                if let Err(e) = emulator.write_reg(reg_idx as i32, *reg_val) {
                    println!(
                        "[ERR] Couldn't set register x{} ({}), skipping...",
                        reg_idx, e
                    )
                }
            })
    }
}
