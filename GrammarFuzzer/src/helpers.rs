// General imports
use libafl::{
    state::{HasMetadata},
    inputs::Input,
};

// Qemu imports
use libafl_qemu::{
    Emulator, QemuHelper, QemuHelperTuple, QemuHooks, SyscallHookResult,
};

use syscall_numbers::x86::*;

///  wrapper around general purpose register resets, mimics AFL_QEMU_PERSISTENT_GPR
///   ref: https://github.com/AFLplusplus/AFLplusplus/blob/stable/qemu_mode/README.persistent.md#24-resetting-the-register-state
///   ref: https://epi052.gitlab.io/notes-to-self/blog/2021-11-26-fuzzing-101-with-libafl-part-4/#QemuGPRegisterHelper
#[derive(Default, Debug)]
pub struct QemuGPRegisterHelper {
    /// vector of values representing each registers saved value
    register_state: Vec<u32>,
}

/// implement the QemuHelper trait for QemuGPRegisterHelper
impl<I, S> QemuHelper<I, S> for QemuGPRegisterHelper
where
    I: Input,
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

///  wrapper around general purpose register resets, mimics AFL_QEMU_PERSISTENT_GPR
#[derive(Default, Debug)]
pub struct QemuFakeFileHelper {
    fd_base: u32,
    fds: Vec<u32>,
}

const FAKE_FD_BASE: u32 = 0x10000;

impl<I, S> QemuHelper<I, S> for QemuFakeFileHelper
where
    I: Input,
    S: HasMetadata,
{
    fn init_hooks<QT>(&self, hooks: &QemuHooks<'_, I, QT, S>)
    where
        QT: QemuHelperTuple<I, S>,
    {
        hooks.syscalls(hook_file_syscalls::<I, QT, S>);
    }

    fn pre_exec(&mut self, emulator: &Emulator, _input: &I) {
        self.restore(emulator);
    }
}

impl QemuFakeFileHelper {
    pub fn new() -> Self {
        Self {
            fds: Vec::new(),
            fd_base: FAKE_FD_BASE,
        }
    }

    fn restore(&mut self, emulator: &Emulator) {
        self.fd_base = FAKE_FD_BASE;
        self.fds.clear();
    }

    fn handle_open(&mut self, a0: u32, a1: u32, a2: u32) -> SyscallHookResult {
        // write files are mockable by us
        if a1 & 1 != 0 {
            let new_fd = self.fd_base;
            self.fd_base += 1;
            self.fds.push(new_fd);
            /* Only used for debugging, so emu.load_addr is manually added here:
            let c_str: &std::ffi::CStr = unsafe { std::ffi::CStr::from_ptr((a0+0x10000) as *const _) };
            let str_slice: &str = c_str.to_str().unwrap();
            println!("Hooked open for {str_slice}");
            */
            return SyscallHookResult::new(Some(new_fd.into()));
        }
        return SyscallHookResult::new(None);
    }

    fn handle_close(&mut self, a0: u32, a1: u32, a2: u32) -> SyscallHookResult {
        if a0 >= FAKE_FD_BASE {
            if self.fds.contains(&a0) {
                // Remove the  fd from the list
                self.fds.retain(|&fd| fd != a0);
                return SyscallHookResult::new(Some(0))
            }
        }
        return SyscallHookResult::new(None);
    }

    fn handle_write(&mut self, a0: u32, a1: u32, a2: u32) -> SyscallHookResult {
        if a0 >= FAKE_FD_BASE {
            if self.fds.contains(&a0) {
                // Mock the write
                return SyscallHookResult::new(Some(a2.into()))
            }
        }
        return SyscallHookResult::new(None);
    }
}


#[allow(clippy::too_many_arguments)]
pub fn hook_file_syscalls<I, QT, S>(
    hooks: &mut QemuHooks<'_, I, QT, S>,
    _state: Option<&mut S>,
    sys_num: i32,
    a0: u64,
    a1: u64,
    a2: u64,
    _a3: u64,
    _a4: u64,
    _a5: u64,
    _a6: u64,
    _a7: u64,
) -> SyscallHookResult
where
    I: Input,
    QT: QemuHelperTuple<I, S>,
{
    let h = hooks.match_helper_mut::<QemuFakeFileHelper>().unwrap();
    let (a0, a1, a2) = (a0 as u32, a1 as u32, a2 as u32);
    match sys_num as i64 {
        SYS_open => h.handle_open(a0, a1, a2),
        SYS_write => h.handle_write(a0, a1, a2),
        SYS_mkdir | SYS_mkdirat => SyscallHookResult::new(Some(0)),
        _ =>  SyscallHookResult::new(None),
    }
}

