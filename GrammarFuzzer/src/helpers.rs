// General imports
use libafl::{
    state::{HasMetadata},
};

// Qemu imports
use libafl_qemu::{
    Emulator, QemuHelper,
};

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
