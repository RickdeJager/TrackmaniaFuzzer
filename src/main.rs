use std::path::PathBuf;

// General imports
use libafl::{
    bolts::{
        current_nanos,
        launcher::Launcher,
        os::Cores,
        rands::StdRand,
        shmem::{ShMemProvider, StdShMemProvider},
        tuples::tuple_list,
    },
    corpus::{
        Corpus, InMemoryCorpus, OnDiskCorpus,
    },
    events::EventConfig,
    executors::{ExitKind, TimeoutExecutor, ShadowExecutor},
    feedback_and_fast, feedback_or,
    feedbacks::{CrashFeedback, MapFeedbackState, MaxMapFeedback, TimeFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::Input,
    monitors::MultiMonitor,
    mutators::StdScheduledMutator,
    observers::{HitcountsMapObserver, TimeObserver, VariableMapObserver},
    stages::StdMutationalStage,
    state::{HasCorpus, HasMetadata, StdState},
    schedulers::{IndexesLenTimeMinimizerScheduler, QueueScheduler},
    Error,
};

// Qemu imports
use libafl_qemu::{
    edges, edges::QemuEdgeCoverageHelper, snapshot::QemuSnapshotHelper,
    asan::QemuAsanHelper, init_with_asan, Emulator, MmapPerms, QemuExecutor, QemuHooks, Regs,
    cmplog,
    cmplog::{CmpLogObserver, QemuCmpLogHelper},
};

// Nautilus imports
use libafl::{
    feedbacks::{NautilusChunksMetadata, NautilusFeedback},
    generators::{NautilusContext, NautilusGenerator},
    inputs::NautilusInput,
    mutators::{NautilusRandomMutator, NautilusRecursionMutator, NautilusSpliceMutator},
};


// Own imports
mod helpers;
use helpers::{QemuTimeFreezeHelper, QemuGPRegisterHelper};

const SERVER_BINARY: &str = "./TrackmaniaServer";

const MAX_XML_SIZE: u32 = 0x6000;
//const XML_INIT: u32 = 0x085cad97; // XML specific
//const XML_INIT: u32 = 0x084c7890; // Game loop once

const XML_RPC_CALL: u32 = 0x087d8ba0;
const XML_RPC_EXIT_UNINIT: u32 = 0x087d8e09;
const XML_RPC_EXIT_TOO_LARGE: u32 = 0x087d8d09;
// Quit the fuzzer before sending a response, so we don't need a valid socket session.
// (For debugging, EAX contains the RPC error code here)
const XML_RPC_LEAVE: u32 = 0x087d8c53;
//const XML_RPC_LEAVE: u32 = 0x087d8cdd;

// These are not exploitable, beyond basic server crashes.
const TINYXML_ASSERT: u32 = 0x08a20e84;

// Exploitable, but known PC's
// (Currently, everything related to handling challenge file names contains format string vulns)
const AVOID_EXPLOITABLE: [u32; 9] = [
    0x080eaba0, 0x080e47b0, 0x080e20f0, 0x080ea760, 0x080ea980, 0x080e4cb0, 0x08794220, 0x082c4e30, 0x087942c9
];

const CRASH_DIR: &str = "./nautilus-crashes";
const CRASH_DIR_CONCRETE: &str = "./crashes";


// Take the entire output directory, copy all files over to a concrete directory.
fn create_concrete_outputs(context: &NautilusContext) {
    let crashes = std::fs::read_dir(CRASH_DIR).expect("Failed to read crashes");
    let out_dir = PathBuf::from(CRASH_DIR_CONCRETE);
    let mut tmp = vec![];
    for path in crashes {
        tmp.clear();
        let path = path.unwrap().path();
        if path.extension().unwrap_or_else(|| std::ffi::OsStr::new("")) == "lafl_lock" {
            continue;
        }
        // Check if this file was already converted.
        let out_file = out_dir.join(path.file_name().unwrap());
        if !out_file.exists() {
            let input = NautilusInput::from_file(path).expect("Failed to create NautilusInput");
            input.unparse(context, &mut tmp);
            let mut len = tmp.len();
            if len > MAX_XML_SIZE as usize {
                len = MAX_XML_SIZE as usize;
            }
            std::fs::write(&out_file, &tmp[..len]).expect("Failed to write file contents");
            println!("Converted {:?}", &out_file);
        }
    }
}

fn main() -> Result<(), Error> {
    // Trackmania will want to load stuff relative to their server dir.
    std::env::set_current_dir(std::path::Path::new("../Server")).unwrap();

    // Load a nautilus context from a grammar file.
    let context = NautilusContext::from_file(6, "./auto-grammar.json");

    if std::env::args()
        .collect::<Vec<String>>()
        .iter()
        .any(|arg| arg == "repro")
    {
        create_concrete_outputs(&context);
        return Ok(());
    }

    let mut args = vec![
        "qemu-i386".to_string(),
        SERVER_BINARY.to_string(),
        "/nodaemon".to_string(),
        "/lan".to_string(),
   //     "/verbose_rpc_full".to_string(),
   //     "/verbose_rpc".to_string(),
        "/dedicated_cfg=dedicated_cfg.txt".to_string(),
        "/game_settings=MatchSettings/Nations/NationsGreen.txt".to_string(),
    ];

    let mut env: Vec<(String, String)> = Vec::new();
    let emu = Emulator::new(&args, &env);
 //   let emu = init_with_asan(&mut args, &mut env);

    // Initialize the remote interface for trackmania
    //    emu.set_breakpoint(XML_INIT);
    emu.set_breakpoint(XML_RPC_CALL);
    unsafe { emu.run() };
    println!("RPC initialized");
    emu.remove_breakpoint(XML_RPC_CALL);

    // Find out where we need to swap in our input
    let esp: u32 = emu.read_reg(Regs::Esp).unwrap();

    let mut xml_rpc_struct = [0; 4];
    let mut socket_struct = [0; 4];
    let mut ret = [0; 4];
    unsafe {
        emu.read_mem(esp, &mut ret);
        emu.read_mem(esp + 4, &mut xml_rpc_struct);
        emu.read_mem(esp + 12, &mut socket_struct);
    }
    let ret = u32::from_le_bytes(ret);
    let xml_rpc_struct = u32::from_le_bytes(xml_rpc_struct);
    let socket_struct = u32::from_le_bytes(socket_struct);
    let socket_auth = socket_struct + 0x10;

    let input_addr: u32 = emu
        .map_private(0, MAX_XML_SIZE as usize, MmapPerms::ReadWrite)
        .unwrap();
    println!("Mapped input buffer at {:x}", input_addr);

    let xml_size_p = xml_rpc_struct;
    let xml_data_p = xml_rpc_struct + 4;
    let xml_size_p2 = xml_rpc_struct + 8;
    unsafe {
        // Edit the auth details in-place
        // 0 (God rights), 1 (SuperAdmin), 2 (Admin), 3 (User), 4 (Default)
        emu.write_mem(socket_auth, &0i32.to_le_bytes());
        // Set the data pointer to point to our mutated input
        emu.write_mem(xml_data_p, &input_addr.to_le_bytes());
    }

    // Setup breakpoints on all return paths
    emu.set_breakpoint(XML_RPC_EXIT_UNINIT);
    emu.set_breakpoint(XML_RPC_EXIT_TOO_LARGE);
    emu.set_breakpoint(XML_RPC_LEAVE);
    emu.set_breakpoint(TINYXML_ASSERT);

    // Set a breakpoint on the normal ret addr in case we missed an exit
    emu.set_breakpoint(ret);

    // Set breakpoints to avoid known exploitable code
    /*
    for bp in AVOID_EXPLOITABLE {
        emu.set_breakpoint(bp);
    }
    */

    let input_corpus = InMemoryCorpus::new();
    let crash_dir = PathBuf::from(CRASH_DIR);
    let solutions_corpus = OnDiskCorpus::new(&crash_dir)?;

    let mut run_client = |state: Option<_>, mut mgr, _core_id| {

        let mut buf = vec![];
        let empty = [0u8; MAX_XML_SIZE as usize];
        // The wrapped harness function
        let mut harness = |input: &NautilusInput| {
            input.unparse(&context, &mut buf);
            buf.push(b'\0');
            let mut len = buf.len();
            if len > MAX_XML_SIZE as usize {
                len = MAX_XML_SIZE as usize;
                buf[len-1] = b'\0';
            }
            let len_u32 = len as u32;

            unsafe {
                // Write our data into the expected format
                emu.write_mem(input_addr, &empty);
                emu.write_mem(input_addr, &buf[..len]);
                emu.write_mem(xml_size_p, &len_u32.to_le_bytes());
 //               emu.write_mem(xml_size_p2, &len_u32.to_le_bytes()); // TODO
            }

            // Run the emulator until next BP
            unsafe {
                emu.run();
            }

            ExitKind::Ok
        };

        let edges = unsafe { &mut edges::EDGES_MAP };
        let edges_size = unsafe { &mut edges::MAX_EDGES_NUM };
        let edges_observer =
            HitcountsMapObserver::new(VariableMapObserver::new("edges", edges, edges_size));

        // Create an observation channel to keep track of the execution time and previous runtime
        let time_observer = TimeObserver::new("time");

        // Create an observation channel using cmplog map
        let cmplog_observer = CmpLogObserver::new("cmplog", unsafe { &mut cmplog::CMPLOG_MAP }, true);

        let feedback_state = MapFeedbackState::with_observer(&edges_observer);
        let feedback = feedback_or!(
            MaxMapFeedback::new_tracking(&feedback_state, &edges_observer, true, false),
            TimeFeedback::new_with_observer(&time_observer),
            NautilusFeedback::new(&context)
        );

        let objective_state = MapFeedbackState::new("dedup_edges", edges::EDGES_MAP_SIZE);

        let objective = feedback_and_fast!(
            CrashFeedback::new(),
            MaxMapFeedback::new(&objective_state, &edges_observer)
        );

        let mut state = state.unwrap_or_else(|| {
            StdState::new(
                // random number generator with a time-based seed
                StdRand::with_seed(current_nanos()),
                // input corpus
                input_corpus.clone(),
                // solutions corpus
                solutions_corpus.clone(),
                // States of the feedbacks that store the data related to the feedbacks that should be
                // persisted in the State.
                tuple_list!(feedback_state, objective_state),
            )
        });

        if state.metadata().get::<NautilusChunksMetadata>().is_none() {
            state.add_metadata(NautilusChunksMetadata::new("/dev/shm/".into()));
        }

        let scheduler = IndexesLenTimeMinimizerScheduler::new(QueueScheduler::new());

        let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);
        let hooks = QemuHooks::new(
            &emu,
            tuple_list!(
                QemuSnapshotHelper::new(),
//                QemuAsanHelper::default(),
                QemuGPRegisterHelper::new(&emu),
                QemuCmpLogHelper::default(),
                QemuTimeFreezeHelper::default(),
                QemuEdgeCoverageHelper::default(),
            ),
        );

        let executor = QemuExecutor::new(
            hooks,
            &mut harness,
            tuple_list!(edges_observer, time_observer),
            &mut fuzzer,
            &mut state,
            &mut mgr,
        )?;

        // wrap the `QemuExecutor` with a `TimeoutExecutor` that sets a timeout before each run
        let executor = TimeoutExecutor::new(executor, std::time::Duration::from_millis(200));
        // Show the cmplog observer
        let mut executor = ShadowExecutor::new(executor, tuple_list!(cmplog_observer));

        let mut generator = NautilusGenerator::new(&context);

        // In case the corpus is empty (i.e. on first run), generate an initial corpus
        // corpus
        if state.corpus().count() < 1 {
            state
                .generate_initial_inputs_forced(
                    &mut fuzzer,
                    &mut executor,
                    &mut generator,
                    &mut mgr,
                    50,
                )
                .unwrap_or_else(|_| {
                    println!("Failed generate initial corpus");
                    std::process::exit(0);
                });
        }

        let mutator = StdScheduledMutator::with_max_iterations(
            tuple_list!(
                NautilusRandomMutator::new(&context),
                NautilusRandomMutator::new(&context),
                NautilusRandomMutator::new(&context),
                NautilusRandomMutator::new(&context),
                NautilusRandomMutator::new(&context),
                NautilusRecursionMutator::new(&context),
                NautilusRecursionMutator::new(&context),
                NautilusSpliceMutator::new(&context),
                NautilusSpliceMutator::new(&context),
            ),
            2,
        );
        let mut stages = tuple_list!(StdMutationalStage::new(mutator));

        fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)?;
        Ok(())
    };

    let monitor = MultiMonitor::new(|s| println!("{}", s));

    // Build and run a Launcher
    match Launcher::builder()
        .shmem_provider(StdShMemProvider::new()?)
        .configuration(EventConfig::from_build_id())
        .monitor(monitor)
        .run_client(&mut run_client)
        .cores(&Cores::from_cmdline("0-3").unwrap())
        //.stdout_file(Some("/dev/null"))
        .stdout_file(Some("/tmp/blah"))
        .build()
        .launch()
    {
        Ok(()) => Ok(()),
        Err(Error::ShuttingDown) => {
            println!("Fuzzing stopped by user. Good bye.");
            Ok(())
        }
        Err(err) => panic!("Failed to run launcher: {:?}", err),
    }
}
