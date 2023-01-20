use std::{path::PathBuf, io::Read};
use core::ptr::addr_of_mut;

// General imports
use libafl::{
    bolts::{
        current_nanos,
        launcher::Launcher,
        core_affinity::Cores,
        rands::StdRand,
        shmem::{ShMemProvider, StdShMemProvider},
        tuples::tuple_list,
    },
    corpus::{Corpus, InMemoryCorpus, OnDiskCorpus},
    events::EventConfig,
    executors::{ExitKind, TimeoutExecutor},
    feedback_and_fast, feedback_or,
    feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::Input,
    monitors::MultiMonitor,
    mutators::StdScheduledMutator,
    observers::{HitcountsMapObserver, TimeObserver, VariableMapObserver},
    schedulers::{IndexesLenTimeMinimizerScheduler, QueueScheduler},
    stages::StdMutationalStage,
    state::{HasCorpus, HasMetadata, StdState},
    Error,
};

// Qemu imports
use libafl_qemu::{
    edges::{
        MAX_EDGES_NUM, edges_map_mut_slice, QemuEdgeCoverageHelper,
    },
    snapshot::QemuSnapshotHelper, Emulator, MmapPerms,
    QemuExecutor, QemuHooks, Regs,
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
use helpers::{QemuGPRegisterHelper, QemuFakeFileHelper};

mod grammar;

const SERVER_BINARY: &str = "./TrackmaniaServer";

const MAX_XML_SIZE: u32 = 0x00080000;

const XML_RPC_CALL: u32 = 0x087d8ba0;
const CRASH_DIR: &str = "../nautilus-crashes";
const CRASH_DIR_CONCRETE: &str = "../crashes";

// Take the entire output directory, copy all files over to a concrete directory.
fn create_concrete_outputs(context: &NautilusContext) {
    let crashes = std::fs::read_dir(CRASH_DIR).expect("Failed to read crashes");
    let out_dir = PathBuf::from(CRASH_DIR_CONCRETE);
    let mut tmp = vec![];
    for path in crashes {
        tmp.clear();
        let path = path.unwrap().path();
        if let Some(extension) = path.extension() {
            if extension == "lafl_lock" || extension == "metadata" {
                continue;
            }
        }
        // Check if this file was already converted.
        let out_file = out_dir.join(path.file_name().unwrap());
        if !out_file.exists() {
            let input = NautilusInput::from_file(path).expect(&format!("Failed to create NautilusInput ({out_file:?})"));
            input.unparse(context, &mut tmp);
            grammar::unparse_bounded(&context, &input, &mut tmp, MAX_XML_SIZE as usize);

            // Remove null terminator before writing to disk
            tmp.pop();
            std::fs::write(&out_file, &tmp).expect("Failed to write file contents");
            println!("Converted {:?}", &out_file);
        }
    }
}

fn main() -> Result<(), Error> {
    // Trackmania will want to load stuff relative to their server dir.
    std::env::set_current_dir(std::path::Path::new("../Server")).unwrap();

    // Do we want to exclude format string bugs?
    let no_format_string = std::env::args().find(|a| a == "--noformat").is_some();
    let do_repro = std::env::args().find(|a| a == "--repro").is_some();

    // Load a nautilus context
    let context = grammar::get_trackmania_context(10);

    if do_repro {
        create_concrete_outputs(&context);
        return Ok(());
    }

    let args = vec![
        "qemu-i386".to_string(),
        /* 
         Uncomment to attach GDB
        "-g".to_string(),
        "1234".to_string(),
        */
        SERVER_BINARY.to_string(),
        "/nodaemon".to_string(),
        "/lan".to_string(),
        "/nolog".to_string(),
        "/dedicated_cfg=dedicated_cfg.txt".to_string(),
        "/game_settings=MatchSettings/Nations/NationsGreen.txt".to_string(),
    ];

    std::env::remove_var("LD_LIBRARY_PATH");
    let env: Vec<(String, String)> = Vec::new();
    let emu = Emulator::new(&args, &env);

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
        .map_private(0, (2*MAX_XML_SIZE) as usize, MmapPerms::ReadWrite)
        .unwrap();
    println!("Mapped input buffer at {:x}", input_addr);

    let xml_size_p = xml_rpc_struct;
    let xml_data_p = xml_rpc_struct + 4;
    unsafe {
        // Edit the auth details in-place
        // 0 (God rights), 1 (SuperAdmin), 2 (Admin), 3 (User), 4 (Default)
        emu.write_mem(socket_auth, &0i32.to_le_bytes());
        // Set the data pointer to point to our mutated input
        emu.write_mem(xml_data_p, &input_addr.to_le_bytes());

        if no_format_string {
            // Silence the binary, as if we were in daemon mode
            emu.write_mem(0x08ce05e0u32, &1u32.to_le_bytes());
            let mut g_server_obj = [0; 4];
            emu.read_mem(0x08cbaab4u32, &mut g_server_obj);
            let g_server_obj = u32::from_le_bytes(g_server_obj);
            emu.write_mem(g_server_obj+0x4cu32, &0u32.to_le_bytes());
        }
    }

    // Set a breakpoint on the ret addr
    emu.set_breakpoint(ret);

    let input_corpus = InMemoryCorpus::new();
    let crash_dir = PathBuf::from(CRASH_DIR);
    let solutions_corpus = OnDiskCorpus::new(&crash_dir)?;

    let mut run_client = |state: Option<_>, mut mgr, _core_id| {
        let mut buf = vec![];
        // The wrapped harness function
        let mut harness = |input: &NautilusInput| {
            // Skip large inputs
            if !grammar::unparse_bounded(&context, input, &mut buf, MAX_XML_SIZE as usize) {
                return ExitKind::Ok;
            }

            let len_u32 = buf.len() as u32;
            unsafe {
                // Write our data into the expected format
                emu.write_mem(input_addr, &buf);
                emu.write_mem(xml_size_p, &len_u32.to_le_bytes());
            }

            // Run the emulator until next BP
            unsafe {
                emu.run();
            }

            ExitKind::Ok
        };

        let edges_observer = unsafe {
            HitcountsMapObserver::new(VariableMapObserver::from_mut_slice(
                "edges",
                edges_map_mut_slice(),
                addr_of_mut!(MAX_EDGES_NUM),
            ))
        };
    
        // Create an observation channel to keep track of the execution time and previous runtime
        let time_observer = TimeObserver::new("time");

        let mut feedback = feedback_or!(
            MaxMapFeedback::new_tracking(&edges_observer, true, false),
            TimeFeedback::with_observer(&time_observer),
            NautilusFeedback::new(&context)
        );

        let mut objective = CrashFeedback::new();

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
                &mut feedback,
                &mut objective,
            ).unwrap()
        });

        if state.metadata().get::<NautilusChunksMetadata>().is_none() {
            state.add_metadata(NautilusChunksMetadata::new("/dev/shm/".into()));
        }

        let scheduler = IndexesLenTimeMinimizerScheduler::new(QueueScheduler::new());

        let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);
        let mut hooks = QemuHooks::new(
            &emu,
            tuple_list!(
          //      QemuSnapshotHelper::new(),
                QemuGPRegisterHelper::new(&emu),
                QemuEdgeCoverageHelper::default(),
                QemuFakeFileHelper::new(),
            ),
        );

        let executor = QemuExecutor::new(
            &mut hooks,
            &mut harness,
            tuple_list!(edges_observer, time_observer),
            &mut fuzzer,
            &mut state,
            &mut mgr,
        )?;

        // wrap the `QemuExecutor` with a `TimeoutExecutor` that sets a timeout before each run
        let mut executor = TimeoutExecutor::new(executor, std::time::Duration::from_millis(800));
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

        // Setup a mutational stage with a basic bytes mutator
        let mutator = StdScheduledMutator::with_max_stack_pow(
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
        .cores(&Cores::from_cmdline("0-15").unwrap())
        //.stdout_file(Some("/dev/null"))
        .stdout_file(Some("/tmp/debug"))
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
