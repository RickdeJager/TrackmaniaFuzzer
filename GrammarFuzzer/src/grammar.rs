use libafl::generators::NautilusContext;
use libafl::inputs::NautilusInput;

use regex::Regex;

// return false if the input is too large to be useful
pub fn unparse_bounded(
    context: &NautilusContext,
    input: &NautilusInput,
    output_vec: &mut Vec<u8>,
    max_len: usize,
) -> bool {
    input.unparse(&context, output_vec);
    let old_len = output_vec.len();
    let new_len = std::cmp::min(old_len, max_len);
    output_vec.resize(new_len + 1, 0u8);
    old_len <= max_len
}

pub fn get_trackmania_context(tree_depth: usize) -> NautilusContext {
    // Generate a grammar string, nautilus does not expose the py engine :(
    let mut str_grammar = Vec::new();
    macro_rules! add_rule {
        ($a:expr, $b:expr) => {
            str_grammar.push([$a.to_string(), $b.to_string()].to_vec())
        };
    }

    add_rule!(
        "RPC-CALL",
        "<?xml version=\"1.0\"?><methodCall>{METHOD_CALL}</methodCall>"
    );

    let method_re = Regex::new(r"\w+ (.*)\((.*)\)").unwrap();
    for line in include_str!("grammar_data/methods-arg.list").lines() {
        // Extract method name and types
        let caps = method_re.captures(line).unwrap();
        let method_name = caps.get(1).unwrap().as_str();
        let args = caps.get(2).unwrap().as_str();
        let args: Vec<&str> = match args.is_empty() {
            true => Vec::new(),
            false => args.split(", ").collect(),
        };

        // prepare parameters
        let mut params = "".to_string();
        for arg in args {
            let typed_rule = match arg {
                "int" => "{INT_VALUE}",
                "double" => "{DOUBLE_VALUE}",
                "string" => "{STRING_VALUE}",
                "boolean" => "{BOOLEAN_VALUE}",
                "struct" => "{STRUCT_VALUE}",
                "array" => "{ARRAY_VALUE}",
                "base64" => "{BASE64_VALUE}",
                x => unreachable!("Unexpected type: >{}<", x),
            };
            params.push_str(&format!("<param>{typed_rule}</param>"));
        }

        // Add a strict rule for this method
        add_rule!(
            "METHOD_CALL",
            format!("<methodName>{method_name}</methodName><params>{params}</params>")
        )
    }

    // Register value types
    for rule in [
        "INT_VALUE",
        "DOUBLE_VALUE",
        "STRING_VALUE",
        "BOOLEAN_VALUE",
        "STRUCT_VALUE",
        "ARRAY_VALUE",
        "BASE64_VALUE",
    ] {
        let (tag, sub_rule) = match rule {
            "INT_VALUE" => ("i4", "{INT}"),
            "DOUBLE_VALUE" => ("double", "{DOUBLE}"),
            "STRING_VALUE" => ("string", "{STRING}"),
            "BOOLEAN_VALUE" => ("bool", "{BOOLEAN}"),
            "STRUCT_VALUE" => ("struct", "{STRUCT}"),
            "ARRAY_VALUE" => ("array", "{ARRAY}"),
            "BASE64_VALUE" => ("base64", "{BASE64}"),
            _ => unreachable!(),
        };

        add_rule!(rule, format!("<value><{tag}>{sub_rule}</{tag}></value>"));
        add_rule!("VALUE", format!("{{{rule}}}"));
    }

    // Strings
    for elem in [
        "",
        "%999999s", "%99 ", "%0999d",
        "{INT}",
        "dateTime.iso8601",
        "http://",
        "gbx://",
        "\\\\",
    ] {
        add_rule!("STRING", elem);
    }
    for c in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ%!@#$^&*()_+'<>?[]|,".chars() {
        add_rule!("STRING", c.to_string());
    }
    add_rule!("STRING", "{STRING}{STRING}");

    // Base64 (TODO)
    add_rule!("BASE64", "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQQo=");
    add_rule!("BASE64", "{STRING}");

    // Integers
    for elem in ["", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9"] {
        add_rule!("INT", elem);
    }
    add_rule!("INT", "{INT}{INT}");
    add_rule!("INT", "0");
    add_rule!("INT", "9999999999");
    add_rule!("INT", "{STRING}");

    // Doubles
    add_rule!("DOUBLE", "{INT}.{INT}");
    add_rule!("DOUBLE", "1.0");
    add_rule!("DOUBLE", "0.0");
    add_rule!("DOUBLE", "0.{INT}");
    add_rule!("DOUBLE", "{STRING}");

    // Booleans
    add_rule!("BOOLEAN", "1");
    add_rule!("BOOLEAN", "0");
    add_rule!("BOOLEAN", "{STRING}");

    // Structs
    let struct_member_names = [
        "GameMode",
        "ChatTime",
        "RoundsPointsLimit",
        "RoundsUseNewRules",
        "RoundsForcedLaps",
        "TimeAttackLimit",
        "TimeAttackSynchStartPeriod",
        "TeamPointsLimit",
        "TeamMaxPoints",
        "TeamUseNewRules",
        "LapsNbLaps",
        "LapsTimeLimit",
        "FinishTimeout",
        "AllWarmUpDuration",
        "DisableRespawn",
        "ForceShowAllOpponents",
        "RoundsPointsLimitNewRules",
        "TeamPointsLimitNewRules",
        "CupPointsLimit",
        "CupRoundsPerChallenge",
        "CupNbWinners",
        "CupWarmUpDurationName",
        "Comment",
        "Password",
        "PasswordForSpectator",
        "CurrentMaxPlayers",
        "NextMaxPlayers",
        "CurrentMaxSpectators",
        "NextMaxSpectators",
        "IsP2PUpload",
        "IsP2PDownload",
        "CurrentLadderMode",
        "NextLadderMode",
        "CurrentVehicleNetQuality",
        "NextVehicleNetQuality",
        "CurrentCallVoteTimeOut",
        "NextCallVoteTimeOut",
        "CallVoteRatio",
        "AllowChallengeDownload",
        "AutoSaveReplays",
        "RefereePassword",
        "RefereeMode",
        "AutoSaveValidationReplays",
        "HideServer",
        "CurrentUseChangingValidationSeed",
        "NextUseChangingValidationSeedOrig",
        "Name",
        "Checksum",
        "UrlCurrentValueNextValue",
    ];

    for elem in struct_member_names {
        add_rule!("STRUCT_MEMBER_NAME", elem);
    }

    for chunk in struct_member_names.windows(5) {
        let mut full_struct = String::new();
        for elem in chunk {
            full_struct.push_str(&format!("<member><name>{elem}</name>{{VALUE}}</member>"))
        }
        add_rule!("STRUCT", full_struct); // hacky shortcut to get a bunch of valid structs, fast.
    }

    add_rule!("STRUCT_MEMBER_NAME", "{STRING}");
    add_rule!("STRUCT", "{STRUCT}{STRUCT_CONTENT}");
    add_rule!(
        "STRUCT_CONTENT",
        "<member><name>{STRUCT_MEMBER_NAME}</name>{VALUE}</member>"
    );
    add_rule!("STRUCT", "");

    // Arrays with mixed content
    add_rule!(
        "ARRAY",
        "<data>{ARRAY_MIXED_CONTENT}{ARRAY_MIXED_CONTENT}</data>"
    );
    add_rule!("ARRAY_MIXED_CONTENT", "{VALUE}");
    add_rule!("ARRAY_MIXED_CONTENT", "");

    // Add Array's for each type
    for rule in [
        "INT_VALUE",
        "DOUBLE_VALUE",
        "STRING_VALUE",
        "BOOLEAN_VALUE",
        "STRUCT_VALUE",
        "ARRAY_VALUE",
        "BASE64_VALUE",
    ] {
        let array_content_name = format!("ARRAY_CONTENT_{rule}");
        add_rule!(
            "ARRAY",
            format!("<data>{{{array_content_name}}}{{{array_content_name}}}</data>")
        );
        add_rule!(array_content_name, format!("{{{rule}}}"));
        add_rule!(array_content_name, "");
    }

    println!("{:#?}", &str_grammar);
    NautilusContext::new(tree_depth, &str_grammar)
}
