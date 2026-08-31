//! The headless entry's command line and its key line.
//!
//! The login secret never crosses on the command line: a process argument
//! vector is world-readable on Linux and `ps` shows it everywhere. It arrives
//! on standard input, which leaves it neither in the argument vector nor on
//! disk.
//!
//! Both readers are pure over their input, so what each spelling means is
//! asserted without a process.

use std::ffi::OsString;
use std::io::BufRead;
use std::path::PathBuf;

use zeroize::Zeroizing;

use crate::engine::LOGIN_SECRET_LEN;

/// Selects the headless start. The login secret follows on standard input.
const DEV_KEY_STDIN: &str = "--dev-key-stdin";

/// Where the shell publishes its control endpoint.
const CONTROL_FILE: &str = "--control-file";

/// The longest key line this build reads. One key and its line ending are 66
/// bytes; anything larger is refused rather than buffered.
const MAX_KEY_LINE_BYTES: usize = 128;

/// The headless entry's arguments.
pub struct Options {
    /// Where the control endpoint is published.
    pub control_file: PathBuf,
}

/// What the headless entry runs on.
pub struct Headless {
    /// The login secret the session starts on.
    pub dev_key: Zeroizing<Vec<u8>>,
    /// Where the control endpoint is published.
    pub control_file: PathBuf,
}

/// Reads the headless entry's arguments, or reports why they are not one.
///
/// `Ok(None)` is the ordinary start: the caller gave no `--dev-key-stdin`.
/// `args` holds the arguments after the program name.
pub fn options(args: impl IntoIterator<Item = OsString>) -> Result<Option<Options>, String> {
    let mut headless = false;
    let mut control_file = None;
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        if arg == DEV_KEY_STDIN {
            headless = true;
        } else if arg == CONTROL_FILE {
            let value = args.next().ok_or_else(missing_path)?;
            control_file = Some(PathBuf::from(value));
        } else {
            return Err(format!(
                "{}: this build takes no such argument",
                arg.to_string_lossy()
            ));
        }
    }
    match (headless, control_file) {
        (false, _) => Ok(None),
        (true, Some(control_file)) => Ok(Some(Options { control_file })),
        (true, None) => Err(format!("{DEV_KEY_STDIN} needs {CONTROL_FILE}")),
    }
}

/// Reads the login secret from one line of `source`.
///
/// The line buffer is zeroized before this returns, whichever way it went.
pub fn read_dev_key(source: impl BufRead) -> Result<Zeroizing<Vec<u8>>, String> {
    let mut line = Zeroizing::new(Vec::new());
    let read = source
        .take(MAX_KEY_LINE_BYTES as u64 + 1)
        .read_until(b'\n', &mut line)
        .map_err(|error| format!("{DEV_KEY_STDIN} could not read standard input: {error}"))?;
    if read == 0 {
        return Err(format!(
            "{DEV_KEY_STDIN} found no key line on standard input"
        ));
    }
    if read > MAX_KEY_LINE_BYTES {
        return Err(format!(
            "{DEV_KEY_STDIN} needs a key line under {MAX_KEY_LINE_BYTES} bytes"
        ));
    }
    let whole: &[u8] = &line;
    let trimmed = whole.strip_suffix(b"\n").unwrap_or(whole);
    let trimmed = trimmed.strip_suffix(b"\r").unwrap_or(trimmed);
    login_secret(trimmed)
}

/// The login secret one key line carries.
pub fn login_secret(line: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
    if line.len() != LOGIN_SECRET_LEN * 2 {
        return Err(malformed_key());
    }
    let mut secret = Zeroizing::new(Vec::with_capacity(LOGIN_SECRET_LEN));
    for pair in line.chunks(2) {
        secret.push((digit(pair[0])? << 4) | digit(pair[1])?);
    }
    Ok(secret)
}

/// The key refusal. It never repeats the line it refused.
fn malformed_key() -> String {
    format!(
        "{DEV_KEY_STDIN} needs {} lowercase hex characters on standard input",
        LOGIN_SECRET_LEN * 2
    )
}

fn missing_path() -> String {
    format!("{CONTROL_FILE} needs a path")
}

/// One lowercase hex digit. Uppercase is refused so that one spelling reaches
/// this reader, and a suite cannot mint a key this build reads differently.
fn digit(character: u8) -> Result<u8, String> {
    match character {
        b'0'..=b'9' => Ok(character - b'0'),
        b'a'..=b'f' => Ok(character - b'a' + 10),
        _ => Err(malformed_key()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A made-up key: 32 bytes of `0xab`, which no session ever runs on.
    const KEY: &str = "abababababababababababababababababababababababababababababababab";

    fn parse(given: &[&str]) -> Result<Option<Options>, String> {
        options(given.iter().map(OsString::from).collect::<Vec<_>>())
    }

    fn read(line: &str) -> Result<Zeroizing<Vec<u8>>, String> {
        read_dev_key(line.as_bytes())
    }

    #[test]
    fn reads_a_well_formed_command_line() {
        let parsed = parse(&["--dev-key-stdin", "--control-file", "/tmp/control"])
            .expect("a well-formed command line")
            .expect("a headless start");
        assert_eq!(parsed.control_file, PathBuf::from("/tmp/control"));
    }

    #[test]
    fn reads_the_two_arguments_in_either_order() {
        let parsed = parse(&["--control-file", "/tmp/control", "--dev-key-stdin"])
            .expect("a well-formed command line")
            .expect("a headless start");
        assert_eq!(parsed.control_file, PathBuf::from("/tmp/control"));
    }

    #[test]
    fn a_command_line_with_no_headless_flag_is_an_ordinary_start() {
        assert!(parse(&[]).expect("no headless start").is_none());
        assert!(
            parse(&["--control-file", "/tmp/control"])
                .expect("no headless start")
                .is_none()
        );
    }

    #[test]
    fn refuses_a_headless_flag_that_names_no_control_file() {
        assert_eq!(
            parse(&["--dev-key-stdin"]).err(),
            Some("--dev-key-stdin needs --control-file".to_owned())
        );
    }

    #[test]
    fn refuses_a_control_file_with_no_value() {
        assert_eq!(
            parse(&["--dev-key-stdin", "--control-file"]).err(),
            Some(missing_path())
        );
    }

    #[test]
    fn refuses_an_argument_it_does_not_take() {
        assert_eq!(
            parse(&["--dev-key", KEY]).err(),
            Some("--dev-key: this build takes no such argument".to_owned())
        );
        assert_eq!(
            parse(&["--control-file", "/tmp/control", "--headless"]).err(),
            Some("--headless: this build takes no such argument".to_owned())
        );
    }

    #[test]
    fn reads_a_well_formed_key_line() {
        for line in [KEY, &format!("{KEY}\n"), &format!("{KEY}\r\n")] {
            let secret = read(line).expect("a well-formed key line");
            assert_eq!(secret.as_slice(), &[0xabu8; LOGIN_SECRET_LEN]);
        }
    }

    #[test]
    fn refuses_a_key_line_that_is_not_32_bytes_of_lowercase_hex() {
        for refused in [
            &KEY[..62],
            &format!("{KEY}ab") as &str,
            "not-hex-at-allnot-hex-at-allnot-hex-at-allnot-hex-at-allnot-hexx",
            &KEY.to_uppercase(),
            "\n",
        ] {
            assert_eq!(
                read(refused).err(),
                Some(malformed_key()),
                "{refused} was read"
            );
        }
    }

    #[test]
    fn refuses_standard_input_that_closed_with_no_line() {
        assert_eq!(
            read("").err(),
            Some("--dev-key-stdin found no key line on standard input".to_owned())
        );
    }

    #[test]
    fn refuses_a_key_line_past_the_byte_ceiling() {
        let flooded = "a".repeat(MAX_KEY_LINE_BYTES + 1);
        assert_eq!(
            read(&flooded).err(),
            Some(format!(
                "--dev-key-stdin needs a key line under {MAX_KEY_LINE_BYTES} bytes"
            ))
        );
    }

    /// The refusal is printed where a CI log keeps it, so it may not repeat the
    /// key it read.
    #[test]
    fn a_refusal_never_repeats_the_key() {
        assert!(!malformed_key().contains(KEY));
    }
}
