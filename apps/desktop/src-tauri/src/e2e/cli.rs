//! The headless entry's command line and its key line.
//!
//! The login secret never crosses on the command line: a process argument
//! vector is world-readable on Linux and `ps` shows it everywhere. It arrives
//! on standard input, which leaves it neither in the argument vector nor on
//! disk.
//!
//! Both readers are pure over their input, so what each spelling means is
//! asserted without a process.

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::Read;
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

/// What the headless entry runs on.
pub struct Headless {
    /// The login secret the session starts on.
    pub dev_key: Zeroizing<Vec<u8>>,
    /// Where the control endpoint is published.
    pub control_file: PathBuf,
}

/// The control file this command line names, or `None` if it asks for no
/// headless start.
///
/// `args` holds the arguments after the program name.
pub fn control_file(args: impl IntoIterator<Item = OsString>) -> Result<Option<PathBuf>, String> {
    let mut headless = false;
    let mut control_file = None;
    let mut args = args.into_iter().enumerate();
    while let Some((position, arg)) = args.next() {
        if arg == DEV_KEY_STDIN {
            headless = true;
        } else if arg == CONTROL_FILE {
            let (_, value) = args.next().ok_or_else(missing_path)?;
            control_file = Some(PathBuf::from(value));
        } else {
            return Err(unknown_argument(&arg, position));
        }
    }
    match (headless, control_file) {
        (false, _) => Ok(None),
        (true, Some(control_file)) => Ok(Some(control_file)),
        (true, None) => Err(format!("{DEV_KEY_STDIN} needs {CONTROL_FILE}")),
    }
}

/// The login secret standard input carries.
pub fn dev_key_from_stdin() -> Result<Zeroizing<Vec<u8>>, String> {
    read_dev_key(unbuffered_stdin()?)
}

/// Standard input as a handle of this reader's own.
///
/// [`std::io::stdin`] reads through a process-wide buffer that nothing can
/// clear, so a key line taken there outlives every [`Zeroizing`] owner. A
/// duplicate of the handle reads the same stream with no buffer at all.
fn unbuffered_stdin() -> Result<File, String> {
    #[cfg(unix)]
    let duplicated = {
        use std::os::fd::AsFd as _;
        std::io::stdin().as_fd().try_clone_to_owned()
    };
    #[cfg(windows)]
    let duplicated = {
        use std::os::windows::io::AsHandle as _;
        std::io::stdin().as_handle().try_clone_to_owned()
    };
    duplicated
        .map(File::from)
        .map_err(|error| format!("{DEV_KEY_STDIN} could not open standard input: {error}"))
}

/// Reads the login secret from one line of `source`.
///
/// The line lands in one buffer allocated at the byte ceiling. A buffer that
/// grew would free a partial copy of the key un-zeroized. What the buffer holds
/// is zeroized before this returns, whichever way it went.
pub fn read_dev_key(mut source: impl Read) -> Result<Zeroizing<Vec<u8>>, String> {
    let mut line = Zeroizing::new(vec![0u8; MAX_KEY_LINE_BYTES + 1]);
    let mut filled = 0;
    let mut newline = None;
    while newline.is_none() && filled < line.len() {
        let read = source
            .read(&mut line[filled..])
            .map_err(|error| format!("{DEV_KEY_STDIN} could not read standard input: {error}"))?;
        if read == 0 {
            break;
        }
        newline = line[filled..filled + read]
            .iter()
            .position(|byte| *byte == b'\n')
            .map(|at| filled + at);
        filled += read;
    }
    if filled == 0 {
        return Err(format!(
            "{DEV_KEY_STDIN} found no key line on standard input"
        ));
    }
    if newline.map_or(filled, |at| at + 1) > MAX_KEY_LINE_BYTES {
        return Err(format!(
            "{DEV_KEY_STDIN} needs a key line under {MAX_KEY_LINE_BYTES} bytes"
        ));
    }
    let whole = &line[..newline.unwrap_or(filled)];
    login_secret(whole.strip_suffix(b"\r").unwrap_or(whole))
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

/// The refusal for an argument this build does not take.
///
/// The refusal reaches a CI log, so it carries no value: a mistyped
/// `--dev-key=<secret>` is named by the text before the `=`, and an argument
/// that is not a flag is named by its position alone.
fn unknown_argument(arg: &OsStr, position: usize) -> String {
    let text = arg.to_string_lossy();
    let name = text.split('=').next().unwrap_or_default();
    if name.starts_with('-') {
        format!("{name}: this build takes no such argument")
    } else {
        format!(
            "argument {}: this build takes no such argument",
            position + 1
        )
    }
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

    /// Delivers its bytes one at a time, as a pipe may.
    struct OneByteAtATime<'a>(&'a [u8]);

    impl Read for OneByteAtATime<'_> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let Some((first, rest)) = self.0.split_first() else {
                return Ok(0);
            };
            if buf.is_empty() {
                return Ok(0);
            }
            buf[0] = *first;
            self.0 = rest;
            Ok(1)
        }
    }

    fn parse(given: &[&str]) -> Result<Option<PathBuf>, String> {
        control_file(given.iter().map(OsString::from).collect::<Vec<_>>())
    }

    fn read(line: &str) -> Result<Zeroizing<Vec<u8>>, String> {
        read_dev_key(line.as_bytes())
    }

    #[test]
    fn reads_a_well_formed_command_line() {
        let parsed = parse(&["--dev-key-stdin", "--control-file", "/tmp/control"])
            .expect("a well-formed command line")
            .expect("a headless start");
        assert_eq!(parsed, PathBuf::from("/tmp/control"));
    }

    #[test]
    fn reads_the_two_arguments_in_either_order() {
        let parsed = parse(&["--control-file", "/tmp/control", "--dev-key-stdin"])
            .expect("a well-formed command line")
            .expect("a headless start");
        assert_eq!(parsed, PathBuf::from("/tmp/control"));
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

    /// The refusal is printed where a CI log keeps it, so a value a mistyped
    /// argument carried may not reach it.
    #[test]
    fn a_refusal_never_repeats_what_an_argument_carried() {
        let flag = format!("--dev-key={KEY}");
        let named = parse(&[&flag]).expect_err("a refusal");
        assert_eq!(named, "--dev-key: this build takes no such argument");

        let positional = parse(&["--dev-key-stdin", KEY]).expect_err("a refusal");
        assert_eq!(positional, "argument 2: this build takes no such argument");
    }

    #[test]
    fn reads_a_well_formed_key_line() {
        for line in [KEY, &format!("{KEY}\n"), &format!("{KEY}\r\n")] {
            let secret = read(line).expect("a well-formed key line");
            assert_eq!(secret.as_slice(), &[0xabu8; LOGIN_SECRET_LEN]);
        }
    }

    /// A pipe may deliver the key line in pieces. One buffer takes them all,
    /// so no partial copy is left behind.
    #[test]
    fn reads_a_key_line_that_arrives_one_byte_at_a_time() {
        let line = format!("{KEY}\n");
        let secret = read_dev_key(OneByteAtATime(line.as_bytes())).expect("a well-formed key line");
        assert_eq!(secret.as_slice(), &[0xabu8; LOGIN_SECRET_LEN]);
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
        let over_long =
            format!("--dev-key-stdin needs a key line under {MAX_KEY_LINE_BYTES} bytes");
        assert_eq!(read(&flooded).err(), Some(over_long.clone()));
        assert_eq!(
            read_dev_key(OneByteAtATime(flooded.as_bytes())).err(),
            Some(over_long)
        );
    }

    /// The refusal is printed where a CI log keeps it, so it may not repeat the
    /// key it read.
    #[test]
    fn a_refusal_never_repeats_the_key() {
        assert!(!malformed_key().contains(KEY));
    }
}
