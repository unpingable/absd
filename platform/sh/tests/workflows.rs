//! Real files, native host processes and the production AST/evaluator.
//! This Host adapter tests language/executor planning. ABSD pipe supervision
//! and authority transfer remain target-specific and require guest execution.
use absd_sh::*;
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    process::{Command, Stdio},
};

struct Native;
impl Host for Native {
    type Source = File;
    type Sink = File;
    fn open_read(&mut self, path: &str) -> io::Result<File> {
        File::open(path)
    }
    fn open_write(&mut self, path: &str, append: bool) -> io::Result<File> {
        OpenOptions::new()
            .write(true)
            .create(true)
            .append(append)
            .truncate(!append)
            .open(path)
    }
    fn is_dir(&mut self, path: &str) -> io::Result<bool> {
        fs::metadata(path).map(|m| m.is_dir())
    }
    fn session_request(&mut self, _: SessionRequest) -> io::Result<(i32, String)> {
        Err(io::ErrorKind::Unsupported.into())
    }
    fn run(&mut self, stages: Vec<Stage<File, File>>) -> Vec<Ran> {
        use std::{io::Read, thread};
        type Drain = (usize, thread::JoinHandle<io::Result<Vec<u8>>>, Box<dyn Write>);
        fn output(output: Output<File>, slot: usize, merge: bool,
                  previous: &mut Option<io::PipeReader>, drains: &mut Vec<Drain>, stage: usize)
                  -> (Stdio, Option<Stdio>) {
            let parent = match output {
                Output::Inherit => Some(slot),
                Output::ParentStdout => Some(0),
                Output::ParentStderr => Some(1),
                _ => None,
            };
            if let Some(parent) = parent {
                let stdio = || if parent == 0 { Stdio::from(io::stdout()) } else { Stdio::from(io::stderr()) };
                return (stdio(), merge.then(stdio));
            }
            let (mut reader, writer) = io::pipe().unwrap();
            let second = merge.then(|| Stdio::from(writer.try_clone().unwrap()));
            let sink: Option<Box<dyn Write>> = match output {
                Output::Next => None,
                Output::Shared(sink) => Some(Box::new(sink)),
                Output::Capture(sink) => Some(Box::new(sink)),
                Output::Discard => Some(Box::new(io::sink())),
                _ => unreachable!("resolved destination"),
            };
            if let Some(sink) = sink {
                drains.push((stage, thread::spawn(move || {
                    let mut bytes = Vec::new(); reader.read_to_end(&mut bytes)?; Ok(bytes)
                }), sink));
            } else {
                *previous = Some(reader);
            }
            (Stdio::from(writer), second)
        }
        let mut previous = None;
        let mut children = Vec::new();
        let mut ran = Vec::new();
        let mut drains = Vec::new();
        let mut feeds = Vec::new();
        for (index, stage) in stages.into_iter().enumerate() {
            let mut cmd = Command::new(stage.program);
            cmd.args(stage.args).current_dir(stage.cwd).env_clear().envs(stage.env);
            let feed: Option<Box<dyn Read + Send>> = match stage.stdin {
                Input::Inherit => { cmd.stdin(Stdio::null()); None },
                Input::Previous => { cmd.stdin(previous.take().map_or_else(Stdio::null, Stdio::from)); None },
                Input::File(file) => Some(Box::new(file)),
                Input::Bytes(bytes) => Some(Box::new(io::Cursor::new(bytes))),
            };
            if let Some(mut source) = feed {
                let (reader, mut writer) = io::pipe().unwrap();
                cmd.stdin(Stdio::from(reader));
                feeds.push(thread::spawn(move || io::copy(&mut source, &mut writer)));
            }
            let merge = matches!(stage.stderr, Output::SameAsStdout);
            let (stdout, alias) = output(stage.stdout, 0, merge, &mut previous, &mut drains, index);
            cmd.stdout(stdout);
            if let Some(stderr) = alias {
                cmd.stderr(stderr);
            } else {
                cmd.stderr(output(stage.stderr, 1, false, &mut previous, &mut drains, index).0);
            }
            match cmd.spawn() {
                Ok(child) => { children.push(Some(child)); ran.push(Ran { exit: Ok(Exit::Other), redirect: None }); },
                Err(error) => { children.push(None); ran.push(Ran { exit: Err(error), redirect: None }); },
            }
            drop(cmd);
        }
        drop(previous);
        for (index, child) in children.into_iter().enumerate() {
            if let Some(mut child) = child { ran[index].exit = child.wait().map(|s| Exit::Code(s.code().unwrap_or(128))); }
        }
        for feed in feeds { let _ = feed.join().unwrap(); }
        for (stage, reader, mut sink) in drains {
            let result = reader.join().unwrap().and_then(|bytes| sink.write_all(&bytes)).and_then(|_| sink.flush());
            if let Err(error) = result { ran[stage].redirect = Some(error); }
        }
        ran
    }
}
struct Workspace(std::path::PathBuf);
impl Workspace {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "absd-shell133-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn shell(&self) -> Shell<Native> {
        Shell::new(Native, self.0.to_str().unwrap().into())
    }
    fn put(&self, name: &str, text: &str) {
        fs::write(self.0.join(name), text).unwrap();
    }
}
impl Drop for Workspace {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
fn run(shell: &mut Shell<Native>, text: &str) -> (i32, String, String) {
    let (mut out, mut err) = (Vec::new(), Vec::new());
    shell.run_line(text, &mut out, &mut err);
    (
        shell.status,
        String::from_utf8(out).unwrap(),
        String::from_utf8(err).unwrap(),
    )
}

#[test]
fn quiet_conditions_native_false_guards_keep_branch_and_loop_results() {
    for (script, want, code) in [
        ("if /bin/test -e absent; then echo WRONG; else echo false:$?; fi", "false:1\n", 0),
        ("if /bin/test -e absent; then echo WRONG; elif /bin/test -e also-absent; then echo WRONG; else echo else:$?; fi", "else:1\n", 0),
        ("i=0; while /bin/test $i -lt 2; do i=$((i+1)); echo $i; done", "1\n2\n", 0),
        ("i=0; until /bin/test $i -ge 2; do i=$((i+1)); echo $i; done", "1\n2\n", 0),
        ("/bin/test -e absent || echo recovered", "recovered\n", 0),
        ("/bin/test -e absent && echo WRONG", "", 1),
        ("! /bin/test -e absent; echo negated:$?", "negated:0\n", 0),
    ] {
        let ws = Workspace::new();
        let (status, out, err) = run(&mut ws.shell(), script);
        assert_eq!(status, code, "{script}");
        assert_eq!(out, want, "{script}");
        assert_eq!(err, "", "{script}");
    }
}

#[test]
fn quiet_conditions_inherit_through_functions_groups_and_nested_lists() {
    for script in [
        "f() { /bin/test -e absent; }; if f; then echo WRONG; else echo recovered; fi",
        "if { /bin/test -e absent; /bin/test -e also-absent; }; then echo WRONG; else echo recovered; fi",
        "if true && /bin/test -e absent; then echo WRONG; else echo recovered; fi",
        "if { if /bin/test -e absent; then echo WRONG; fi; /bin/test -e absent; }; then echo WRONG; else echo recovered; fi",
    ] {
        let ws = Workspace::new();
        assert_eq!(run(&mut ws.shell(), script), (0, "recovered\n".into(), "".into()), "{script}");
    }
}

#[test]
fn quiet_conditions_preserve_script_native_and_launch_diagnostics() {
    let ws = Workspace::new();
    ws.put("predicate.sh", "#!/bin/sh\necho predicate diagnostic >&2\n/bin/false\n");
    assert_eq!(run(&mut ws.shell(), "if ./predicate.sh; then echo WRONG; else echo recovered:$?; fi"),
               (0, "recovered:1\n".into(), "predicate diagnostic\n".into()));
    let (status, out, err) = run(&mut ws.shell(), "if ./missing-program; then echo WRONG; else echo recovered:$?; fi");
    assert_eq!((status, out), (0, "recovered:127\n".into()));
    assert!(err.contains("missing-program") && err.contains("not found"), "{err:?}");
    let (status, out, err) = run(&mut ws.shell(), "if /bin/cat absent 2> native-errors; then echo WRONG; else echo recovered:$?; fi");
    assert_eq!((status, out, err), (0, "recovered:1\n".into(), "".into()));
    let native = fs::read_to_string(ws.0.join("native-errors")).unwrap();
    assert!(native.contains("absent") && native.contains("No such file"), "{native:?}");
}

#[test]
fn quiet_conditions_preserve_nonunit_statuses_and_negation() {
    for (script, status, out, err) in [
        ("/bin/bash -c 'exit 7' || echo s:$?", 0, "s:7\n", ""),
        ("if /bin/bash -c 'exit 7'; then :; else echo s:$?; fi", 0, "s:7\n", ""),
        ("while /bin/bash -c 'exit 7'; do :; done; echo s:$?", 0, "s:0\n", ""),
        ("/bin/bash -c 'exit 7' && echo WRONG; echo s:$?", 0, "s:7\n", ""),
        ("! /bin/bash -c 'exit 7'; echo s:$?", 0, "s:0\n", ""),
        ("! /bin/true; echo s:$?", 0, "s:1\n", ""),
        ("/bin/bash -c 'exit 7'", 7, "", "absd-sh: /bin/bash: exit status 7\n"),
        ("if /bin/echo x | /bin/bash -c 'cat >/dev/null; exit 7'; then :; else echo s:$?; fi", 0, "s:7\n", ""),
    ] {
        let ws = Workspace::new();
        assert_eq!(run(&mut ws.shell(), script), (status, out.into(), err.into()), "{script}");
    }
}

#[test]
fn quiet_conditions_restore_reporting_for_ordinary_final_commands_and_errors() {
    let ws = Workspace::new();
    let mut shell = ws.shell();
    assert_eq!(run(&mut shell, "if /bin/test -e absent; then echo WRONG; fi; /bin/false"),
               (1, "".into(), "absd-sh: /bin/false: exit status 1\n".into()));
    assert_eq!(run(&mut shell, "true && /bin/false"),
               (1, "".into(), "absd-sh: /bin/false: exit status 1\n".into()));
    let (_, _, err) = run(&mut shell, "if echo $((1 / 0)); then echo WRONG; fi");
    assert!(err.contains("division by zero"), "{err:?}");
    assert_eq!(run(&mut shell, "/bin/false"),
               (1, "".into(), "absd-sh: /bin/false: exit status 1\n".into()));
}
#[test]
fn real_script_arguments_status_environment_and_atomic_edit() {
    let ws = Workspace::new();
    ws.put("task.sh", "#!/bin/sh\nexport OPERATOR='field tech'\necho \"$0:$#:$1\"\n/bin/printenv OPERATOR > env.txt\nif /bin/test -f env.txt; then\nfor word in alpha 'beta gamma'; do echo \"$word\" >> result.txt; done\nfi\necho \"$(/bin/cat env.txt)\"\necho \"$(/bin/cat result.txt | /bin/wc -l)\"\n/bin/cp result.txt result.old\n/bin/sed 's/alpha/revised/' result.old > result.new\n/bin/mv result.new result.txt\n");
    let mut shell = ws.shell();
    let (status, out, err) = run(&mut shell, "sh task.sh first");
    assert_eq!(status, 0, "{err}");
    assert_eq!(err, "");
    assert_eq!(out, "task.sh:1:first\nfield tech\n2\n");
    assert_eq!(
        fs::read_to_string(ws.0.join("result.txt")).unwrap(),
        "revised\nbeta gamma\n"
    );
    assert_eq!(
        run(&mut shell, "echo \"${OPERATOR:-private}\"").1,
        "private\n"
    );
}
#[test]
fn direct_shebang_glob_and_quoted_glob() {
    let ws = Workspace::new();
    ws.put("b.txt", "b");
    ws.put("a.txt", "a");
    ws.put(".hidden.txt", "h");
    ws.put(
        "run",
        "#!/bin/sh\nfor file in *.txt; do echo \"$file\"; done\necho '*.txt' \\*\\.txt\n",
    );
    let (status, out, err) = run(&mut ws.shell(), "./run");
    assert_eq!(status, 0, "{err}");
    assert_eq!(out, "a.txt\nb.txt\n*.txt *.txt\n");
}
#[test]
fn loops_functions_positional_and_isolated_substitution() {
    let ws = Workspace::new();
    let mut shell = ws.shell();
    let (status, out, err) = run(
        &mut shell,
        "set -- 'one two' three; f() { echo \"$1\"; }; for arg; do f \"$arg\"; done; i=0; while /bin/test $i -lt 3; do i=$((i+1)); if /bin/test $i -eq 2; then continue; fi; echo $i; done; echo \"$(i=9; cd /; echo $i)\"; echo $i; until true; do echo wrong; done; case done in d*) echo matched;; esac",
    );
    assert_eq!(status, 0, "{err}");
    assert_eq!(out, "one two\nthree\n1\n3\n9\n3\nmatched\n");
    assert_eq!(shell.cwd, ws.0.to_str().unwrap());
}
#[test]
fn script_and_compound_redirects_include_native_children() {
    let ws = Workspace::new();
    ws.put("run", "#!/bin/sh\necho first\n/bin/printf 'second\\n'\n");
    let (status, out, err) = run(
        &mut ws.shell(),
        "sh run > result; { echo third; /bin/cat result; } > combined; echo \"$(/bin/cat combined)\"",
    );
    assert_eq!(status, 0, "{err}");
    assert_eq!(out, "third\nfirst\nsecond\n");
}
#[test]
fn exported_environment_and_local_assignments_have_bounded_scope() {
    let ws = Workspace::new();
    let mut shell = ws.shell();
    let (status, out, err) = run(
        &mut shell,
        "X=outer; export X; X='command local' /bin/printenv X > local; /bin/printenv X > outer; echo \"$(/bin/cat local):$(/bin/cat outer)\"; unset X; echo \"${X:-unset}\"",
    );
    assert_eq!(status, 0, "{err}");
    assert_eq!(out, "command local:outer\nunset\n");
}
#[test]
fn rejected_constructs_produce_usage_errors_and_no_output() {
    let ws = Workspace::new();
    for text in [
        "echo bad &",
        "echo bad 2>&3",
        "echo bad <<EOF\ndata\nEOF",
        "{ echo bad; } | /bin/cat",
        "echo $((1/0))",
        "sh run < input",
    ] {
        let (status, out, err) = run(&mut ws.shell(), text);
        assert_eq!(status, 2, "{text}: {err}");
        assert_eq!(out, "", "{text}");
        assert!(!err.is_empty(), "{text}");
    }
}
#[test]
fn capture_overflow_is_a_failure() {
    let ws = Workspace::new();
    ws.put("large", &"x".repeat(MAX_SCRIPT_BYTES + 1));
    let (status, _, err) = run(&mut ws.shell(), "value=$(/bin/cat large)");
    assert_ne!(status, 0, "{err}");
    assert!(err.contains("1 MiB"), "{err}");
}
#[test]
fn literal_empty_arguments_and_quoted_at_preserve_boundaries() {
    let ws = Workspace::new();
    let mut shell = ws.shell();
    let (status, out, err) = run(
        &mut shell,
        "set --; /bin/printf '<%s>\\n' \"$@\" > empty1; echo \"$(/bin/cat empty1)\"; set -- '' 'a b'; /bin/printf '<%s>\\n' \"$@\" > empty2; echo \"$(/bin/cat empty2)\"; echo x${unset}y; echo \"${unset:+bad}\"; echo \"${set:=saved}\"; echo $set",
    );
    assert_eq!(status, 0, "{err}");
    assert_eq!(out, "<>\n<>\n<a b>\nxy\n\nsaved\nsaved\n");
}

#[test]
fn field_splitting_happens_after_concatenation_and_preserves_quoted_at() {
    let ws = Workspace::new();
    let (status, out, err) = run(
        &mut ws.shell(),
        "value=' one two '; set -- $value'last'; echo \"$#:$1:$2:$3\"; set -- a 'b c'; set -- pre\"$@\"post; echo \"$#:$1:$2\"; HOME=/home/operator; echo ~/notes; export value=$value; echo \"$value\"",
    );
    assert_eq!(status, 0, "{err}");
    assert_eq!(
        out,
        "3:one:two:last\n2:prea:b cpost\n/home/operator/notes\n one two \n"
    );
}

#[test]
fn native_pipeline_from_builtin_and_substitution_trailing_newlines() {
    let ws = Workspace::new();
    let (status, out, err) = run(
        &mut ws.shell(),
        "echo \"$(echo 'hello world' | /bin/cat)\"; echo \"$(/bin/printf 'two\\n\\n')\"",
    );
    assert_eq!(status, 0, "{err}");
    assert_eq!(out, "hello world\ntwo\n");
}

#[test]
fn empty_script_success_does_not_inherit_failed_parent_status() {
    let ws = Workspace::new();
    ws.put("empty", "#!/bin/sh\n# comment\n");
    let (status, out, err) = run(&mut ws.shell(), "false; ./empty; echo $?");
    assert_eq!(status, 0, "{err}");
    assert_eq!(out, "0\n");
}

struct Interrupting {
    calls: usize,
    native: Native,
}
impl Host for Interrupting {
    type Source = File;
    type Sink = File;
    fn open_read(&mut self, p: &str) -> io::Result<File> {
        self.native.open_read(p)
    }
    fn open_write(&mut self, p: &str, a: bool) -> io::Result<File> {
        self.native.open_write(p, a)
    }
    fn is_dir(&mut self, p: &str) -> io::Result<bool> {
        self.native.is_dir(p)
    }
    fn session_request(&mut self, r: SessionRequest) -> io::Result<(i32, String)> {
        self.native.session_request(r)
    }
    fn run(&mut self, s: Vec<Stage<File, File>>) -> Vec<Ran> {
        self.native.run(s)
    }
    fn interrupted(&mut self) -> bool {
        self.calls += 1;
        self.calls == 8
    }
}
#[test]
fn interrupt_inside_builtin_substitution_stops_outer_list() {
    let ws = Workspace::new();
    let mut shell = Shell::new(
        Interrupting {
            calls: 0,
            native: Native,
        },
        ws.0.to_str().unwrap().into(),
    );
    let (mut out, mut err) = (Vec::new(), Vec::new());
    shell.run_line(
        "echo \"$(while true; do :; done)\"; echo wrong",
        &mut out,
        &mut err,
    );
    assert_eq!(shell.status, 130);
    assert!(out.is_empty(), "{}", String::from_utf8_lossy(&out));
}

#[test]
fn capture_overflow_in_argument_prevents_the_outer_command() {
    let ws = Workspace::new();
    ws.put("large", &"x".repeat(MAX_SCRIPT_BYTES + 1));
    let (status, out, err) = run(&mut ws.shell(), "echo \"$(/bin/cat large)\"; echo wrong");
    assert_eq!(status, 2, "{err}");
    assert!(out.is_empty());
    assert!(err.contains("1 MiB"));
}
#[test]
fn cd_defaults_to_home_and_tracks_exported_pwd() {
    let ws = Workspace::new();
    let script = format!(
        "HOME='{}'; cd /; cd; echo \"$PWD:$OLDPWD\"; /bin/printenv PWD > pwd; echo \"$(/bin/cat pwd)\"",
        ws.0.display()
    );
    let (status, out, err) = run(&mut ws.shell(), &script);
    assert_eq!(status, 0, "{err}");
    assert_eq!(out, format!("{}:/\n{}\n", ws.0.display(), ws.0.display()));
}

#[test]
fn quoted_case_patterns_and_named_user_tilde_remain_literal() {
    let ws = Workspace::new();
    let (status, out, err) = run(
        &mut ws.shell(),
        "case abc in 'a*') echo wrong;; a*) echo matched;; esac; echo ~someone",
    );
    assert_eq!(status, 0, "{err}");
    assert_eq!(out, "matched\n~someone\n");
}

#[test]
fn operator_replay_script_is_parsed_by_production_language() {
    // Wrong arity takes the fixture's usage path before touching the filesystem.
    let ws = Workspace::new();
    ws.put(
        "operator-smoke",
        include_str!("../../fixtures/shell-operator-smoke.sh"),
    );
    let (status, out, _) = run(&mut ws.shell(), "sh operator-smoke");
    assert_eq!(status, 2);
    assert_eq!(
        out,
        "usage: sh shell-operator-smoke.sh NEW_WRITABLE_DIRECTORY\n"
    );
}

#[test]
fn unsupported_control_builtins_fail_before_any_program_effect() {
    let ws = Workspace::new();
    for name in [
        "return", "read", "trap", "exec", "eval", "wait", "local", "getopts", "ulimit", "umask",
        "jobs", "fg", "bg",
    ] {
        let (status, out, err) = run(
            &mut ws.shell(),
            &format!("echo BEFORE; if false; then {name}; fi; echo AFTER"),
        );
        assert_eq!(status, 2, "{name}: {err}");
        assert!(out.is_empty(), "{name}: {out}");
    }
}
#[test]
fn prefix_assignments_are_sequential_and_restore_only_the_assigned_keys() {
    let ws = Workspace::new();
    ws.put("library", "LIBRARY=loaded; libfn() { echo function; }\n");
    let text = format!(
        "a=1 b=$a; echo [$b]; f() {{ R=done; }}; X=1 f; echo [$R]; X=1 cd '{}'; echo $PWD; X=1 . library; echo [$LIBRARY]; libfn; echo [${{X:-gone}}]",
        ws.0.display()
    );
    let (status, out, err) = run(&mut ws.shell(), &text);
    assert_eq!(status, 0, "{err}");
    assert_eq!(
        out,
        format!(
            "[1]\n[done]\n{}\n[loaded]\nfunction\n[gone]\n",
            ws.0.display()
        )
    );
}
#[test]
fn unsupported_ast_forms_are_refused_before_redirections_or_earlier_commands() {
    let ws = Workspace::new();
    for text in [
        "echo BEFORE > touched; /bin/cat missing 2>&3",
        "echo BEFORE; echo ${name%pattern}",
        "echo BEFORE; echo $((1<<2))",
        "echo BEFORE; echo $(echo AFTER &)",
    ] {
        let (status, out, err) = run(&mut ws.shell(), text);
        assert_eq!(status, 2, "{text}: {err}");
        assert!(out.is_empty(), "{text}: {out}");
        assert!(!ws.0.join("touched").exists());
    }
}
#[test]
fn inline_script_errors_become_status_for_the_callers_conditional() {
    let ws = Workspace::new();
    ws.put("bad", "echo WRONG\nreturn 1\n");
    for call in ["sh bad", ". bad"] {
        let (status, out, err) = run(
            &mut ws.shell(),
            &format!("if {call}; then echo WRONG; else echo recovered:$?; fi; echo AFTER"),
        );
        assert_eq!(status, 0, "{call}: {err}");
        assert_eq!(out, "recovered:2\nAFTER\n");
        assert!(err.contains("unsupported"), "{err}");
    }
}

#[test]
fn real_child_combined_output_preserves_write_order_and_alias_snapshot() {
    let ws = Workspace::new();
    std::os::unix::fs::symlink("/bin/sh", ws.0.join("dual")).unwrap();
    let mut shell = ws.shell();
    let (status, out, err) = run(&mut shell,
        "./dual -c 'printf out; printf err >&2; printf end' > combined 2>&1; echo \"$(/bin/cat combined)\"; echo \"$(./dual -c 'printf out; printf err >&2' 2>&1 > separated)\"; echo \"$(/bin/cat separated)\"");
    assert_eq!(status, 0, "{err}");
    assert_eq!(err, "");
    assert_eq!(out, "outerrend\nerr\nout\n");
    assert_eq!(fs::read(ws.0.join("combined")).unwrap(), b"outerrend");
    assert_eq!(fs::read(ws.0.join("separated")).unwrap(), b"out");
}

#[test]
fn real_stderr_can_retain_the_pipeline_after_stdout_is_redirected() {
    let ws = Workspace::new();
    std::os::unix::fs::symlink("/bin/sh", ws.0.join("dual")).unwrap();
    let (status, out, err) = run(&mut ws.shell(),
        "./dual -c 'printf out; printf err >&2' 2>&1 > separate | /bin/cat > piped; echo \"$(/bin/cat piped)\"; echo \"$(/bin/cat separate)\"");
    assert_eq!(status, 0, "{err}");
    assert_eq!(err, "");
    assert_eq!(out, "err\nout\n");
}

#[test]
fn real_combined_output_larger_than_pipe_capacity_keeps_child_write_order() {
    let ws = Workspace::new();
    std::os::unix::fs::symlink("/bin/sh", ws.0.join("dual")).unwrap();
    let (status, out, err) = run(&mut ws.shell(),
        "./dual -c 'i=0; while test \"$i\" -lt 20000; do printf \"O%s\\n\" \"$i\"; printf \"E%s\\n\" \"$i\" >&2; i=$((i+1)); done' > combined 2>&1");
    assert_eq!(status, 0, "{err}");
    assert!(out.is_empty() && err.is_empty());
    let expected = (0..20000).map(|i| format!("O{i}\nE{i}\n")).collect::<String>();
    assert!(expected.len() > 65536);
    assert_eq!(fs::read(ws.0.join("combined")).unwrap(), expected.as_bytes());
}

#[test]
fn overwritten_pipe_and_refused_stage_deliver_eof_and_leave_the_next_command_usable() {
    let ws = Workspace::new();
    std::os::unix::fs::symlink("/bin/sh", ws.0.join("dual")).unwrap();
    let mut shell = ws.shell();
    let (status, _, err) = run(&mut shell,
        "./dual -c 'printf only' > separate | /bin/cat > empty; /bin/printf after > after");
    assert_eq!(status, 0, "{err}");
    assert_eq!(fs::read(ws.0.join("separate")).unwrap(), b"only");
    assert!(fs::read(ws.0.join("empty")).unwrap().is_empty());
    assert_eq!(fs::read(ws.0.join("after")).unwrap(), b"after");
    let (status, _, err) = run(&mut shell,
        "./missing 2>&1 | /bin/cat > refused-empty; ./dual -c 'printf out; printf err >&2' > out 2> err");
    assert_eq!(status, 0, "{err}");
    assert!(err.contains("not found"));
    assert!(fs::read(ws.0.join("refused-empty")).unwrap().is_empty());
    assert_eq!(fs::read(ws.0.join("out")).unwrap(), b"out");
    assert_eq!(fs::read(ws.0.join("err")).unwrap(), b"err");
}

#[test]
fn later_open_failure_preserves_earlier_truncation_and_never_starts_the_consumer() {
    let ws = Workspace::new();
    std::os::unix::fs::symlink("/bin/sh", ws.0.join("dual")).unwrap();
    ws.put("opened", "old contents");
    let mut shell = ws.shell();
    let (status, out, err) = run(&mut shell, "./dual -c 'printf effect > effect' > opened 2> .");
    assert_eq!(status, 1, "{err}");
    assert!(out.is_empty() && !err.is_empty());
    assert!(fs::read(ws.0.join("opened")).unwrap().is_empty());
    assert!(!ws.0.join("effect").exists());
    let (status, out, err) = run(&mut shell, "{ echo wrong; } 2> .; echo restored");
    assert_eq!(status, 0, "{err}");
    assert_eq!(out, "restored\n");
}

#[test]
fn real_null_redirections_discard_large_output_preserve_alias_order_and_supply_eof() {
    let ws = Workspace::new();
    std::os::unix::fs::symlink("/bin/sh", ws.0.join("dual")).unwrap();
    let (status, out, err) = run(&mut ws.shell(),
        "./dual -c 'i=0; while test \"$i\" -lt 20000; do printf out; printf err >&2; i=$((i+1)); done' >/dev/null 2>&1; echo \"$(./dual -c 'printf out; printf err >&2' 2>&1 >/dev/null)\"; echo \"$(/bin/cat </dev/null)\"");
    assert_eq!(status, 0, "{err}");
    assert_eq!(out, "err\n\n");
    assert!(err.is_empty());
    assert!(fs::read_dir(&ws.0).unwrap().all(|entry| entry.unwrap().file_name() == "dual"));
}

#[test]
fn redirected_failure_keeps_status_without_an_extra_shell_line() {
    let ws = Workspace::new();
    std::os::unix::fs::symlink("/bin/sh", ws.0.join("dual")).unwrap();
    let mut shell = ws.shell();
    let (status, out, err) = run(&mut shell, "./dual -c 'printf native >&2; exit 7' >/dev/null 2>&1");
    assert_eq!(status, 7);
    assert!(out.is_empty() && err.is_empty(), "{out:?} {err:?}");
    let (status, _, err) = run(&mut shell, "./dual -c 'exit 7' >/dev/null");
    assert_eq!(status, 7);
    assert_eq!(err, "absd-sh: ./dual: exit status 7\n");
    let (status, _, err) = run(&mut shell, "./dual -c 'printf native >&2; exit 7' 2> error");
    assert_eq!(status, 7);
    assert!(err.is_empty());
    assert_eq!(fs::read(ws.0.join("error")).unwrap(), b"native");
}

#[test]
fn heredoc_literal_expanded_and_tab_stripped_bodies_use_real_native_stdin() {
    let ws = Workspace::new();
    ws.put("match.txt", "must not glob");
    let mut shell = ws.shell();
    let source = "X='one two'; HOME=/wrong; /bin/cat <<'LITERAL' > literal\n$X ~ *.txt \"double\" 'single' $(echo wrong)\nLITERAL\n/bin/cat <<EXPANDED > expanded\n~ *.txt \"$X\" 'single' $(echo hi) $((2+3)) \\$X\nEXPANDED\n/bin/cat <<-TABS > tabs\n\t\tfirst\n \tspace-keeps-tab\n\tTABS\n/bin/cat <<EMPTY > empty\nEMPTY\necho after";
    let (status, out, err) = run(&mut shell, source);
    assert_eq!((status, out.as_str(), err.as_str()), (0, "after\n", ""));
    assert_eq!(fs::read_to_string(ws.0.join("literal")).unwrap(), "$X ~ *.txt \"double\" 'single' $(echo wrong)\n");
    assert_eq!(fs::read_to_string(ws.0.join("expanded")).unwrap(), "~ *.txt \"one two\" 'single' hi 5 $X\n");
    assert_eq!(fs::read_to_string(ws.0.join("tabs")).unwrap(), "first\n \tspace-keeps-tab\n");
    assert_eq!(fs::read(ws.0.join("empty")).unwrap(), b"");
}

#[test]
fn heredoc_large_feed_pipeline_and_early_consumer_exit_close_input() {
    let ws = Workspace::new();
    let body = "payload\n".repeat(20000);
    let source = format!("/bin/cat <<'EOF' | /bin/cat > result\n{body}EOF\n/bin/head -c 0 <<'EARLY'\n{body}EARLY\necho alive");
    let (status, out, err) = run(&mut ws.shell(), &source);
    assert_eq!((status, out.as_str(), err.as_str()), (0, "alive\n", ""));
    assert_eq!(fs::read_to_string(ws.0.join("result")).unwrap(), body);
}

#[test]
fn heredoc_parameter_defaults_keep_tilde_literal_and_positionals_as_text() {
    let ws = Workspace::new();
    let (status, out, err) = run(&mut ws.shell(), "HOME=/unexpected; set -- 'one two' three; /bin/cat <<EOF > result\n${UNSET:-~} ${UNSET:-\"a b\"} $@\nEOF\n");
    assert_eq!((status, out.as_str(), err.as_str()), (0, "", ""));
    assert_eq!(fs::read_to_string(ws.0.join("result")).unwrap(), "~ a b one two three\n");
}

#[test]
fn heredoc_manual_recipe_uses_an_explicit_writable_directory() {
    let ws = Workspace::new();
    let source = include_str!("../../man/absd-sh.1");
    let section = source.split_once(".Ss Heredocs\n").unwrap().1;
    let block = section.split_once(".Bd -literal -offset indent\n").unwrap().1.split_once(".Ed").unwrap().0;
    // Neither the initial cwd nor HOME is writable. Only translate the
    // documented operator directory to this host fixture; target verbatim
    // execution is checked separately over real SSH.
    use std::os::unix::fs::PermissionsExt;
    let initial = ws.0.join("initial-read-only");
    fs::create_dir(&initial).unwrap();
    fs::set_permissions(&initial, fs::Permissions::from_mode(0o500)).unwrap();
    let mut shell = Shell::new(Native, initial.to_str().unwrap().into());
    let (status, _, err) = run(&mut shell, &format!("HOME='{}'", initial.display()));
    assert_eq!(status, 0, "{err}");
    let block = block.replace("cd /home/operator\n", &format!("cd '{}'\n", ws.0.display()));
    let transcript = ws.0.join("transcript");
    let result = run(&mut shell, &format!("{{\n{block}}} > {}", transcript.display()));
    fs::set_permissions(&initial, fs::Permissions::from_mode(0o700)).unwrap();
    let (status, out, err) = result;
    assert_eq!((status, out.as_str(), err.as_str()), (0, "", ""));
    assert_eq!(fs::read_to_string(ws.0.join("transcript")).unwrap(), "$HOME stays literal\noperator: field tech\nsum: 5\n");
}

#[test]
fn script_file_heredoc_uses_script_parameters_and_resumes_after_delimiter() {
    let ws = Workspace::new();
    ws.put("run.sh", "/bin/cat <<EOF > result\nargument: $1\n$(echo nested)\nEOF\necho after\n");
    let (status, out, err) = run(&mut ws.shell(), "sh run.sh 'one two'");
    assert_eq!((status, out.as_str(), err.as_str()), (0, "after\n", ""));
    assert_eq!(fs::read_to_string(ws.0.join("result")).unwrap(), "argument: one two\nnested\n");
}

#[test]
fn heredoc_tab_strip_keeps_interior_tabs_and_never_ends_on_trailing_tab() {
    let ws = Workspace::new();
    let source = "/bin/cat <<-EOF > result\n\ta\tb\t\n\tc\t$((1+1))\td\n\tEOF\t\n\techo leaked > leak\n\tEOF\necho after";
    let (status, out, err) = run(&mut ws.shell(), source);
    assert!(!ws.0.join("leak").exists(), "body text executed after a false delimiter");
    assert_eq!((status, out.as_str(), err.as_str()), (0, "after\n", ""));
    assert_eq!(fs::read_to_string(ws.0.join("result")).unwrap(), "a\tb\t\nc\t2\td\nEOF\t\necho leaked > leak\n");
    let (_, _, err) = run(&mut ws.shell(), "/bin/cat <<-'EOF' > quoted\n\ta\tb\t\n\tEOF\n");
    assert!(err.is_empty());
    assert_eq!(fs::read_to_string(ws.0.join("quoted")).unwrap(), "a\tb\t\n");
}

#[test]
fn heredoc_unquoted_backslashes_match_the_native_reference_shell() {
    let ws = Workspace::new();
    let body = r#"a\"b \"c\"
one\
two
\$X \\ \` \' \a
"#;
    let reference = Command::new("/bin/sh").args(["-c", &format!("X=value; cat <<EOF\n{body}EOF\n")]).output().unwrap();
    assert!(reference.status.success());
    let (status, out, err) = run(&mut ws.shell(), &format!("X=value; /bin/cat <<EOF > result\n{body}EOF\n"));
    assert_eq!((status, out.as_str(), err.as_str()), (0, "", ""));
    assert_eq!(fs::read(ws.0.join("result")).unwrap(), reference.stdout);
}

#[test]
fn heredoc_documented_default_quote_bound() {
    let ws = Workspace::new();
    let (status, _, err) = run(&mut ws.shell(), "/bin/cat <<EOF > default\n${UNSET:-'c'}\nEOF\n");
    assert_eq!(status, 0, "{err}");
    assert_eq!(fs::read_to_string(ws.0.join("default")).unwrap(), "c\n");
}

// #172: Bash-observed delimiter recognition must keep body text inert.
fn delimiter172_case(source: &str, expected: &[u8]) {
    let ws = Workspace::new();
    let reference = Command::new("/bin/bash").args(["--noprofile", "--norc", "-c", source]).current_dir(&ws.0).output().unwrap();
    assert!(reference.status.success(), "{:?}", reference.stderr);
    assert_eq!(fs::read(ws.0.join("body")).unwrap(), expected);
    assert!(!ws.0.join("marker").exists());
    fs::remove_file(ws.0.join("body")).unwrap();
    let (status, out, err) = run(&mut ws.shell(), source);
    assert_eq!(status, 0, "{err}");
    assert_eq!(out.as_bytes(), reference.stdout);
    assert_eq!(err.as_bytes(), reference.stderr);
    assert_eq!(fs::read(ws.0.join("body")).unwrap(), expected);
    assert!(!ws.0.join("marker").exists(), "heredoc body executed as a command");
}

#[test]
fn delimiter172_cr_body_unquoted() {
    delimiter172_case("/bin/cat <<EOF > body\npayload\nEOF\r\necho BAD > marker\nEOF\necho done\n", b"payload\nEOF\r\necho BAD > marker\n");
}

#[test]
fn delimiter172_cr_body_quoted() {
    delimiter172_case("/bin/cat <<'EOF' > body\npayload\nEOF\r\necho BAD > marker\nEOF\necho done\n", b"payload\nEOF\r\necho BAD > marker\n");
}

#[test]
fn delimiter172_quoted_cr_delimiter() {
    delimiter172_case("/bin/cat <<'EOF\r' > body\npayload\nEOF\r\r\necho BAD > marker\nEOF\r\necho done\n", b"payload\nEOF\r\r\necho BAD > marker\n");
}

#[test]
fn delimiter172_joined_unquoted_body() {
    delimiter172_case("/bin/cat <<EOF > body\none\\\nEOF\necho BAD > marker\nEOF\necho done\n", b"oneEOF\necho BAD > marker\n");
}

#[test]
fn delimiter172_quoted_body_no_join() {
    delimiter172_case("/bin/cat <<'EOF' > body\none\\\nEOF\necho done\n", b"one\\\n");
}

#[test]
fn delimiter172_joined_delimiter() {
    delimiter172_case("/bin/cat <<EOF > body\npayload\nEO\\\nF\necho done\n", b"payload\n");
}

#[test]
fn delimiter172_quoted_split_stays_body() {
    delimiter172_case("/bin/cat <<'EOF' > body\nEO\\\nF\nEOF\necho done\n", b"EO\\\nF\n");
}

#[test]
fn delimiter172_even_backslashes() {
    delimiter172_case("/bin/cat <<EOF > body\none\\\\\nEOF\necho done\n", b"one\\\n");
}

#[test]
fn delimiter172_odd_backslashes() {
    delimiter172_case("/bin/cat <<EOF > body\none\\\\\\\nEOF\necho BAD > marker\nEOF\necho done\n", b"one\\EOF\necho BAD > marker\n");
}

#[test]
fn delimiter172_tab_join_unquoted() {
    delimiter172_case("/bin/cat <<-EOF > body\t\n\tone\\\n\tEOF\n\techo BAD > marker\n\tEOF\necho done\n", b"one\tEOF\necho BAD > marker\n");
}

#[test]
fn delimiter172_tab_join_quoted() {
    delimiter172_case("/bin/cat <<-'EOF' > body\n\tone\\\n\tEOF\necho done\n", b"one\\\n");
}

#[test]
fn delimiter172_tab_split_delimiter() {
    delimiter172_case("/bin/cat <<-EOF > body\n\tpayload\n\tEO\\\nF\necho done\n", b"payload\n");
}

#[test]
fn delimiter172_tab_empty_prefix_join() {
    for prefix in ["", "\t"] {
        delimiter172_case(&format!("/bin/cat <<-EOF > body\n{prefix}\\\n\tEOF\necho done\n"), b"");
    }
}

#[test]
fn delimiter172_unquoted_cr_delimiter() {
    delimiter172_case("/bin/cat <<EOF\r > body\npayload\nEOF\necho BAD > marker\nEOF\r\necho done\n", b"payload\nEOF\necho BAD > marker\n");
}

// #182: compare exact control-flow output/status with the real host shell.
// Diagnostic wording belongs to ABSD and is asserted independently.
fn loop_control_182_reference(name: &str, script: &str, diagnostic: &str) {
    let ws = Workspace::new();
    let reference = Command::new("/bin/bash")
        .args(["--noprofile", "--norc", "-c", script])
        .env_clear().env("PATH", "/usr/bin:/bin").env("LC_ALL", "C")
        .current_dir(&ws.0).output().unwrap();
    let (status, out, err) = run(&mut ws.shell(), script);
    assert_eq!(Some(status), reference.status.code(), "status [{name}]: {script}");
    assert_eq!(out.as_bytes(), reference.stdout, "stdout [{name}]: {script}");
    assert_eq!(err, diagnostic, "ABSD diagnostic [{name}]: {script}");
}

#[test]
fn loop_control_182_guards() {
    for (name, script, diagnostic) in [
        ("break_while", "while break; do echo BODY; done; echo AFTER", ""),
        ("continue_while", "i=0; while { i=$((i+1)); case $i in 1) continue;; *) false;; esac; }; do echo BODY; break; done; echo AFTER:$i", ""),
        ("break_until", "until break; do echo BODY; done; echo AFTER", ""),
        ("continue_until", "i=0; until { i=$((i+1)); case $i in 1) continue;; *) true;; esac; }; do echo BODY; break; done; echo AFTER:$i", ""),
        ("guard_break_last_body_status", "i=0; while { i=$((i+1)); case $i in 1) true;; *) break;; esac; }; do false; done; echo STATUS:$?; echo AFTER", ""),
        ("continue_until_after_failed_body", "i=0; until { i=$((i+1)); case $i in 1) false;; *) continue;; esac; }; do false; done; echo STATUS:$?; echo AFTER:$i", ""),
        ("negated_continue_while_status", "while ! continue; do echo WRONG; done; echo STATUS:$?; echo AFTER", ""),
        ("negated_break_until_status", "until ! break; do echo WRONG; done; echo STATUS:$?; echo AFTER", ""),
        ("negated_break_while_status", "while ! break; do echo WRONG; done; echo STATUS:$?; echo AFTER", ""),
        ("negated_continue_after_failed_body", "i=0; while { i=$((i+1)); case $i in 1) true;; *) ! continue;; esac; }; do false; done; echo STATUS:$?; echo AFTER:$i", ""),
        ("guard_break_until_after_failed_body", "i=0; until { i=$((i+1)); case $i in 1) false;; *) break;; esac; }; do false; done; echo STATUS:$?; echo AFTER:$i", "")
    ] {
        loop_control_182_reference(name, script, diagnostic);
    }
}

#[test]
fn loop_control_182_function_scopes() {
    for (name, script, diagnostic) in [
        ("break_function", "f() { while break; do echo BODY; done; echo F_AFTER; }; f; echo AFTER", ""),
        ("continue_function", "f() { if continue; then echo THEN; else echo ELSE; fi; echo F_AFTER; }; f; echo AFTER", "absd-sh: continue: outside a loop\n"),
        ("function_called_from_loop", "f() { break; echo F_AFTER; }; for i in 1 2; do f; echo BODY:$i; done; echo AFTER", "absd-sh: break: outside a loop\nabsd-sh: break: outside a loop\n"),
        ("function_defined_inside_body", "for i in 1 2; do f() { break; echo F_AFTER; }; f; echo BODY:$i; done; echo AFTER", "absd-sh: break: outside a loop\nabsd-sh: break: outside a loop\n"),
        ("function_own_loop", "f() { for i in 1 2; do echo F:$i; break; done; echo F_AFTER; }; f; echo AFTER", ""),
        ("function_variables", "i=outer; f() { i=inner; break; echo F_AFTER; }; f; echo I:$i", "absd-sh: break: outside a loop\n"),
        ("caller_break_after_function", "f() { :; }; for i in 1 2; do f; echo BODY:$i; break; done; echo AFTER", ""),
        ("caller_continue_after_function", "f() { :; }; for i in 1 2; do f; continue; echo WRONG; done; echo AFTER", "")
    ] {
        loop_control_182_reference(name, script, diagnostic);
    }
}

#[test]
fn loop_control_182_subshell_scopes() {
    for (name, script, diagnostic) in [
        ("subshell_in_body", "for i in 1 2; do (break; echo SUB_AFTER); echo BODY:$i; done; echo AFTER", "absd-sh: break: outside a loop\nabsd-sh: break: outside a loop\n"),
        ("subshell_in_guard", "while (break; echo SUB_AFTER; false); do echo WRONG; done; echo AFTER", "absd-sh: break: outside a loop\n"),
        ("subshell_own_loop", "for i in 1 2; do (for j in 1 2; do break; done; echo SUB_AFTER); echo BODY:$i; done; echo AFTER", ""),
        ("subshell_variables", "i=outer; (i=inner; break; echo SUB_AFTER); echo I:$i", "absd-sh: break: outside a loop\n")
    ] {
        loop_control_182_reference(name, script, diagnostic);
    }
}

#[test]
fn loop_control_182_outer_requests() {
    for (name, script, diagnostic) in [
        ("break_nested_guard", "for i in 1 2; do while break; do echo WRONG; done; echo BODY:$i; done; echo AFTER", ""),
        ("continue_if_in_body", "for i in 1 2; do if continue; then echo WRONG; fi; echo WRONG; done; echo AFTER", ""),
        ("break_if_in_body", "for i in 1 2; do if break; then echo WRONG; fi; echo WRONG; done; echo AFTER", ""),
        ("negated_break_body", "for i in 1 2; do ! break; echo WRONG; done; echo STATUS:$?; echo AFTER", "")
    ] {
        loop_control_182_reference(name, script, diagnostic);
    }
}

#[test]
fn loop_control_182_invalid_controls() {
    // Steward0436 / #182 explicitly supersedes the old bare-break status2
    // assertion with Bash status0, its diagnostic and same-line recovery.
    for (name, script, diagnostic) in [
        ("break_if", "if break; then echo THEN; else echo ELSE; fi; echo AFTER", "absd-sh: break: outside a loop\n"),
        ("continue_if", "if continue; then echo THEN; else echo ELSE; fi; echo AFTER", "absd-sh: continue: outside a loop\n"),
        ("bare_break_status", "break; echo STATUS:$?; echo AFTER", "absd-sh: break: outside a loop\n"),
        ("bare_continue_status", "continue; echo STATUS:$?; echo AFTER", "absd-sh: continue: outside a loop\n")
    ] {
        loop_control_182_reference(name, script, diagnostic);
    }
}

#[test]
fn loop_control_182_bare_controls_and_unsupported_counts() {
    // #182 / steward0436: zero-argument out-of-loop control is diagnostic
    // status0, explicitly replacing the old status2 bare-break assertion.
    for name in ["break", "continue"] {
        let ws = Workspace::new();
        assert_eq!(run(&mut ws.shell(), name),
            (0, "".into(), format!("absd-sh: {name}: outside a loop\n")));
        let (status, out, err) = run(&mut ws.shell(), &format!("{name} 2; echo WRONG"));
        assert_eq!((status, out), (2, "".into()));
        assert!(err.contains("only the innermost loop"), "{err}");
    }
}

#[test]
fn loop_control_182_restores_function_context_on_error_and_exit() {
    for script in [
        "f() { for i in 1; do echo $((1/0)); done; }; for outer in 1; do f; done",
        "f() { for i in 1; do exit 7; done; }; for outer in 1; do f; done",
    ] {
        let ws = Workspace::new();
        let mut shell = ws.shell();
        let (status, out, err) = run(&mut shell, script);
        assert_eq!(out, "");
        if script.contains("1/0") {
            assert_eq!(status, 2);
            assert!(err.contains("division by zero"), "{err}");
        } else {
            assert_eq!(status, 7);
            assert_eq!(err, "");
        }
        assert_eq!(run(&mut shell, "break; echo AFTER"),
            (0, "AFTER\n".into(), "absd-sh: break: outside a loop\n".into()));
    }
}
