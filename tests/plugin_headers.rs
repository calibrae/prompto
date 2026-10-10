//! `claude-plugin/bin/prompto-headers`: the Claude Code plugin's headers
//! helper, which reads the role token. It must refuse a token file anyone
//! else could read: by mode, by symlink, by owner, and by an ACL that
//! grants read. ACLs are shown to it through stand-in `ls` and `getfacl`
//! commands on `PATH`, so this runs the same on Linux and macOS, with or
//! without the ACL tools installed.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

const TOKEN: &str = "pto_test_token";

fn helper() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("claude-plugin/bin/prompto-headers")
}

/// Run the helper on `file`; with `shims`, `PATH` is that directory only.
/// `Ok(stdout)` or `Err(stderr)`.
fn run(file: &Path, shims: Option<&Path>) -> Result<String, String> {
    let mut cmd = Command::new("/bin/sh");
    cmd.arg(helper()).arg(file);
    if let Some(dir) = shims {
        cmd.env("PATH", dir);
    }
    let out = cmd.output().unwrap();
    if out.status.success() {
        Ok(String::from_utf8(out.stdout).unwrap())
    } else {
        Err(String::from_utf8(out.stderr).unwrap())
    }
}

fn token_file(dir: &Path, mode: u32) -> PathBuf {
    let f = dir.join("token");
    std::fs::write(&f, format!("{TOKEN}\n")).unwrap();
    std::fs::set_permissions(&f, std::fs::Permissions::from_mode(mode)).unwrap();
    f
}

fn script(dir: &Path, name: &str, body: &str) {
    let p = dir.join(name);
    std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// A `PATH` of stand-ins: `ls -ln` shows `mode` for the file (owned by
/// us); `ls -led` prints `ls_e`; `getfacl` exists only when `facl` is
/// `Some`, and prints it. The other tools the helper uses are the real
/// ones, linked in.
fn shims(dir: &Path, mode: &str, ls_e: Option<&str>, facl: Option<&str>) -> PathBuf {
    let bin = dir.join("bin");
    let _ = std::fs::remove_dir_all(&bin);
    std::fs::create_dir_all(&bin).unwrap();
    for tool in ["head", "tr", "id", "sed", "grep"] {
        let real = ["/usr/bin", "/bin"]
            .iter()
            .map(|d| Path::new(d).join(tool))
            .find(|p| p.exists())
            .unwrap_or_else(|| panic!("no {tool}"));
        std::os::unix::fs::symlink(real, bin.join(tool)).unwrap();
    }
    let ls_e = match ls_e {
        Some(out) => format!("printf '%s\\n' '{out}'"),
        None => "echo 'ls: invalid option -- e' >&2; exit 2".into(),
    };
    script(
        &bin,
        "ls",
        &format!(
            "case $1 in\n  -ln) echo \"{mode} 1 $(id -u) 0 15 Jan 1 00:00 $3\" ;;\n  -led) {ls_e} ;;\n  *) exit 2 ;;\nesac"
        ),
    );
    if let Some(acl) = facl {
        script(&bin, "getfacl", &format!("printf '%s\\n' '{acl}'"));
    }
    bin
}

#[test]
fn a_private_token_file_gives_the_header() {
    let d = tempfile::tempdir().unwrap();
    for mode in [0o600, 0o400] {
        let f = token_file(d.path(), mode);
        let out = run(&f, None).unwrap();
        assert_eq!(out, format!("{{\"Authorization\": \"Bearer {TOKEN}\"}}\n"));
    }
}

#[test]
fn a_file_others_could_read_is_refused() {
    let d = tempfile::tempdir().unwrap();
    for mode in [0o640, 0o604, 0o644, 0o660] {
        let f = token_file(d.path(), mode);
        let err = run(&f, None).unwrap_err();
        assert!(err.contains("readable by you only"), "{mode:o}: {err}");
    }
    let f = token_file(d.path(), 0o600);
    let link = d.path().join("link");
    std::os::unix::fs::symlink(&f, &link).unwrap();
    assert!(run(&link, None).unwrap_err().contains("symlink"));
    assert!(
        run(&d.path().join("nope"), None)
            .unwrap_err()
            .contains("no token file")
    );
}

#[test]
fn an_acl_marker_passes_only_when_the_acl_grants_no_one_else_read() {
    let d = tempfile::tempdir().unwrap();
    let f = token_file(d.path(), 0o600);
    // Linux, getfacl present.
    let private = "user::rw-\ngroup::---\nmask::---\nother::---";
    let bin = shims(d.path(), "-rw-------+", None, Some(private));
    assert!(run(&f, Some(&bin)).is_ok());
    for leak in [
        "user::rw-\nuser:1001:r--\ngroup::---\nmask::r--\nother::---",
        "user::rw-\ngroup::r--\nother::---",
        "user::rw-\ngroup:1002:r--\nother::---",
        "user::rw-\ngroup::---\nother::r--",
    ] {
        let bin = shims(d.path(), "-rw-------+", None, Some(leak));
        let err = run(&f, Some(&bin)).unwrap_err();
        assert!(err.contains("ACL"), "{leak}: {err}");
    }
    // macOS: no getfacl, `ls -le` lists the entries.
    let bin = shims(
        d.path(),
        "-rw-------+",
        Some("-rw-------+ 1 501 20 15 Jan 1 00:00 token\n 0: group:everyone allow read"),
        None,
    );
    assert!(run(&f, Some(&bin)).unwrap_err().contains("ACL"));
    let bin = shims(
        d.path(),
        "-rw-------@",
        Some("-rw-------@ 1 501 20 15 Jan 1 00:00 token"),
        None,
    );
    assert!(run(&f, Some(&bin)).is_ok(), "extended attributes, no ACL");
    // Can't tell (no getfacl, no `ls -e`): refused.
    let bin = shims(d.path(), "-rw-------+", None, None);
    assert!(run(&f, Some(&bin)).unwrap_err().contains("ACL"));
    // An SELinux context grants nothing.
    let bin = shims(d.path(), "-rw-------.", None, None);
    assert!(run(&f, Some(&bin)).is_ok());
    // Any other marker is refused.
    let bin = shims(d.path(), "-rw-------x", None, None);
    assert!(
        run(&f, Some(&bin))
            .unwrap_err()
            .contains("readable by you only")
    );
}
