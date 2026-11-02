//! A library keeps no process-wide state, and this one holds no `unsafe`: neither appears in
//! `src/`.

use std::fs;
use std::path::Path;

const MARKERS: &[&str] = &["static", "OnceLock", "LazyLock", "thread_local", "unsafe"];

fn scan(directory: &Path, found: &mut Vec<String>) {
    for entry in fs::read_dir(directory).expect("the directory is readable") {
        let path = entry.expect("a directory entry").path();
        if path.is_dir() {
            scan(&path, found);
            continue;
        }
        let text = fs::read_to_string(&path).expect("a source file is UTF-8");
        for line in text.lines() {
            let code = line.split("//").next().unwrap_or_default();
            // Whole words, so `remote_static` is not state; `&'static` is a lifetime.
            let hit = code
                .replace("'static", "")
                .split(|character: char| !character.is_alphanumeric() && character != '_')
                .any(|word| MARKERS.contains(&word));
            if hit {
                found.push(format!("{}: {}", path.display(), line.trim()));
            }
        }
    }
}

#[test]
fn the_source_holds_no_process_wide_state_and_no_unsafe() {
    let mut found = Vec::new();
    scan(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut found,
    );
    assert!(found.is_empty(), "{found:#?}");
}
