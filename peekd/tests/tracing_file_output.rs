//! Integration test: verify tracing-appender writes logs to file.

use std::fs;
use std::path::PathBuf;

fn setup_tracing(dir: &std::path::Path) -> tracing_appender::non_blocking::WorkerGuard {
    let file_appender = tracing_appender::rolling::never(dir, "test.log");
    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new("info"))
        .with_writer(non_blocking)
        .with_ansi(false)
        .init();
    guard
}

#[test]
fn tracing_writes_to_file() {
    let tmp = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("tracing_test");
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp).unwrap();

    let _guard = setup_tracing(&tmp);

    tracing::info!("attached kretprobe/inet_sendmsg");
    tracing::warn!("libc not found, DNS tracking disabled");
    tracing::error!("storage flush failed: disk full");

    // Drop guard to flush
    drop(_guard);

    let log_path = tmp.join("test.log");
    assert!(log_path.exists(), "log file should exist at {:?}", log_path);

    let content = fs::read_to_string(&log_path).unwrap();
    assert!(
        content.contains("attached kretprobe/inet_sendmsg"),
        "log should contain info message, got: {}",
        content
    );
    assert!(
        content.contains("libc not found"),
        "log should contain warn message, got: {}",
        content
    );
    assert!(
        content.contains("storage flush failed"),
        "log should contain error message, got: {}",
        content
    );
    assert!(
        content.contains("INFO"),
        "log should contain INFO level, got: {}",
        content
    );
    assert!(
        content.contains("WARN"),
        "log should contain WARN level, got: {}",
        content
    );
    assert!(
        content.contains("ERROR"),
        "log should contain ERROR level, got: {}",
        content
    );

    // Cleanup
    let _ = fs::remove_dir_all(&tmp);
}
