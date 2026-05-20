use std::path::PathBuf;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::fmt::writer::MakeWriterExt;
use tracing_subscriber::EnvFilter;

pub fn init(log_dir: PathBuf) -> Option<WorkerGuard> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    match RollingFileAppender::builder()
        .rotation(Rotation::DAILY)
        .filename_prefix("peekd.log")
        .build(&log_dir)
    {
        Ok(file_appender) => {
            let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
            let _ = tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_writer(non_blocking.and(std::io::stderr))
                .try_init();
            Some(guard)
        }
        Err(e) => {
            let _ = tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_writer(std::io::stderr)
                .try_init();
            tracing::warn!("file logging unavailable in {}: {}", log_dir.display(), e);
            None
        }
    }
}
