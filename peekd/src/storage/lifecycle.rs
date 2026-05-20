use super::{
    AlertEventSender, DbWriter, PrivacyMask, WriterMsg, _cleanup_retention, _ensure_wal_mode,
    _init_schema,
};
use crate::config::Config;
use crate::types::BpfEvent;
use std::sync::Arc;
use std::thread;
use tokio::sync::{broadcast, oneshot};
use tokio::task::JoinHandle;
use tokio::time::{interval, Duration};
use tracing::{error, info, warn};

pub struct StorageHandle {
    alert_tx: AlertEventSender,
    shutdown_tx: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
}

impl StorageHandle {
    pub fn alert_sender(&self) -> AlertEventSender {
        self.alert_tx.clone()
    }

    pub async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Err(e) = self.task.await {
            error!("storage relay task failed: {}", e);
        }
    }
}

pub fn start(
    rx: broadcast::Receiver<BpfEvent>,
    config: Arc<Config>,
    metrics: Arc<crate::metrics::Metrics>,
) -> Result<StorageHandle, Box<dyn std::error::Error>> {
    start_with_db_path(rx, config, metrics, crate::config::db_path())
}

pub(super) fn start_with_db_path(
    rx: broadcast::Receiver<BpfEvent>,
    config: Arc<Config>,
    metrics: Arc<crate::metrics::Metrics>,
    db_path: std::path::PathBuf,
) -> Result<StorageHandle, Box<dyn std::error::Error>> {
    if !config.database.enabled {
        return Ok(disabled_handle());
    }
    info!("opening db: {}", db_path.display());
    if let Some(parent) = db_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let db = rusqlite::Connection::open(&db_path)?;
    _ensure_wal_mode(&db).map_err(|e| -> Box<dyn std::error::Error> { e })?;
    _init_schema(&db)?;
    if let Err(e) = _cleanup_retention(&db, config.database.retention_days) {
        warn!("retention cleanup failed (ignored): {}", e);
    }

    let (writer_tx, writer_rx) = std::sync::mpsc::channel::<WriterMsg>();
    let writer = DbWriter::new(
        db,
        config.database.retention_days,
        metrics.clone(),
        PrivacyMask::from_config(&config.log),
    );
    let writer_handle = thread::Builder::new()
        .name("peekd-db-writer".into())
        .spawn(move || writer.run(writer_rx))?;
    let alert_tx = writer_tx.clone();
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let task = tokio::spawn(storage_relay(
        rx,
        writer_tx,
        writer_handle,
        metrics,
        config.database.write_limit_seconds,
        shutdown_rx,
    ));
    Ok(StorageHandle {
        alert_tx,
        shutdown_tx: Some(shutdown_tx),
        task,
    })
}

async fn storage_relay(
    mut rx: broadcast::Receiver<BpfEvent>,
    writer_tx: AlertEventSender,
    writer_handle: thread::JoinHandle<()>,
    metrics: Arc<crate::metrics::Metrics>,
    write_limit_seconds: u64,
    mut shutdown_rx: oneshot::Receiver<()>,
) {
    let mut batch: Vec<BpfEvent> = Vec::with_capacity(256);
    let mut flush_interval = interval(Duration::from_secs(write_limit_seconds));

    loop {
        tokio::select! {
            _ = &mut shutdown_rx => break,
            result = rx.recv() => match result {
                Ok(event) => {
                    batch.push(event);
                    if batch.len() >= 256 {
                        let _ = writer_tx.send(WriterMsg::Events(std::mem::take(&mut batch)));
                    }
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    warn!("storage sink lagged, dropping {} events", n);
                    metrics.record_broadcast_lag("storage", n);
                }
                Err(broadcast::error::RecvError::Closed) => break,
            },
            _ = flush_interval.tick() => {
                if !batch.is_empty() {
                    let _ = writer_tx.send(WriterMsg::Events(std::mem::take(&mut batch)));
                }
                let _ = writer_tx.send(WriterMsg::Flush);
            }
        }
    }

    if !batch.is_empty() {
        let _ = writer_tx.send(WriterMsg::Events(batch));
    }
    let _ = writer_tx.send(WriterMsg::Shutdown);
    tokio::task::spawn_blocking(move || {
        if let Err(e) = writer_handle.join() {
            error!("storage writer thread panicked: {:?}", e);
        }
    })
    .await
    .ok();
}

fn disabled_handle() -> StorageHandle {
    let (tx, rx) = std::sync::mpsc::channel::<WriterMsg>();
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let task = tokio::spawn(async move {
        tokio::select! {
            _ = shutdown_rx => {}
            _ = tokio::task::spawn_blocking(move || while rx.recv().is_ok() {}) => {}
        }
    });
    StorageHandle {
        alert_tx: tx,
        shutdown_tx: Some(shutdown_tx),
        task,
    }
}
