use std::future::Future;

#[cfg(feature = "remote-clickhouse")]
pub struct ClickHouseSink {
    url: String,
    client: reqwest::Client,
    batch: Vec<crate::types::ConnectionRow>,
    batch_size: usize,
}

#[cfg(feature = "remote-clickhouse")]
impl ClickHouseSink {
    pub fn new(url: &str, batch_size: usize) -> Self {
        Self {
            url: url.to_string(),
            client: reqwest::Client::new(),
            batch: Vec::with_capacity(batch_size),
            batch_size,
        }
    }
}

#[cfg(feature = "remote-clickhouse")]
impl crate::types::RemoteStorage for ClickHouseSink {
    fn write_batch(
        &mut self,
        rows: &[crate::types::ConnectionRow],
    ) -> impl Future<Output = Result<(), Box<dyn std::error::Error>>> + Send {
        async move {
            let json = serde_json::to_string(rows)?;
            self.client
                .post(&self.url)
                .header("Content-Type", "application/json")
                .body(json)
                .send()
                .await?;
            Ok(())
        }
    }
}

pub struct JsonFileSink {
    path: std::path::PathBuf,
}

impl JsonFileSink {
    pub fn new(path: &std::path::Path) -> Self {
        Self {
            path: path.to_path_buf(),
        }
    }
}

impl crate::types::RemoteStorage for JsonFileSink {
    async fn write_batch(
        &mut self,
        rows: &[crate::types::ConnectionRow],
    ) -> Result<(), Box<dyn std::error::Error>> {
        use std::io::Write;
        let path = self.path.clone();
        let rows = rows.to_vec();
        let result = tokio::task::spawn_blocking(move || -> std::io::Result<()> {
            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)?;
            for row in &rows {
                let line = serde_json::to_string(row).map_err(std::io::Error::other)?;
                writeln!(file, "{}", line)?;
            }
            Ok(())
        })
        .await
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
        result.map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
    }
}
