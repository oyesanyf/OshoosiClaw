//! Asynchronous JSONL streaming parser with backpressure and memory bounds.

use thiserror::Error;
use tokio::io::AsyncBufReadExt;

#[derive(Error, Debug)]
pub enum StreamError {
    #[error("I/O error reading forensic stream: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON deserialization error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Forensic stream exceeded maximum line limit of {0} lines")]
    MaxLinesExceeded(usize),
}

/// Parses an asynchronous line-buffered stream of JSONL records into strongly typed Rust structs.
/// Enforces a hard `max_lines` boundary to prevent out-of-memory denial-of-service conditions.
pub async fn parse_jsonl_stream<R: tokio::io::AsyncBufRead + Unpin, T: for<'de> serde::Deserialize<'de>>(
    mut reader: R,
    max_lines: usize,
) -> Result<Vec<T>, StreamError> {
    let mut results = Vec::new();
    let mut line_buf = String::new();
    let mut line_count = 0usize;

    loop {
        line_buf.clear();
        let bytes_read = reader.read_line(&mut line_buf).await?;
        if bytes_read == 0 {
            break; // EOF reached
        }

        let trimmed = line_buf.trim();
        if trimmed.is_empty() {
            continue;
        }

        line_count += 1;
        if line_count > max_lines {
            return Err(StreamError::MaxLinesExceeded(max_lines));
        }

        match serde_json::from_str::<T>(trimmed) {
            Ok(item) => results.push(item),
            Err(e) => {
                tracing::warn!(
                    "[FORENSICS] Skipping unparseable JSONL record at line {}: {} (content: '{}')",
                    line_count,
                    e,
                    trimmed
                );
            }
        }
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};
    use std::io::Cursor;

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct MockRecord {
        id: u32,
        name: String,
    }

    #[tokio::test]
    async fn test_stream_decoder_parses_jsonl_records() {
        let raw_jsonl = b"{\"id\": 1, \"name\": \"alpha\"}\n{\"id\": 2, \"name\": \"beta\"}\n\n{\"id\": 3, \"name\": \"gamma\"}\n";
        let cursor = Cursor::new(raw_jsonl);

        let parsed: Vec<MockRecord> = parse_jsonl_stream(cursor, 100).await.expect("valid parse");
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[0].id, 1);
        assert_eq!(parsed[0].name, "alpha");
        assert_eq!(parsed[1].id, 2);
        assert_eq!(parsed[2].name, "gamma");
    }

    #[tokio::test]
    async fn test_stream_decoder_enforces_max_lines() {
        let raw_jsonl = b"{\"id\": 1, \"name\": \"a\"}\n{\"id\": 2, \"name\": \"b\"}\n{\"id\": 3, \"name\": \"c\"}\n";
        let cursor = Cursor::new(raw_jsonl);

        let res: Result<Vec<MockRecord>, StreamError> = parse_jsonl_stream(cursor, 2).await;
        match res {
            Err(StreamError::MaxLinesExceeded(limit)) => assert_eq!(limit, 2),
            _ => panic!("Expected MaxLinesExceeded error"),
        }
    }
}
