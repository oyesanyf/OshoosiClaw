use base64::{engine::general_purpose, Engine as _};
use chrono::{DateTime, Utc};
use regex::Regex;
use reqwest::blocking::Client;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use serde::Serialize;
use std::collections::HashSet;
use uuid::Uuid;

pub const OTX_DISCOVERY_URL: &str = "https://otx.alienvault.com/taxii/discovery";
pub const OTX_COLLECTIONS_URL: &str = "https://otx.alienvault.com/taxii/collections";
pub const OTX_POLL_URL: &str = "https://otx.alienvault.com/taxii/poll";

#[derive(Debug, Serialize, Eq, PartialEq, Hash, Clone)]
pub struct Indicator {
    pub indicator_type: String,
    pub value: String,
    pub source: String,
    pub collected_at: DateTime<Utc>,
}

pub fn post_taxii(
    client: &Client,
    url: &str,
    api_key: &str,
    body: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let password = "foo";
    let auth = general_purpose::STANDARD.encode(format!("{api_key}:{password}"));

    let response = client
        .post(url)
        .header(AUTHORIZATION, format!("Basic {auth}"))
        .header(CONTENT_TYPE, "application/xml")
        .body(body.to_string())
        .send()?;

    let status = response.status();
    let text = response.text()?;

    if !status.is_success() {
        return Err(format!("HTTP error {status}: {text}").into());
    }

    Ok(text)
}

pub fn discovery_request() -> String {
    format!(
        r#"<taxii_11:Discovery_Request xmlns:taxii_11="http://taxii.mitre.org/messages/taxii_xml_binding-1.1" message_id="{}"/>"#,
        Uuid::new_v4()
    )
}

pub fn collections_request() -> String {
    format!(
        r#"<taxii_11:Collection_Information_Request xmlns:taxii_11="http://taxii.mitre.org/messages/taxii_xml_binding-1.1" message_id="{}"/>"#,
        Uuid::new_v4()
    )
}

pub fn poll_request(collection: &str, begin: DateTime<Utc>) -> String {
    format!(
        r#"<taxii_11:Poll_Request xmlns:taxii_11="http://taxii.mitre.org/messages/taxii_xml_binding-1.1" message_id="{}" collection_name="{}">
    <taxii_11:Exclusive_Begin_Timestamp>{}</taxii_11:Exclusive_Begin_Timestamp>
    <taxii_11:Poll_Parameters allow_asynch="false"/>
</taxii_11:Poll_Request>"#,
        Uuid::new_v4(),
        xml_escape(collection),
        begin.to_rfc3339()
    )
}

pub fn extract_indicators(xml: &str) -> Vec<Indicator> {
    let mut found: HashSet<Indicator> = HashSet::new();
    let collected_at = Utc::now();

    let patterns = vec![
        ("ipv4", r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
        ("md5", r"\b[a-fA-F0-9]{32}\b"),
        ("sha1", r"\b[a-fA-F0-9]{40}\b"),
        ("sha256", r"\b[a-fA-F0-9]{64}\b"),
        ("url", r#"https?://[^\s<>"']+"#),
        (
            "email",
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        ),
        (
            "domain",
            r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b",
        ),
    ];

    for (indicator_type, pattern) in patterns {
        let re = Regex::new(pattern).unwrap();
        for mat in re.find_iter(xml) {
            let value = mat.as_str().trim().to_string();
            if indicator_type == "ipv4" && !valid_ipv4(&value) {
                continue;
            }
            found.insert(Indicator {
                indicator_type: indicator_type.to_string(),
                value,
                source: "OTX TAXII".to_string(),
                collected_at,
            });
        }
    }

    found.into_iter().collect()
}

fn valid_ipv4(ip: &str) -> bool {
    ip.split('.').all(|part| part.parse::<u8>().is_ok())
}

pub fn xml_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}
