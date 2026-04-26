//! Sysmon event extraction and parsing.
//!
//! Reads Microsoft-Windows-Sysmon/Operational events.

use chrono::{DateTime, Utc};
use osoosi_types::{SysmonEvent, SysmonEventId};
use serde_json::json;
use tracing::debug;

pub struct SysmonParser;

impl Default for SysmonParser {
    fn default() -> Self {
        Self::new()
    }
}

impl SysmonParser {
    pub fn new() -> Self {
        Self
    }

    /// Parse a Sysmon XML event.
    pub fn parse_xml(&self, xml: &str) -> anyhow::Result<SysmonEvent> {
        use quick_xml::events::Event;
        use quick_xml::reader::Reader;

        let mut reader = Reader::from_str(xml);
        reader.trim_text(true);

        let mut event_id: Option<u16> = None;
        let mut computer: String = "unknown".to_string();
        let mut event_data = serde_json::Map::new();
        let mut timestamp = Utc::now();

        let mut buf = Vec::new();
        let mut current_tag = String::new();
        let mut in_event_data = false;

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(ref e)) => {
                    current_tag = local_xml_name(e.name().as_ref());
                    if current_tag == "EventData" {
                        in_event_data = true;
                    }
                    if in_event_data && current_tag == "Data" {
                        let name = data_name_attr(e);

                        if let Some(name) = name {
                            let text = reader.read_text(e.name())?;
                            event_data.insert(name, json!(text.to_string()));
                        }
                    }
                }
                Ok(Event::Empty(ref e)) => {
                    let tag = local_xml_name(e.name().as_ref());
                    if tag == "TimeCreated" {
                        if let Some(system_time) = attr_value(e, b"SystemTime") {
                            if let Ok(dt) = DateTime::parse_from_rfc3339(&system_time) {
                                timestamp = dt.with_timezone(&Utc);
                            }
                        }
                    } else if in_event_data && tag == "Data" {
                        if let Some(name) = data_name_attr(e) {
                            event_data.insert(name, json!(""));
                        }
                    }
                }
                Ok(Event::Text(e)) => {
                    let text = e.unescape()?.into_owned();
                    match current_tag.as_str() {
                        "EventID" => event_id = Some(text.parse()?),
                        "Computer" => computer = text,
                        "EventRecordID" => {
                            event_data.insert("EventRecordID".to_string(), json!(text));
                        }
                        _ => {}
                    }
                }
                Ok(Event::End(ref e)) => {
                    let tag = local_xml_name(e.name().as_ref());
                    if tag == "EventData" {
                        in_event_data = false;
                    }
                    current_tag.clear();
                }
                Ok(Event::Eof) => break,
                Err(e) => return Err(anyhow::anyhow!("XML error: {}", e)),
                _ => {}
            }
            buf.clear();
        }

        let id = event_id.ok_or_else(|| anyhow::anyhow!("Missing EventID"))?;
        // Keep unsupported Sysmon IDs instead of dropping them.
        // They are mapped to Generic and we preserve the raw numeric ID in event data.
        let event_id_typed = match SysmonEventId::try_from(id) {
            Ok(v) => v,
            Err(_) => {
                debug!("Unsupported Sysmon EventID {} mapped to Generic", id);
                event_data.insert("RawEventID".to_string(), json!(id));
                SysmonEventId::Generic
            }
        };

        Ok(SysmonEvent {
            event_id: event_id_typed,
            timestamp,
            computer,
            data: json!(event_data),
            product_version: None,
        })
    }
}

fn local_xml_name(name: &[u8]) -> String {
    let raw = String::from_utf8_lossy(name);
    raw.rsplit(':').next().unwrap_or(&raw).to_string()
}

fn attr_value(e: &quick_xml::events::BytesStart<'_>, wanted: &[u8]) -> Option<String> {
    e.attributes()
        .flatten()
        .find(|attr| {
            attr.key
                .as_ref()
                .rsplit(|b| *b == b':')
                .next()
                .unwrap_or(attr.key.as_ref())
                == wanted
        })
        .map(|attr| String::from_utf8_lossy(attr.value.as_ref()).to_string())
}

fn data_name_attr(e: &quick_xml::events::BytesStart<'_>) -> Option<String> {
    attr_value(e, b"Name")
}
