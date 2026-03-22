//! Sysmon event extraction and parsing.
//! 
//! Reads Microsoft-Windows-Sysmon/Operational events.

use osoosi_types::{SysmonEvent, SysmonEventId};
use chrono::Utc;
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

        let mut buf = Vec::new();
        let mut current_tag = String::new();
        let mut in_event_data = false;

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(ref e)) => {
                    current_tag = String::from_utf8_lossy(e.name().as_ref()).to_string();
                    if current_tag == "EventData" {
                        in_event_data = true;
                    }
                    if in_event_data && current_tag == "Data" {
                        let name = e.attributes()
                            .find(|a| a.as_ref().map(|attr| attr.key.as_ref() == b"Name").unwrap_or(false))
                            .and_then(|a| a.ok())
                            .map(|a| String::from_utf8_lossy(a.value.as_ref()).to_string());
                        
                        if let Some(name) = name {
                            let text = reader.read_text(e.name())?;
                            event_data.insert(name, json!(text.to_string()));
                        }
                    }
                }
                Ok(Event::Text(e)) => {
                    let text = e.unescape()?.into_owned();
                    match current_tag.as_str() {
                        "EventID" => event_id = Some(text.parse()?),
                        "Computer" => computer = text,
                        _ => {}
                    }
                }
                Ok(Event::End(ref e)) => {
                    let tag = String::from_utf8_lossy(e.name().as_ref()).to_string();
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
            timestamp: Utc::now(),
            computer,
            data: json!(event_data),
        })
    }
}
