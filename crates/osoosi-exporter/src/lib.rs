//! OpenỌ̀ṣọ́ọ̀sì Telemetry Exporter.
//!
//! Provides OpenTelemetry tracing integration for distributed tracing.
//! Set `OSOOSI_OTEL_ENABLED=1` to enable. Add the returned layer to your
//! tracing subscriber **first** (before fmt layers):
//!
//! ```ignore
//! let reg = tracing_subscriber::registry();
//! let reg = if let Some(otel) = osoosi_exporter::init_opentelemetry_layer() {
//!     reg.with(otel)
//! } else {
//!     reg
//! };
//! reg.with(fmt::layer()).init();
//! ```

use opentelemetry::trace::TracerProvider as _;
use opentelemetry_sdk::trace::SdkTracerProvider;

/// Initialize OpenTelemetry tracing and return a layer to add to the tracing subscriber.
/// Set OSOOSI_OTEL_ENABLED=1 to enable.
pub fn init_opentelemetry_layer<S>(
) -> Option<tracing_opentelemetry::OpenTelemetryLayer<S, opentelemetry_sdk::trace::Tracer>>
where
    S: tracing::Subscriber + for<'span> tracing_subscriber::registry::LookupSpan<'span>,
{
    if std::env::var("OSOOSI_OTEL_ENABLED")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
    {
        let provider = SdkTracerProvider::default();
        let tracer = provider.tracer("osoosi-edr");
        opentelemetry::global::set_tracer_provider(provider);
        Some(tracing_opentelemetry::layer().with_tracer(tracer))
    } else {
        None
    }
}
/// SIEM Exporter for Enterprise Log Streaming (e.g. Splunk, ELK).
pub struct SiemExporter {
    #[allow(dead_code)]
    endpoint: String,
    #[allow(dead_code)]
    token: String,
    /// Differential Privacy configuration
    dp: Option<osoosi_dp::DifferentialPrivacy>,
}

impl SiemExporter {
    pub fn new(
        endpoint: String,
        token: String,
        dp_config: Option<osoosi_dp::PrivacyConfig>,
    ) -> Self {
        Self {
            endpoint,
            token,
            dp: dp_config.map(osoosi_dp::DifferentialPrivacy::new),
        }
    }

    pub async fn export_event(
        &self,
        event_type: &str,
        data: serde_json::Value,
    ) -> anyhow::Result<()> {
        let mut data = data;
        // Apply noise to top-level numeric fields if DP is enabled
        if let Some(ref dp) = self.dp {
            if let Some(obj) = data.as_object_mut() {
                for value in obj.values_mut() {
                    if let Some(n) = value.as_f64() {
                        *value = serde_json::json!(dp.add_noise(n as f32));
                    }
                }
            }
        }

        let _payload = serde_json::json!({
            "sourcetype": "osoosi_audit",
            "event": {
                "type": event_type,
                "data": data,
                "timestamp": chrono::Utc::now(),
            }
        });
        // In a real implementation, send this to the Splunk HEC or similar
        // reqwest::Client::new().post(&self.endpoint).json(&payload).send().await?;
        Ok(())
    }
}
