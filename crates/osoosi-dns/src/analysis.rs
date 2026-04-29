//! DNS Query Analysis Engine
//!
//! Performs entropy-based DGA detection, DNS tunneling detection,
//! and domain reputation analysis on intercepted DNS queries.

use std::collections::HashMap;

/// Result of analyzing a DNS query
#[derive(Debug, Clone)]
pub struct DnsAnalysis {
    pub domain: String,
    pub verdict: DnsVerdict,
    pub entropy: f64,
    pub label_count: usize,
    pub max_label_len: usize,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum DnsVerdict {
    /// Domain is clean, forward normally
    Allow,
    /// Domain is suspicious, log but allow
    Suspicious,
    /// Domain is malicious, sinkhole it
    Block,
}

/// Analyze a domain name for DGA patterns, tunneling, and known-bad indicators.
pub fn analyze_domain(domain: &str) -> DnsAnalysis {
    let domain_lower = domain.to_lowercase().trim_end_matches('.').to_string();
    let labels: Vec<&str> = domain_lower.split('.').collect();
    let label_count = labels.len();
    let max_label_len = labels.iter().map(|l| l.len()).max().unwrap_or(0);

    // --- 1. Known Darknet TLDs ---
    if domain_lower.ends_with(".onion") || domain_lower.ends_with(".i2p") || domain_lower.ends_with(".bit") {
        return DnsAnalysis {
            domain: domain_lower,
            verdict: DnsVerdict::Block,
            entropy: 0.0,
            label_count,
            max_label_len,
            reason: "Darknet TLD detected (.onion/.i2p/.bit). Sinkholed.".to_string(),
        };
    }

    // --- 2. DGA Detection via Shannon Entropy ---
    let sld = if labels.len() >= 2 { labels[labels.len() - 2].to_string() } else { domain_lower.clone() };
    let entropy = shannon_entropy(&sld);

    if entropy > 4.0 && sld.len() > 10 {
        let reason = format!("DGA detected: SLD '{}' has entropy {:.2} (threshold: 4.0). Likely algorithmically generated.", sld, entropy);
        return DnsAnalysis {
            domain: domain_lower,
            verdict: DnsVerdict::Block,
            entropy,
            label_count,
            max_label_len,
            reason,
        };
    }

    // --- 3. DNS Tunneling Detection ---
    // DNS tunneling encodes data in subdomain labels, creating very long labels
    if max_label_len > 50 {
        return DnsAnalysis {
            domain: domain_lower,
            verdict: DnsVerdict::Block,
            entropy,
            label_count,
            max_label_len,
            reason: format!("DNS tunneling suspected: label length {} exceeds 50 chars. Data exfiltration likely.", max_label_len),
        };
    }

    // Excessive subdomain depth (normal domains rarely exceed 4 labels)
    if label_count > 6 {
        return DnsAnalysis {
            domain: domain_lower,
            verdict: DnsVerdict::Suspicious,
            entropy,
            label_count,
            max_label_len,
            reason: format!("Unusual subdomain depth: {} labels. Possible DNS tunneling or beaconing.", label_count),
        };
    }

    // --- 4. Suspicious entropy (moderate) ---
    if entropy > 3.5 && sld.len() > 8 {
        let reason = format!("Elevated entropy {:.2} for SLD '{}'. Monitor for DGA patterns.", entropy, sld);
        return DnsAnalysis {
            domain: domain_lower,
            verdict: DnsVerdict::Suspicious,
            entropy,
            label_count,
            max_label_len,
            reason,
        };
    }

    // --- 5. Clean ---
    DnsAnalysis {
        domain: domain_lower,
        verdict: DnsVerdict::Allow,
        entropy,
        label_count,
        max_label_len,
        reason: "Domain appears benign.".to_string(),
    }
}

/// Calculate Shannon entropy of a string (higher = more random = more suspicious)
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }

    let mut freq: HashMap<char, f64> = HashMap::new();
    let len = s.len() as f64;

    for c in s.chars() {
        *freq.entry(c).or_insert(0.0) += 1.0;
    }

    freq.values()
        .map(|count| {
            let p = count / len;
            if p > 0.0 { -p * p.log2() } else { 0.0 }
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normal_domain() {
        let result = analyze_domain("google.com");
        assert_eq!(result.verdict, DnsVerdict::Allow);
    }

    #[test]
    fn test_darknet_domain() {
        let result = analyze_domain("hiddenservice.onion");
        assert_eq!(result.verdict, DnsVerdict::Block);
    }

    #[test]
    fn test_dga_domain() {
        // Use a truly random-looking domain with many unique chars to guarantee entropy > 4.0
        let result = analyze_domain("a8hd7gk2mxp9qw4zbtlvyne.com");
        assert!(result.verdict == DnsVerdict::Block || result.verdict == DnsVerdict::Suspicious);
        assert!(result.entropy > 3.5);
    }

    #[test]
    fn test_tunneling_domain() {
        let long_label = "a".repeat(60);
        let domain = format!("{}.evil.com", long_label);
        let result = analyze_domain(&domain);
        assert_eq!(result.verdict, DnsVerdict::Block);
    }

    #[test]
    fn test_entropy_calculation() {
        // "aaaa" should have entropy 0 (all same char)
        assert_eq!(shannon_entropy("aaaa"), 0.0);
        // "abcd" should have entropy 2.0 (4 unique chars, uniform)
        let e = shannon_entropy("abcd");
        assert!((e - 2.0).abs() < 0.01);
    }
}
