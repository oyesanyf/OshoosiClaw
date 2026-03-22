use osoosi_types::{TaintedValue, TaintLabel, TaintSink};
use std::collections::HashSet;

#[test]
fn test_taint_flow_logical() {
    let mut labels = HashSet::new();
    labels.insert(TaintLabel::DownloadedFile);
    
    let tainted = TaintedValue::new(
        "C:\\Users\\Public\\malware.exe",
        labels,
        "NetworkDownload"
    );

    let sink = TaintSink::process_injection();
    
    let result = tainted.check_sink(&sink);
    assert!(result.is_err(), "Downloaded file should be blocked from process injection");
}

#[test]
fn test_taint_merge() {
    let mut l1 = HashSet::new();
    l1.insert(TaintLabel::SuspiciousNetwork);
    let mut t1 = TaintedValue::new("data", l1, "src1");

    let mut l2 = HashSet::new();
    l2.insert(TaintLabel::UntrustedScript);
    let t2 = TaintedValue::new("data", l2, "src2");

    t1.merge_taint(&t2);
    assert!(t1.labels.contains(&TaintLabel::SuspiciousNetwork));
    assert!(t1.labels.contains(&TaintLabel::UntrustedScript));
}
