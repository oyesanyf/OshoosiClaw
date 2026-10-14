pub mod atlas_matrix;
pub mod atlas_parser;
pub mod atlas_sync;
pub mod coverage_matrix;
pub mod evidence_validator;
pub mod technique_mapper;
pub mod test_generator;
pub mod threat_correlator;

pub use atlas_matrix::{AtlasTactic, AtlasTechnique, MitreAtlasMatrix};
pub use atlas_parser::{AtlasCaseStudy, AtlasMitigation, AtlasParser, ParsedAtlasKnowledgeBase};
pub use atlas_sync::{
    AtlasSyncError, AtlasSyncMetadata, AtlasSyncManager, EMBEDDED_GOLDEN_STIX,
    PINNED_ATLAS_GOLDEN_SHA256,
};
pub use coverage_matrix::{
    AtlasCoverageEntry, AtlasCoverageMatrix, AtlasCoverageSummary, MitigationStatus,
};
pub use evidence_validator::{EvidenceValidationVerdict, EvidenceValidator};
pub use technique_mapper::{MappedThreatRecord, TechniqueMapper, ThreatFeasibility};
pub use test_generator::{AtlasTestCase, AtlasTestGenerator};
pub use threat_correlator::{AtlasTechniqueRelationship, ThreatCorrelator};
