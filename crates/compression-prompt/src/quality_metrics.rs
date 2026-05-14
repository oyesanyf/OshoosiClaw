pub struct QualityMetrics;

impl QualityMetrics {
    pub fn calculate_lexical_overlap(original: &str, compressed: &str) -> f32 {
        let original_words: std::collections::HashSet<_> = original.split_whitespace().collect();
        let compressed_words: std::collections::HashSet<_> = compressed.split_whitespace().collect();
        
        if original_words.is_empty() {
            return 1.0;
        }

        let intersection = original_words.intersection(&compressed_words).count();
        intersection as f32 / original_words.len() as f32
    }
}
