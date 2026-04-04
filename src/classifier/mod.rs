// Tier 3: LLM classifier for ambiguous inputs.
// opt-in only. uses local Ollama or cloud API.
// stub — interface defined, implementation deferred until Tiers 1+2 are validated.

pub struct LlmClassifier {
    _provider: ClassifierProvider,
}

pub enum ClassifierProvider {
    Ollama { model: String, endpoint: String },
    Cloud { api_key: String, endpoint: String },
}

#[derive(Debug)]
pub struct ClassifierResult {
    pub is_injection: bool,
    pub confidence: f64,
    pub reasoning: Option<String>,
}

impl LlmClassifier {
    pub fn new(provider: ClassifierProvider) -> Self {
        Self {
            _provider: provider,
        }
    }

    /// classify an input as potentially malicious.
    /// returns None if the classifier is unavailable or times out.
    pub async fn classify(&self, _input: &str) -> Option<ClassifierResult> {
        // TODO: implement Ollama / cloud API call
        // for now, return None (classifier unavailable)
        tracing::info!("Tier 3 LLM classifier not yet implemented");
        None
    }
}
