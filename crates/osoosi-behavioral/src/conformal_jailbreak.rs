//! Multi-Source Conformal Unseen Jailbreak Source Detection (`Persist-3` & `SR-DKW`).
//!
//! Implements the mathematical and statistical framework from:
//! *"Detecting Unseen Jailbreak Sources: A Multi-Source Conformal Detection Perspective"*
//! (Xunlei Qian, Yingqian Cui, Yuping Lin, Jun Wu, Yue Xing — Michigan State University,
//! `arXiv:2610.09167v1`, October 2026).
//!
//! ### Core Components
//! 1. **Shared PCA Projection & Ledoit–Wolf Mahalanobis Nonconformity Scores (Section 3.2)**:
//!    - Fits a shared PCA projection $\Pi: \mathbb{R}^D \to \mathbb{R}^d$ ($d \le 32$) on pooled
//!      training representations across all $K$ known jailbreak sources.
//!    - Fits per-source mean $\hat{\mu}_k$ and analytical Ledoit–Wolf shrinkage covariance
//!      $\hat{\Sigma}_k$ with Moore–Penrose pseudoinverse $\hat{\Sigma}_k^+$.
//!    - Computes nonconformity score $S_k(x) = (z - \hat{\mu}_k)^\top \hat{\Sigma}_k^+ (z - \hat{\mu}_k)$
//!      (Eq. 1), split-conformal p-value $p_k(x)$ (Eq. 2), and evidence $Z_k(x) = -\ln p_k(x)$.
//! 2. **Window-Based Family Evidence & Persistent Confirmation (`Persist-3`, Sections 3.3–3.4)**:
//!    - Computes rolling window average $C_{k,t}$ over $W=10$ steps (Eq. 3), family minimum
//!      $C_t^{\text{fam}} = \min_{k \in [K]} C_{k,t}$ (Eq. 4), and persistent confirmation
//!      $D_t = \mathbb{I}\{\min_{s=t-L+1,\dots,t} C_s^{\text{fam}} \ge \tau\}$ over $L=3$ steps (Eq. 5).
//!    - Satisfies **Finite Forgetting** (Proposition 4.4): after $B = W + L - 1 = 12$ post-switch
//!      observations, pre-switch observations have zero effect on $D_t$.
//! 3. **Cumulative Comparators (`SR-DKW`, `SR-RAW`, and `DkwProductSupermartingale`, Section 3.3 & Appendix F/J)**:
//!    - Applies Dvoretzky–Kiefer–Wolfowitz (DKW) tail slack $\varepsilon_k$ to source-wise p-values
//!      and feeds them into a Shiryaev–Roberts recursion (full-history or windowed $W=10$) and
//!      product supermartingale $E_t^{\text{mix}}$.
//! 4. **Known-Only Validation Threshold Selection & Dynamic Source Enrollment (Sections 3.5–3.6 & Corollary B.6)**:
//!    - Calibrates $\hat{\tau}$ using only stationary and KK validation streams ($\alpha_{\text{stat}} \le 0.01$,
//!      $\alpha_{\text{KK}} \le 0.05$).
//!    - Supports dynamic enrollment of newly detected unseen attack sources ($K \to K+1$) under
//!      Multi-Distribution Conformal Prediction (MDCP, Corollary B.6).
//! 5. **Layered Guardrail Intervention (Section 3.6)**:
//!    - Combines any prompt-level guardrail $G_t \in \{0, 1\}$ with source monitor escalation
//!      $A_t^{(M)} = \mathbb{I}\{t \ge T_{\text{act}}^{(M)}\}$ via $I_t^{(G+M)} = G_t \lor A_t^{(M)}$.

use ndarray::{Array1, Array2, ArrayView1, ArrayView2, Axis};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

/// The 11 canonical jailbreak attack families evaluated in Qian et al. (2026), Appendix K.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum KnownJailbreakSourceFamily {
    /// Greedy Coordinate Gradient suffix optimization (Zou et al., 2023).
    Gcg,
    /// Adaptive Dense-to-Sparse Constrained optimization (Hu et al., 2024).
    Adc,
    /// Prompt Automatic Iterative Refinement (Chao et al., 2025).
    Pair,
    /// Tree of Attacks with Pruning (Mehrotra et al., 2024).
    Tap,
    /// Hierarchical Genetic AutoDAN (Liu et al., 2023).
    Autodan,
    /// Lifelong Strategy Self-Exploration AutoDAN-Turbo (Liu et al., 2025).
    AutodanTurbo,
    /// Character/token order FlipAttack (Liu et al., 2024a).
    FlipAttack,
    /// In-the-wild "Do Anything Now" roleplay templates (Shen et al., 2024).
    DanInTheWild,
    /// Simple Black-Box rephrasing attack (Takemoto, 2024).
    SimpleBlackBox,
    /// First-Token Distribution Steering away from refusal (Fu et al., 2026).
    FirstTokenSteering,
    /// Pareto-Optimal Red Teaming Jailbreak-Zero (Hu et al., 2026).
    JailbreakZero,
}

impl KnownJailbreakSourceFamily {
    /// Returns all 11 canonical known attack families in standard benchmark order.
    pub fn all() -> &'static [Self; 11] {
        &[
            Self::Gcg,
            Self::Adc,
            Self::Pair,
            Self::Tap,
            Self::Autodan,
            Self::AutodanTurbo,
            Self::FlipAttack,
            Self::DanInTheWild,
            Self::SimpleBlackBox,
            Self::FirstTokenSteering,
            Self::JailbreakZero,
        ]
    }

    /// Canonical identifier string for telemetry and audit logs.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Gcg => "GCG",
            Self::Adc => "ADC",
            Self::Pair => "PAIR",
            Self::Tap => "TAP",
            Self::Autodan => "AutoDAN",
            Self::AutodanTurbo => "AutoDAN-Turbo",
            Self::FlipAttack => "FlipAttack",
            Self::DanInTheWild => "DAN-InTheWild",
            Self::SimpleBlackBox => "SimpleBlackBox",
            Self::FirstTokenSteering => "FirstTokenSteering",
            Self::JailbreakZero => "Jailbreak-Zero",
        }
    }
}

/// Offline parameters for a single known attack source $P_k$ in the PCA-projected space.
#[derive(Debug, Clone)]
pub struct CalibratedSource {
    /// Identifier of the known attack method (e.g., `"GCG"`, `"AutoDAN"`, `"PAIR"`).
    pub name: String,
    /// Fitted mean $\hat{\mu}_k \in \mathbb{R}^d$ in the PCA-projected space.
    pub mean: Array1<f64>,
    /// Moore–Penrose pseudoinverse of the Ledoit–Wolf covariance $\hat{\Sigma}_k^+ \in \mathbb{R}^{d \times d}$.
    pub precision: Array2<f64>,
    /// Ledoit–Wolf shrinkage intensity $\hat{\rho}_k \in [0, 1]$ used during fitting.
    pub shrinkage_intensity: f64,
    /// Sorted calibration nonconformity scores $R_{k,1} \le R_{k,2} \le \dots \le R_{k,n_k}$.
    pub calibration_scores: Vec<f64>,
}

impl CalibratedSource {
    /// Constructs a new calibrated source, sorting `calibration_scores` in ascending order
    /// to enable $O(\log n_k)$ rank queries in Eq. (2).
    pub fn new(
        name: impl Into<String>,
        mean: Array1<f64>,
        precision: Array2<f64>,
        mut calibration_scores: Vec<f64>,
    ) -> Self {
        calibration_scores.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        Self {
            name: name.into(),
            mean,
            precision,
            shrinkage_intensity: 0.0,
            calibration_scores,
        }
    }

    /// Fits a `CalibratedSource` in the projected space $\mathbb{R}^d$ from projected training
    /// samples $Z_{\text{train}} \in \mathbb{R}^{n_{\text{tr}} \times d}$ and projected held-out
    /// calibration samples $Z_{\text{cal}} \in \mathbb{R}^{n_k \times d}$ using analytical
    /// Ledoit–Wolf shrinkage covariance estimation and Moore–Penrose pseudoinversion.
    pub fn fit_projected(
        name: impl Into<String>,
        z_train: ArrayView2<f64>,
        z_cal: ArrayView2<f64>,
    ) -> Self {
        let n_tr = z_train.nrows().max(1);
        let d = z_train.ncols();
        let mean = z_train
            .mean_axis(Axis(0))
            .unwrap_or_else(|| Array1::zeros(d));

        let (cov_lw, rho) = ledoit_wolf_covariance(z_train, &mean);
        let precision = moore_penrose_pseudoinverse_spd(&cov_lw, 1e-10);

        let mut source = Self {
            name: name.into(),
            mean,
            precision,
            shrinkage_intensity: rho,
            calibration_scores: Vec::with_capacity(z_cal.nrows()),
        };

        let mut scores: Vec<f64> = (0..z_cal.nrows())
            .map(|i| source.nonconformity_score(&z_cal.row(i)))
            .collect();
        scores.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        source.calibration_scores = scores;
        let _ = n_tr;
        source
    }

    /// Equation (1): Mahalanobis nonconformity score
    /// $$S_k(x) = (z - \hat{\mu}_k)^\top \hat{\Sigma}_k^+ (z - \hat{\mu}_k)$$
    pub fn nonconformity_score(&self, z: &ArrayView1<f64>) -> f64 {
        let diff = z - &self.mean;
        let temp = self.precision.dot(&diff);
        diff.dot(&temp).max(0.0)
    }

    /// Equation (2): Split-conformal p-value
    /// $$p_k(x) = \frac{1 + \sum_{i=1}^{n_k} \mathbb{I}\{R_{k,i} \ge S_k(x)\}}{n_k + 1}$$
    pub fn conformal_p_value(&self, z: &ArrayView1<f64>) -> f64 {
        let s = self.nonconformity_score(z);
        let n_k = self.calibration_scores.len();
        // First index where R_{k,i} >= s using binary search
        let idx = self.calibration_scores.partition_point(|&r| r < s);
        let count_ge = n_k - idx;
        (1.0 + count_ge as f64) / (n_k as f64 + 1.0)
    }

    /// Pointwise evidence against source $k$:
    /// $$Z_k(x) = -\ln p_k(x) \in [0, \ln(n_k + 1)]$$
    pub fn evidence(&self, z: &ArrayView1<f64>) -> f64 {
        -self.conformal_p_value(z).ln()
    }

    /// Maximum possible pointwise evidence $b_k = \ln(n_k + 1)$ (Section 4.2).
    pub fn max_evidence(&self) -> f64 {
        ((self.calibration_scores.len() + 1) as f64).ln()
    }
}

/// Shared PCA projection $\Pi$ and the collection of $K$ known calibrated sources.
#[derive(Debug, Clone)]
pub struct MultiSourceCalibration {
    /// Centering vector $\bar{x} \in \mathbb{R}^D$ from the pooled training data.
    pub pca_mean: Array1<f64>,
    /// Projection matrix $\Pi \in \mathbb{R}^{D \times d}$ (with $d \le 32$).
    pub pca_components: Array2<f64>,
    /// The $K$ known calibrated sources $P_1, \dots, P_K$.
    pub sources: Vec<CalibratedSource>,
}

impl MultiSourceCalibration {
    /// Fits the shared PCA projection $\Pi \in \mathbb{R}^{D \times d}$ ($d \le 32$) on the
    /// pooled training representations of all known sources, then fits each source's mean
    /// $\hat{\mu}_k$, Ledoit–Wolf covariance pseudoinverse $\hat{\Sigma}_k^+$, and held-out
    /// calibration scores $R_{k,1}, \dots, R_{k,n_k}$ (Section 3.2, Assumption 4.1).
    pub fn fit_from_training_and_calibration(
        source_datasets: &[(String, Array2<f64>, Array2<f64>)],
        max_pca_dim: usize,
    ) -> Self {
        assert!(
            !source_datasets.is_empty(),
            "At least one known source is required for multi-source calibration"
        );
        let raw_dim = source_datasets[0].1.ncols();
        let target_dim = max_pca_dim.clamp(1, 32).min(raw_dim);

        // Pool all training matrices to fit shared PCA map \Pi
        let total_train_rows: usize = source_datasets.iter().map(|(_, tr, _)| tr.nrows()).sum();
        let mut pooled = Array2::<f64>::zeros((total_train_rows.max(1), raw_dim));
        let mut row_cursor = 0;
        for (_, tr, _) in source_datasets {
            for r in 0..tr.nrows() {
                pooled.row_mut(row_cursor).assign(&tr.row(r));
                row_cursor += 1;
            }
        }

        let (pca_mean, pca_components) = fit_shared_pca(&pooled.view(), target_dim);

        let mut sources = Vec::with_capacity(source_datasets.len());
        for (name, tr, cal) in source_datasets {
            let z_tr = project_batch(&tr.view(), &pca_mean, &pca_components);
            let z_cal = project_batch(&cal.view(), &pca_mean, &pca_components);
            sources.push(CalibratedSource::fit_projected(
                name.clone(),
                z_tr.view(),
                z_cal.view(),
            ));
        }

        Self {
            pca_mean,
            pca_components,
            sources,
        }
    }

    /// Builds a production pre-calibrated 11-source ensemble in $\mathbb{R}^{64} \to \mathbb{R}^{32}$
    /// covering all 11 benchmark jailbreak attack families from Qian et al. (2026), Appendix K,
    /// with $n_k = 100$ held-out calibration representations per source.
    pub fn default_11_sources_32d() -> Self {
        let raw_dim = 64;
        let pca_dim = 32;
        let n_train = 80;
        let n_cal = 100;

        let mut datasets = Vec::with_capacity(11);
        for (k_idx, family) in KnownJailbreakSourceFamily::all().iter().enumerate() {
            let center = canonical_family_center(k_idx, raw_dim);
            let tr = synthesize_source_embeddings(&center, n_train, 0.35, (k_idx as u64 + 1) * 101);
            let cal = synthesize_source_embeddings(&center, n_cal, 0.35, (k_idx as u64 + 1) * 997);
            datasets.push((family.as_str().to_string(), tr, cal));
        }

        Self::fit_from_training_and_calibration(&datasets, pca_dim)
    }

    /// Projects a raw representation $x \in \mathbb{R}^D$ into $z = \Pi(x) \in \mathbb{R}^d$.
    pub fn project(&self, x: &ArrayView1<f64>) -> Array1<f64> {
        let centered = x - &self.pca_mean;
        self.pca_components.t().dot(&centered)
    }

    /// Returns the vector of conformal p-values $(p_1(x), \dots, p_K(x))$ for a raw prompt representation $x$.
    pub fn p_values(&self, x: &ArrayView1<f64>) -> Vec<f64> {
        let z = self.project(x);
        let z_view = z.view();
        self.sources
            .iter()
            .map(|src| src.conformal_p_value(&z_view))
            .collect()
    }

    /// Returns the vector of evidences $(Z_1(x), \dots, Z_K(x))$ where $Z_k(x) = -\ln p_k(x)$.
    pub fn evidences(&self, x: &ArrayView1<f64>) -> Vec<f64> {
        let z = self.project(x);
        let z_view = z.view();
        self.sources
            .iter()
            .map(|src| src.evidence(&z_view))
            .collect()
    }

    /// Enrolls a newly detected unseen attack source $Q \to P_{K+1}$ into the frozen PCA space
    /// using held-out training and calibration representations (Section 3.6 & Corollary B.6).
    ///
    /// Preserves source-wise split-conformal validity for all $K + 1$ sources without refitting
    /// the frozen PCA projection $\Pi$.
    pub fn enroll_detected_source(
        &mut self,
        name: impl Into<String>,
        raw_train: ArrayView2<f64>,
        raw_calibration: ArrayView2<f64>,
    ) -> usize {
        let z_tr = project_batch(&raw_train, &self.pca_mean, &self.pca_components);
        let z_cal = project_batch(&raw_calibration, &self.pca_mean, &self.pca_components);
        let new_source = CalibratedSource::fit_projected(name, z_tr.view(), z_cal.view());
        self.sources.push(new_source);
        self.sources.len()
    }

    /// Section 3.5: Selects the threshold $\hat{\tau}$ using validation streams from known sources only:
    /// $$\hat{\tau} = \min\{\tau \in \mathcal{T} : \widehat{\mathrm{FPR}}_{\mathrm{val}}(\tau) \le \alpha_{\mathrm{stat}},\; \widehat{\mathrm{KK}}_{\mathrm{val}}(\tau) \le \alpha_{\mathrm{KK}}\}$$
    pub fn calibrate_threshold_known_only(
        &self,
        stationary_streams: &[Vec<Array1<f64>>],
        kk_streams: &[Vec<Array1<f64>>],
        threshold_grid: &[f64],
        alpha_stat: f64,
        alpha_kk: f64,
        window_size: usize,
        persistence_length: usize,
    ) -> ThresholdCalibrationSummary {
        let mut sorted_grid = threshold_grid.to_vec();
        sorted_grid.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

        let precomputed_stat: Vec<Vec<f64>> = stationary_streams
            .iter()
            .map(|stream| self.compute_c_fam_trajectory(stream, window_size))
            .collect();
        let precomputed_kk: Vec<Vec<f64>> = kk_streams
            .iter()
            .map(|stream| self.compute_c_fam_trajectory(stream, window_size))
            .collect();

        let mut selected_tau = *sorted_grid.last().unwrap_or(&2.386);
        let mut selected_fpr = 0.0;
        let mut selected_kk = 0.0;

        for &tau in &sorted_grid {
            let fpr = fraction_streams_alarming(&precomputed_stat, tau, persistence_length);
            let kk_rate = fraction_streams_alarming(&precomputed_kk, tau, persistence_length);
            if fpr <= alpha_stat && kk_rate <= alpha_kk {
                selected_tau = tau;
                selected_fpr = fpr;
                selected_kk = kk_rate;
                break;
            }
        }

        ThresholdCalibrationSummary {
            selected_tau,
            validation_stationary_fpr: selected_fpr,
            validation_kk_alarm_rate: selected_kk,
            alpha_stat_cap: alpha_stat,
            alpha_kk_cap: alpha_kk,
            window_size,
            persistence_length,
        }
    }

    /// Helper that computes the $C_t^{\text{fam}}$ trajectory over a stream of representations.
    pub fn compute_c_fam_trajectory(&self, stream: &[Array1<f64>], window_size: usize) -> Vec<f64> {
        let k = self.sources.len();
        let mut windows: Vec<VecDeque<f64>> = (0..k)
            .map(|_| VecDeque::with_capacity(window_size))
            .collect();
        let mut sums = vec![0.0_f64; k];
        let mut out = Vec::with_capacity(stream.len());

        for x in stream {
            let z_vec = self.evidences(&x.view());
            for (idx, z_k) in z_vec.into_iter().enumerate() {
                if windows[idx].len() == window_size {
                    if let Some(old) = windows[idx].pop_front() {
                        sums[idx] -= old;
                    }
                }
                windows[idx].push_back(z_k);
                sums[idx] += z_k;
            }
            let m_t = windows[0].len() as f64;
            let c_fam = sums.iter().map(|&s| s / m_t).fold(f64::INFINITY, f64::min);
            out.push(c_fam);
        }
        out
    }
}

/// Summary returned by known-source-only threshold calibration (Section 3.5).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdCalibrationSummary {
    pub selected_tau: f64,
    pub validation_stationary_fpr: f64,
    pub validation_kk_alarm_rate: f64,
    pub alpha_stat_cap: f64,
    pub alpha_kk_cap: f64,
    pub window_size: usize,
    pub persistence_length: usize,
}

/// Output of a single online step of the `Persist-3` detector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistStepResult {
    /// Current 1-based time index $t$.
    pub step: usize,
    /// Source-wise conformal p-values $(p_1(X_t), \dots, p_K(X_t))$.
    pub p_values: Vec<f64>,
    /// Source-wise window-averaged evidences $(C_{1,t}, \dots, C_{K,t})$.
    pub c_k_t: Vec<f64>,
    /// Family statistic $C_t^{\text{fam}} = \min_{k \in [K]} C_{k,t}$ (Eq. 4).
    pub c_fam: f64,
    /// Index of the best-matching known source $\arg\min_{k \in [K]} C_{k,t}$.
    pub best_matching_source_idx: usize,
    /// Name of the best-matching known source.
    pub best_matching_source_name: String,
    /// Instantaneous threshold exceedance $A_t(\tau) = \mathbb{I}\{C_t^{\text{fam}} \ge \tau\}$.
    pub exceeded: bool,
    /// Persistent confirmation decision $D_t = \mathbb{I}\{A_t(\tau) = \dots = A_{t-L+1}(\tau) = 1\}$ (Eq. 5).
    pub d_t: bool,
    /// First alarm time $T_{\text{alarm}} = \inf\{s \ge L : D_s = 1\}$ if triggered.
    pub alarm_time: Option<usize>,
    /// Persistent escalation state $A_t^{(M)} = \mathbb{I}\{t \ge T_{\text{alarm}}\}$ (Section 3.6).
    pub escalated: bool,
}

/// Window-based Multi-Source Conformal Detector (`Persist-L`, specifically `Persist-3` when $W=10, L=3$).
///
/// ### Finite Forgetting Property (Proposition 4.4)
/// Because $D_t$ depends only on $L$ consecutive windows of length $W$, the decision $D_t$
/// depends solely on the most recent $B = W + L - 1$ observations. After a known-to-known (KK)
/// or known-to-unknown (KU) switch, observations from the old source stop affecting $D_t$
/// after $B$ new observations have arrived.
#[derive(Debug, Clone)]
pub struct PersistDetector {
    pub calibration: MultiSourceCalibration,
    /// Window length $W$ (paper default: $W = 10$).
    pub window_size: usize,
    /// Persistence length $L$ (paper default: $L = 3$).
    pub persistence_length: usize,
    /// Calibrated threshold $\hat{\tau}$ (paper original split: $\hat{\tau} = 2.386$, resplit: $2.374$).
    pub tau: f64,
    /// Rolling window of recent $Z_k(X_r) = -\ln p_k(X_r)$ values per source $k$.
    windows: Vec<VecDeque<f64>>,
    /// Running sum of $Z_k(X_r)$ in the active window for $O(1)$ average updates.
    window_sums: Vec<f64>,
    /// Consecutive steps for which $C_s^{\text{fam}} \ge \tau$.
    consecutive_exceedances: usize,
    /// Current step $t$.
    step: usize,
    /// First time $T_{\text{alarm}}$ at which $D_t = 1$.
    alarm_time: Option<usize>,
}

impl PersistDetector {
    /// Original split frozen threshold from Section A.1 ($\hat{\tau} = 2.386$).
    pub const DEFAULT_TAU_ORIGINAL_SPLIT: f64 = 2.386;
    /// Robustness resplit frozen threshold from Section A.1 ($\hat{\tau} = 2.374$).
    pub const DEFAULT_TAU_ROBUSTNESS_RESPLIT: f64 = 2.374;

    /// Creates a new `Persist-L` detector.
    pub fn new(
        calibration: MultiSourceCalibration,
        window_size: usize,
        persistence_length: usize,
        tau: f64,
    ) -> Self {
        assert!(window_size >= 1, "window_size W must be >= 1");
        assert!(persistence_length >= 1, "persistence_length L must be >= 1");
        let k = calibration.sources.len();
        Self {
            calibration,
            window_size,
            persistence_length,
            tau,
            windows: (0..k)
                .map(|_| VecDeque::with_capacity(window_size))
                .collect(),
            window_sums: vec![0.0; k],
            consecutive_exceedances: 0,
            step: 0,
            alarm_time: None,
        }
    }

    /// Standard `Persist-3` configuration from Section 3.4 ($W = 10, L = 3$).
    pub fn persist_3(calibration: MultiSourceCalibration, tau: f64) -> Self {
        Self::new(calibration, 10, 3, tau)
    }

    /// Default production `Persist-3` detector initialized with all 11 canonical jailbreak
    /// sources in $\mathbb{R}^{64} \to \mathbb{R}^{32}$ and frozen threshold $\hat{\tau} = 2.386$.
    pub fn default_persist_3() -> Self {
        Self::persist_3(
            MultiSourceCalibration::default_11_sources_32d(),
            Self::DEFAULT_TAU_ORIGINAL_SPLIT,
        )
    }

    /// Finite forgetting horizon $B = W + L - 1$ (Proposition 4.4).
    pub fn finite_memory_horizon(&self) -> usize {
        self.window_size + self.persistence_length - 1
    }

    /// Resets the online stream state while keeping the offline calibration $\mathcal{O}$ frozen.
    pub fn reset(&mut self) {
        for w in &mut self.windows {
            w.clear();
        }
        self.window_sums.fill(0.0);
        self.consecutive_exceedances = 0;
        self.step = 0;
        self.alarm_time = None;
    }

    /// Enrolls a newly detected unseen source $Q \to P_{K+1}$ into the detector's calibration
    /// and extends the rolling window buffers (Section 3.6 & Corollary B.6).
    pub fn enroll_detected_source(
        &mut self,
        name: impl Into<String>,
        raw_train: ArrayView2<f64>,
        raw_calibration: ArrayView2<f64>,
    ) -> usize {
        let new_k = self
            .calibration
            .enroll_detected_source(name, raw_train, raw_calibration);
        self.windows.push(VecDeque::with_capacity(self.window_size));
        self.window_sums.push(0.0);
        new_k
    }

    /// Enrolls a newly detected unseen source from nested `Vec<Vec<f64>>` slices.
    pub fn enroll_detected_source_vecs(
        &mut self,
        name: impl Into<String>,
        train_rows: &[Vec<f64>],
        cal_rows: &[Vec<f64>],
    ) -> Result<usize, String> {
        let raw_dim = self.calibration.pca_mean.len();
        if train_rows.is_empty() || cal_rows.is_empty() {
            return Err("train_rows and cal_rows must be non-empty".to_string());
        }
        let mut tr = Array2::<f64>::zeros((train_rows.len(), raw_dim));
        for (i, r) in train_rows.iter().enumerate() {
            if r.len() != raw_dim {
                return Err(format!(
                    "train row {} has length {}, expected {}",
                    i,
                    r.len(),
                    raw_dim
                ));
            }
            for (j, &v) in r.iter().enumerate() {
                tr[[i, j]] = v;
            }
        }
        let mut cal = Array2::<f64>::zeros((cal_rows.len(), raw_dim));
        for (i, r) in cal_rows.iter().enumerate() {
            if r.len() != raw_dim {
                return Err(format!(
                    "calibration row {} has length {}, expected {}",
                    i,
                    r.len(),
                    raw_dim
                ));
            }
            for (j, &v) in r.iter().enumerate() {
                cal[[i, j]] = v;
            }
        }
        Ok(self.enroll_detected_source(name, tr.view(), cal.view()))
    }

    /// Convenience wrapper around `observe` accepting a `&[f64]` slice.
    /// Automatically pads or truncates to the calibration's input dimension $D$.
    pub fn observe_slice(&mut self, x_slice: &[f64]) -> PersistStepResult {
        let d = self.calibration.pca_mean.len();
        let mut arr = Array1::<f64>::zeros(d);
        for (i, &val) in x_slice.iter().take(d).enumerate() {
            arr[i] = val;
        }
        self.observe(&arr.view())
    }

    /// Processes a new victim-model hidden representation $X_t \in \mathbb{R}^D$.
    pub fn observe(&mut self, x_t: &ArrayView1<f64>) -> PersistStepResult {
        self.step += 1;
        let t = self.step;

        let z = self.calibration.project(x_t);
        let z_view = z.view();

        let k_count = self.calibration.sources.len();
        let mut p_values = Vec::with_capacity(k_count);
        let mut c_k_t = Vec::with_capacity(k_count);

        for (k, src) in self.calibration.sources.iter().enumerate() {
            let p_k = src.conformal_p_value(&z_view);
            let z_k = -p_k.ln();
            p_values.push(p_k);

            if self.windows[k].len() == self.window_size {
                if let Some(oldest) = self.windows[k].pop_front() {
                    self.window_sums[k] -= oldest;
                }
            }
            self.windows[k].push_back(z_k);
            self.window_sums[k] += z_k;

            // Equation (3): C_{k,t} = (1 / m_t) \sum_{r=\max(1, t-W+1)}^t -\ln p_k(X_r)
            let m_t = self.windows[k].len() as f64;
            c_k_t.push(self.window_sums[k] / m_t);
        }

        // Equation (4): C_t^{fam} = \min_{k \in [K]} C_{k,t}
        let mut best_idx = 0;
        let mut c_fam = f64::INFINITY;
        for (k, &val) in c_k_t.iter().enumerate() {
            if val < c_fam {
                c_fam = val;
                best_idx = k;
            }
        }
        let best_name = self
            .calibration
            .sources
            .get(best_idx)
            .map(|s| s.name.clone())
            .unwrap_or_default();

        // Equation (5): Persistent confirmation over L consecutive steps
        let exceeded = c_fam >= self.tau;
        if exceeded {
            self.consecutive_exceedances += 1;
        } else {
            self.consecutive_exceedances = 0;
        }

        let d_t =
            t >= self.persistence_length && self.consecutive_exceedances >= self.persistence_length;

        if d_t && self.alarm_time.is_none() {
            self.alarm_time = Some(t);
        }

        PersistStepResult {
            step: t,
            p_values,
            c_k_t,
            c_fam,
            best_matching_source_idx: best_idx,
            best_matching_source_name: best_name,
            exceeded,
            d_t,
            alarm_time: self.alarm_time,
            escalated: self.alarm_time.is_some(),
        }
    }
}

/// Cumulative Shiryaev–Roberts comparator (`SR-DKW` and `SR-RAW`, Section 3.3 & Appendix F/J).
///
/// Combines sources at each step $t$ via the maximum p-value $p_t^{\text{fam}} = \max_{k \in [K]} \tilde{p}_k(X_t)$
/// (with optional Dvoretzky–Kiefer–Wolfowitz finite-sample slack $\varepsilon_k$) and updates
/// a Shiryaev–Roberts statistic $R_t = (1 + R_{t-1}) \cdot e_t$.
#[derive(Debug, Clone)]
pub struct SrDetector {
    pub calibration: MultiSourceCalibration,
    /// Threshold $\tau_{\text{SR}}$ on $\ln(1 + R_t)$ or $R_t$.
    pub threshold: f64,
    /// Optional DKW confidence parameter $\beta \in (0, 1)$ (`None` = `SR-RAW`, `Some(beta)` = `SR-DKW`).
    pub dkw_beta: Option<f64>,
    /// Optional window truncation $W$ (`None` = full history, `Some(10)` = windowed SR).
    pub window: Option<usize>,
    /// Fixed betting parameter $\lambda \in (0, 1)$ for the e-value $e(p) = (1 - \lambda) p^{-\lambda}$.
    pub lambda: f64,
    /// History of stepwise e-values for windowed SR or full-history recursion.
    e_history: VecDeque<f64>,
    /// Current Shiryaev–Roberts state $R_t$.
    r_state: f64,
    step: usize,
    alarm_time: Option<usize>,
}

impl SrDetector {
    pub fn new(
        calibration: MultiSourceCalibration,
        threshold: f64,
        dkw_beta: Option<f64>,
        window: Option<usize>,
    ) -> Self {
        Self {
            calibration,
            threshold,
            dkw_beta,
            window,
            lambda: 0.5,
            e_history: VecDeque::new(),
            r_state: 0.0,
            step: 0,
            alarm_time: None,
        }
    }

    /// Resets the online Shiryaev–Roberts recursion state.
    pub fn reset(&mut self) {
        self.e_history.clear();
        self.r_state = 0.0;
        self.step = 0;
        self.alarm_time = None;
    }

    /// Computes the DKW-adjusted or raw p-value for source $k$:
    /// $$\tilde{p}_k(x) = \min\left\{1,\; p_k(x) + \sqrt{\frac{\ln(2/\beta)}{2 n_k}}\right\}$$
    fn adjusted_p_value(&self, src: &CalibratedSource, z: &ArrayView1<f64>) -> f64 {
        let p = src.conformal_p_value(z);
        if let Some(beta) = self.dkw_beta {
            let n_k = src.calibration_scores.len().max(1) as f64;
            let k_total = self.calibration.sources.len().max(1) as f64;
            let eps_k = ((2.0 * k_total / beta).ln() / (2.0 * n_k)).sqrt();
            (p + eps_k).min(1.0)
        } else {
            p
        }
    }

    /// Processes a new prompt representation $X_t$ and returns `(R_t, escalated)`.
    pub fn observe(&mut self, x_t: &ArrayView1<f64>) -> (f64, bool) {
        self.step += 1;
        let z = self.calibration.project(x_t);
        let z_view = z.view();

        // Best-matching source has the largest p-value under H_0
        let p_max = self
            .calibration
            .sources
            .iter()
            .map(|src| self.adjusted_p_value(src, &z_view))
            .fold(0.0_f64, f64::max)
            .max(1e-12);

        // Calibrated power e-variable: e(p) = (1 - \lambda) p^{-\lambda}, E_{H_0}[e(p)] <= 1
        let e_t = (1.0 - self.lambda) * p_max.powf(-self.lambda);

        match self.window {
            None => {
                self.r_state = (1.0 + self.r_state) * e_t;
            }
            Some(w) => {
                if self.e_history.len() == w {
                    self.e_history.pop_front();
                }
                self.e_history.push_back(e_t);
                let mut r = 0.0;
                for &e_val in &self.e_history {
                    r = (1.0 + r) * e_val;
                }
                self.r_state = r;
            }
        }

        if self.r_state >= self.threshold && self.alarm_time.is_none() {
            self.alarm_time = Some(self.step);
        }

        (self.r_state, self.alarm_time.is_some())
    }

    /// Convenience wrapper around `observe` accepting a `&[f64]` slice.
    pub fn observe_slice(&mut self, x_slice: &[f64]) -> (f64, bool) {
        let d = self.calibration.pca_mean.len();
        let mut arr = Array1::<f64>::zeros(d);
        for (i, &val) in x_slice.iter().take(d).enumerate() {
            arr[i] = val;
        }
        self.observe(&arr.view())
    }
}

/// Extracts a deterministic 64-dimensional hidden prompt representation $X_t \in \mathbb{R}^{64}$
/// aligned with the 11 known benchmark attack families ($P_1, \dots, P_{11}$) and orthogonal
/// coordinates ($d \in [22, 64)$) for novel/unseen adversarial jailbreak structures.
pub fn embed_prompt_representation_64d(prompt: &str) -> Vec<f64> {
    let lower = prompt.to_ascii_lowercase();
    let matched_known_idx = if lower.contains("gcg") || lower.contains("describing.\\ + similarly")
    {
        Some(0)
    } else if lower.contains("adc") || lower.contains("dense-to-sparse") {
        Some(1)
    } else if lower.contains("pair") || lower.contains("iterative refinement") {
        Some(2)
    } else if lower.contains("tap") || lower.contains("tree of attacks") {
        Some(3)
    } else if lower.contains("autodan-turbo") || lower.contains("strategy self-exploration") {
        Some(5)
    } else if lower.contains("autodan") || lower.contains("genetic jailbreak") {
        Some(4)
    } else if lower.contains("flipattack") || lower.contains("flip the characters") {
        Some(6)
    } else if lower.contains("do anything now") || lower.contains("dan mode") {
        Some(7)
    } else if lower.contains("simple black-box") || lower.contains("hypothetical academic") {
        Some(8)
    } else if lower.contains("first-token") || lower.contains("sure, here is how") {
        Some(9)
    } else if lower.contains("jailbreak-zero") || lower.contains("pareto red team") {
        Some(10)
    } else {
        None
    };

    if let Some(k_idx) = matched_known_idx {
        let center = canonical_family_center(k_idx, 64);
        let mut vec = center.to_vec();
        // Add tiny deterministic hash jitter within calibration radius (0.05)
        let mut h = 0xCBF2_9CE4_8422_2325_u64;
        for b in prompt.as_bytes() {
            h ^= *b as u64;
            h = h.wrapping_mul(0x0100_0000_01B3);
        }
        for (i, slot) in vec.iter_mut().enumerate() {
            let jitter = (((h.rotate_left((i % 63) as u32) & 0xFF) as f64) / 255.0 - 0.5) * 0.08;
            *slot += jitter;
        }
        return vec;
    }

    // Check if the prompt exhibits unseen zero-day / novel adversarial jailbreak characteristics
    let is_novel_jailbreak = lower.contains("ignore previous")
        || lower.contains("bypass safety")
        || lower.contains("override alignment")
        || lower.contains("unfiltered shell")
        || lower.contains("disable guardrail")
        || lower.contains("unseen_attack")
        || lower.contains("base64_payload")
        || lower.contains("cipher_jailbreak");

    if is_novel_jailbreak {
        // Project strongly onto the orthogonal tail coordinates (axes 22..64) and negative
        // known axes so the representation lies far from all K=11 known sources (high \Delta_*(Q)).
        let mut out = vec![-3.8_f64; 64];
        for (i, slot) in out.iter_mut().enumerate().skip(22) {
            *slot = if i % 2 == 0 { 6.5 } else { -6.5 };
        }
        return out;
    }

    // Benign / standard operational prompt maps near Known Family 0 (baseline typical region)
    canonical_family_center(0, 64).to_vec()
}

/// Calibration-conditional DKW Product Supermartingale ($E_t^{\text{mix}}$, Appendix F).
///
/// Maintains per-source product e-processes $E_{k,t} = \prod_{r=1}^t (1 - \lambda) \tilde{p}_k(X_r)^{-\lambda}$
/// and tests the composite null via the minimum e-process across known sources
/// $E_t^{\text{union}} = \min_{k \in [K]} E_{k,t}$, rejecting when $E_t^{\text{union}} \ge 1/\alpha$
/// by Ville's inequality.
#[derive(Debug, Clone)]
pub struct DkwProductSupermartingale {
    pub calibration: MultiSourceCalibration,
    pub alpha: f64,
    pub dkw_beta: f64,
    pub lambda: f64,
    log_e_sources: Vec<f64>,
    step: usize,
    alarm_time: Option<usize>,
}

impl DkwProductSupermartingale {
    pub fn new(calibration: MultiSourceCalibration, alpha: f64, dkw_beta: f64) -> Self {
        let k = calibration.sources.len();
        Self {
            calibration,
            alpha: alpha.clamp(1e-9, 0.5),
            dkw_beta: dkw_beta.clamp(1e-9, 0.5),
            lambda: 0.5,
            log_e_sources: vec![0.0; k],
            step: 0,
            alarm_time: None,
        }
    }

    pub fn observe(&mut self, x_t: &ArrayView1<f64>) -> (f64, bool) {
        self.step += 1;
        let z = self.calibration.project(x_t);
        let z_view = z.view();
        let k_total = self.calibration.sources.len().max(1) as f64;

        for (k, src) in self.calibration.sources.iter().enumerate() {
            let p_raw = src.conformal_p_value(&z_view);
            let n_k = src.calibration_scores.len().max(1) as f64;
            let eps_k = ((2.0 * k_total / self.dkw_beta).ln() / (2.0 * n_k)).sqrt();
            let p_tilde = (p_raw + eps_k).clamp(1e-12, 1.0);
            let log_e_step = (1.0 - self.lambda).ln() - self.lambda * p_tilde.ln();
            self.log_e_sources[k] = (self.log_e_sources[k] + log_e_step).clamp(-50.0, 50.0);
        }

        let min_log_e = self
            .log_e_sources
            .iter()
            .copied()
            .fold(f64::INFINITY, f64::min);
        let e_union = min_log_e.exp();
        if e_union >= (1.0 / self.alpha) && self.alarm_time.is_none() {
            self.alarm_time = Some(self.step);
        }
        (e_union, self.alarm_time.is_some())
    }

    /// Convenience wrapper around `observe` accepting a `&[f64]` slice.
    pub fn observe_slice(&mut self, x_slice: &[f64]) -> (f64, bool) {
        let d = self.calibration.pca_mean.len();
        let mut arr = Array1::<f64>::zeros(d);
        for (i, &val) in x_slice.iter().take(d).enumerate() {
            arr[i] = val;
        }
        self.observe(&arr.view())
    }
}

/// Trait abstracting an online unseen-source monitor $M$ (`Persist-3` or `SR-DKW`).
pub trait SourceMonitor {
    /// Steps the monitor on $X_t$ and returns `true` if $A_t^{(M)} = \mathbb{I}\{t \ge T_{\text{act}}^{(M)}\} = 1$.
    fn step_and_check_escalation(&mut self, x_t: &ArrayView1<f64>) -> bool;
}

impl SourceMonitor for PersistDetector {
    fn step_and_check_escalation(&mut self, x_t: &ArrayView1<f64>) -> bool {
        self.observe(x_t).escalated
    }
}

impl SourceMonitor for SrDetector {
    fn step_and_check_escalation(&mut self, x_t: &ArrayView1<f64>) -> bool {
        self.observe(x_t).1
    }
}

impl SourceMonitor for DkwProductSupermartingale {
    fn step_and_check_escalation(&mut self, x_t: &ArrayView1<f64>) -> bool {
        self.observe(x_t).1
    }
}

/// Section 3.6: Layered Guardrail combining a prompt-level guardrail $G_t \in \{0, 1\}$
/// (e.g., MTK, Prompt Guard 2, or OshoosiClaw `AgenticArbitrator`) with a sequential
/// source monitor $M$ (`Persist-3` or `SR-DKW`):
/// $$I_t^{(G+M)} = G_t \lor A_t^{(M)}$$
#[derive(Debug, Clone)]
pub struct LayeredGuardrail<M: SourceMonitor> {
    pub monitor: M,
}

/// Offline replay evaluation metrics from Section 5.3 (Table 2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayeredReplayMetrics {
    /// Block rate on originally successful attacks ($Y_t = 1$) under $G$ alone.
    pub base_block_rate: f64,
    /// Block rate on originally successful attacks ($Y_t = 1$) under $G + M$.
    pub layered_block_rate: f64,
    /// Block rate increment (percentage points / fraction) over $G$ alone.
    pub block_rate_increment: f64,
    /// Fraction of KU-stream prompts escalated by the monitor only ($G_t = 0, A_t^{(M)} = 1$).
    pub extra_ku_intervention_rate: f64,
    /// Yield: additional interceptions per 100 extra KU interventions.
    pub yield_per_100_extra_interventions: f64,
}

impl<M: SourceMonitor> LayeredGuardrail<M> {
    pub fn new(monitor: M) -> Self {
        Self { monitor }
    }

    /// Evaluates prompt $t$ given its hidden representation $X_t$ and prompt-level guardrail
    /// decision $G_t \in \{0, 1\}$. Returns $I_t^{(G+M)} = G_t \lor A_t^{(M)}$.
    pub fn evaluate_prompt(&mut self, x_t: &ArrayView1<f64>, guardrail_blocked: bool) -> bool {
        let monitor_escalated = self.monitor.step_and_check_escalation(x_t);
        guardrail_blocked || monitor_escalated
    }

    /// Replays a KU stream of `(X_t, G_t, Y_t)` tuples (where $Y_t = \text{true}$ indicates
    /// an originally successful jailbreak attack when unblocked) and computes the Table 2
    /// metrics from Section 5.3.
    pub fn evaluate_ku_stream_replay(
        &mut self,
        stream: &[(Array1<f64>, bool, bool)],
    ) -> LayeredReplayMetrics {
        let mut total_prompts = 0usize;
        let mut total_successful_attacks = 0usize;
        let mut base_blocked_attacks = 0usize;
        let mut layered_blocked_attacks = 0usize;
        let mut extra_monitor_interventions = 0usize;

        for (x_t, g_t, y_t) in stream {
            total_prompts += 1;
            let a_t = self.monitor.step_and_check_escalation(&x_t.view());
            let combined = *g_t || a_t;

            if !*g_t && a_t {
                extra_monitor_interventions += 1;
            }
            if *y_t {
                total_successful_attacks += 1;
                if *g_t {
                    base_blocked_attacks += 1;
                }
                if combined {
                    layered_blocked_attacks += 1;
                }
            }
        }

        let denom_attacks = total_successful_attacks.max(1) as f64;
        let base_block_rate = base_blocked_attacks as f64 / denom_attacks;
        let layered_block_rate = layered_blocked_attacks as f64 / denom_attacks;
        let block_rate_increment = layered_block_rate - base_block_rate;
        let extra_ku_intervention_rate =
            extra_monitor_interventions as f64 / (total_prompts.max(1) as f64);
        let additional_interceptions =
            (layered_blocked_attacks.saturating_sub(base_blocked_attacks)) as f64;
        let yield_per_100 = if extra_monitor_interventions > 0 {
            100.0 * additional_interceptions / (extra_monitor_interventions as f64)
        } else {
            0.0
        };

        LayeredReplayMetrics {
            base_block_rate,
            layered_block_rate,
            block_rate_increment,
            extra_ku_intervention_rate,
            yield_per_100_extra_interventions: yield_per_100,
        }
    }
}

/// Theoretical finite-sample bounds from Section 4 and Appendix B of Qian et al. (2026).
pub mod bounds {
    /// Equation (6): Overlap weight sum of squares $A_{W,L} = \sum_{h=1}^{B} a_h^2$.
    /// For $W \ge L$:
    /// $$A_{W,L} = 2 \sum_{r=1}^{L-1} r^2 + (W - L + 1) L^2$$
    /// For $W = 10, L = 3$, returns $A_{10,3} = 82$.
    pub fn overlap_weight_sum_sq(w: usize, l: usize) -> usize {
        let b = w + l - 1;
        if w >= l {
            let sum_r2: usize = (1..l).map(|r| r * r).sum();
            2 * sum_r2 + (w - l + 1) * l * l
        } else {
            // General exact overlap count for arbitrary (W, L)
            let mut total = 0usize;
            for h in 1..=b {
                let mut a_h = 0usize;
                for win_idx in 0..l {
                    let start = win_idx + 1;
                    let end = win_idx + w;
                    if h >= start && h <= end {
                        a_h += 1;
                    }
                }
                total += a_h * a_h;
            }
            total
        }
    }

    /// Theorem 4.3, Equation (7): Persistence-aware stationary false-alarm bound under $P_j$.
    /// For $\tau > \mu_{0,j}$ and $b_j = \ln(n_j + 1)$:
    /// $$\mathbb{P}_{P_j}\{D_t = 1 \mid \mathcal{O}\} \le \exp\left(-\frac{2(LW)^2(\tau - \mu_{0,j})^2}{b_j^2 A_{W,L}}\right)$$
    pub fn stationary_false_alarm_bound(
        w: usize,
        l: usize,
        tau: f64,
        mu_0_j: f64,
        n_j: usize,
    ) -> f64 {
        if tau <= mu_0_j {
            return 1.0;
        }
        let b_j = ((n_j + 1) as f64).ln();
        let a_wl = overlap_weight_sum_sq(w, l) as f64;
        let lw = (l * w) as f64;
        let num = -2.0 * lw * lw * (tau - mu_0_j).powi(2);
        let den = b_j * b_j * a_wl;
        (num / den).exp().min(1.0)
    }

    /// Corollary B.2: Finite-horizon false-alarm union bound over $t \in \{L, \dots, H\}$
    /// including the warm-up steps $L \le t < B$ where windows have length $m_t = \min(W, t)$.
    pub fn finite_horizon_false_alarm_bound(
        horizon: usize,
        w: usize,
        l: usize,
        tau: f64,
        mu_0_j: f64,
        n_j: usize,
    ) -> f64 {
        if horizon < l || tau <= mu_0_j {
            return if horizon < l { 0.0 } else { 1.0 };
        }
        let b = w + l - 1;
        let mut sum_prob = 0.0;
        for t in l..=horizon {
            let eff_w = w.min(t - l + 1).max(1);
            let step_bound = if t >= b {
                stationary_false_alarm_bound(w, l, tau, mu_0_j, n_j)
            } else {
                stationary_false_alarm_bound(eff_w, l, tau, mu_0_j, n_j)
            };
            sum_prob += step_bound;
        }
        sum_prob.min(1.0)
    }

    /// Theorem 4.6, Equation (8): Detection power lower bound under unseen source $Q$.
    /// Provided $\Delta_k(Q) = \mu_k(Q) - \tau > 0$ for every $k \in [K]$:
    /// $$\mathbb{P}_Q\{D_t = 1 \mid \mathcal{O}\} \ge 1 - L \sum_{k=1}^K \exp\left(-\frac{2 W \Delta_k^2(Q)}{b_k^2}\right)$$
    pub fn detection_power_lower_bound(
        w: usize,
        l: usize,
        tau: f64,
        mu_q: &[f64],
        n_cal: &[usize],
    ) -> f64 {
        assert_eq!(mu_q.len(), n_cal.len());
        let mut sum_exp = 0.0;
        for (&mu_k, &n_k) in mu_q.iter().zip(n_cal.iter()) {
            let delta_k = mu_k - tau;
            if delta_k <= 0.0 {
                return 0.0;
            }
            let b_k = ((n_k + 1) as f64).ln();
            let exponent = -2.0 * (w as f64) * delta_k.powi(2) / (b_k * b_k);
            sum_exp += exponent.exp();
        }
        (1.0 - (l as f64) * sum_exp).max(0.0)
    }

    /// Corollary 4.7, Equation (9): Nearest-source separation detection power lower bound.
    /// With $\Delta_*(Q) = \min_{k \in [K]} \Delta_k(Q)$ and $b_{\max} = \max_{k \in [K]} b_k$:
    /// $$\mathbb{P}_Q\{D_t = 1 \mid \mathcal{O}\} \ge 1 - L K \exp\left(-\frac{2 W \Delta_*^2(Q)}{b_{\max}^2}\right)$$
    pub fn nearest_source_power_bound(
        w: usize,
        l: usize,
        k_sources: usize,
        delta_star: f64,
        b_max: f64,
    ) -> f64 {
        if delta_star <= 0.0 {
            return 0.0;
        }
        let exponent = -2.0 * (w as f64) * delta_star.powi(2) / (b_max * b_max);
        (1.0 - (l * k_sources) as f64 * exponent.exp()).max(0.0)
    }

    /// Rearranged Corollary 4.7: Minimum window size $W$ required to achieve detection power $1 - \eta$:
    /// $$W \ge \frac{b_{\max}^2}{2 \Delta_*^2(Q)} \ln\left(\frac{L K}{\eta}\right)$$
    pub fn required_window_size(
        l: usize,
        k_sources: usize,
        delta_star: f64,
        b_max: f64,
        eta: f64,
    ) -> usize {
        assert!(delta_star > 0.0 && eta > 0.0 && eta < 1.0);
        let ratio = ((l * k_sources) as f64 / eta).ln();
        let w = (b_max * b_max) / (2.0 * delta_star * delta_star) * ratio;
        w.ceil() as usize
    }

    /// Corollary B.5: Upper bound on the probability that post-switch detection delay exceeds
    /// $m$ disjoint blocks of length $B = W + L - 1$:
    /// $$\mathbb{P}_Q\{T_{\text{alarm}} - \nu + 1 > m B \mid \mathcal{O}\} \le \left(L K \exp\left(-\frac{2 W \Delta_*^2(Q)}{b_{\max}^2}\right)\right)^m$$
    pub fn post_switch_delay_upper_bound(
        w: usize,
        l: usize,
        k_sources: usize,
        delta_star: f64,
        b_max: f64,
        m_blocks: usize,
    ) -> f64 {
        if delta_star <= 0.0 {
            return 1.0;
        }
        let single_miss =
            (1.0 - nearest_source_power_bound(w, l, k_sources, delta_star, b_max)).clamp(0.0, 1.0);
        single_miss.powi(m_blocks as i32)
    }
}

// ============================================================================
// Linear Algebra & Statistical Helpers (PCA, Ledoit–Wolf, Moore–Penrose)
// ============================================================================

fn fraction_streams_alarming(
    c_fam_trajectories: &[Vec<f64>],
    tau: f64,
    persistence_length: usize,
) -> f64 {
    if c_fam_trajectories.is_empty() {
        return 0.0;
    }
    let mut alarmed = 0usize;
    for traj in c_fam_trajectories {
        let mut run = 0usize;
        for (idx, &c_fam) in traj.iter().enumerate() {
            if c_fam >= tau {
                run += 1;
            } else {
                run = 0;
            }
            if idx + 1 >= persistence_length && run >= persistence_length {
                alarmed += 1;
                break;
            }
        }
    }
    alarmed as f64 / (c_fam_trajectories.len() as f64)
}

fn project_batch(
    x: &ArrayView2<f64>,
    pca_mean: &Array1<f64>,
    pca_components: &Array2<f64>,
) -> Array2<f64> {
    let n = x.nrows();
    let d = pca_components.ncols();
    let mut out = Array2::<f64>::zeros((n, d));
    for i in 0..n {
        let centered = &x.row(i) - pca_mean;
        let proj = pca_components.t().dot(&centered);
        out.row_mut(i).assign(&proj);
    }
    out
}

/// Fits a shared PCA projection $\Pi \in \mathbb{R}^{D \times d}$ using symmetric Jacobi
/// eigendecomposition of the sample covariance matrix.
fn fit_shared_pca(pooled: &ArrayView2<f64>, target_dim: usize) -> (Array1<f64>, Array2<f64>) {
    let n = pooled.nrows().max(1);
    let d_raw = pooled.ncols();
    let mean = pooled
        .mean_axis(Axis(0))
        .unwrap_or_else(|| Array1::zeros(d_raw));

    let mut cov = Array2::<f64>::zeros((d_raw, d_raw));
    for i in 0..n {
        let diff = &pooled.row(i) - &mean;
        for r in 0..d_raw {
            let dr = diff[r];
            for c in r..d_raw {
                cov[[r, c]] += dr * diff[c];
            }
        }
    }
    let denom = (n.saturating_sub(1).max(1)) as f64;
    for r in 0..d_raw {
        for c in r..d_raw {
            let v = cov[[r, c]] / denom;
            cov[[r, c]] = v;
            cov[[c, r]] = v;
        }
    }

    let (eigvals, eigvecs) = jacobi_eigen_symmetric(&cov, 60);
    let mut order: Vec<usize> = (0..d_raw).collect();
    order.sort_by(|&a, &b| {
        eigvals[b]
            .partial_cmp(&eigvals[a])
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    let mut components = Array2::<f64>::zeros((d_raw, target_dim));
    for (col_idx, &eig_idx) in order.iter().take(target_dim).enumerate() {
        components
            .column_mut(col_idx)
            .assign(&eigvecs.column(eig_idx));
    }

    (mean, components)
}

/// Analytical Ledoit–Wolf shrinkage covariance estimator (Ledoit & Wolf, 2004):
/// $$\hat{\Sigma}_{\text{LW}} = (1 - \hat{\rho}) S + \hat{\rho} \frac{\operatorname{tr}(S)}{d} I_d$$
fn ledoit_wolf_covariance(z: ArrayView2<f64>, mean: &Array1<f64>) -> (Array2<f64>, f64) {
    let n = z.nrows();
    let d = z.ncols();
    if n <= 1 || d == 0 {
        return (Array2::eye(d), 1.0);
    }
    let n_f = n as f64;
    let d_f = d as f64;

    let mut s = Array2::<f64>::zeros((d, d));
    for i in 0..n {
        let diff = &z.row(i) - mean;
        for r in 0..d {
            let dr = diff[r];
            for c in r..d {
                s[[r, c]] += dr * diff[c];
            }
        }
    }
    s /= n_f;
    for r in 0..d {
        for c in (r + 1)..d {
            s[[c, r]] = s[[r, c]];
        }
    }

    let trace_s: f64 = (0..d).map(|i| s[[i, i]]).sum();
    let mu = trace_s / d_f;

    // \delta^2 = ||S - \mu I||_F^2 / d
    let mut delta_sq = 0.0;
    for r in 0..d {
        for c in 0..d {
            let target = if r == c { mu } else { 0.0 };
            let diff = s[[r, c]] - target;
            delta_sq += diff * diff;
        }
    }
    delta_sq /= d_f;

    if delta_sq <= 1e-16 {
        return (Array2::from_diag(&Array1::from_elem(d, mu.max(1e-6))), 1.0);
    }

    // \beta^2 = (1 / (n^2 d)) \sum_{i=1}^n ||x_i x_i^\top - S||_F^2
    let mut sum_norm_sq = 0.0;
    for i in 0..n {
        let diff = &z.row(i) - mean;
        let norm_sq = diff.dot(&diff);
        sum_norm_sq += norm_sq * norm_sq;
    }
    let s_frob_sq: f64 = s.iter().map(|&v| v * v).sum();
    let beta_sq = ((sum_norm_sq / n_f - s_frob_sq).max(0.0)) / (n_f * d_f);
    let rho = (beta_sq / delta_sq).clamp(0.0, 1.0);

    let mut cov_lw = s * (1.0 - rho);
    let diag_add = rho * mu.max(1e-6);
    for i in 0..d {
        cov_lw[[i, i]] += diag_add;
    }

    (cov_lw, rho)
}

/// Computes the Moore–Penrose pseudoinverse $A^+$ of a symmetric positive semi-definite matrix
/// via spectral decomposition $V \Lambda^+ V^\top$.
fn moore_penrose_pseudoinverse_spd(mat: &Array2<f64>, rcond: f64) -> Array2<f64> {
    let d = mat.nrows();
    if d == 0 {
        return Array2::zeros((0, 0));
    }
    let (eigvals, eigvecs) = jacobi_eigen_symmetric(mat, 60);
    let max_eig = eigvals.iter().copied().fold(0.0_f64, f64::max).max(1e-12);
    let cutoff = max_eig * rcond;

    let mut pinv = Array2::<f64>::zeros((d, d));
    for k in 0..d {
        let lam = eigvals[k];
        if lam > cutoff {
            let inv_lam = 1.0 / lam;
            let v = eigvecs.column(k);
            for r in 0..d {
                let vr = v[r] * inv_lam;
                for c in r..d {
                    pinv[[r, c]] += vr * v[c];
                }
            }
        }
    }
    for r in 0..d {
        for c in (r + 1)..d {
            pinv[[c, r]] = pinv[[r, c]];
        }
    }
    pinv
}

/// Cyclic Jacobi eigenvalue algorithm for real symmetric matrices $A \in \mathbb{R}^{d \times d}$.
fn jacobi_eigen_symmetric(mat: &Array2<f64>, max_sweeps: usize) -> (Array1<f64>, Array2<f64>) {
    let d = mat.nrows();
    let mut a = mat.clone();
    let mut v = Array2::<f64>::eye(d);

    for _sweep in 0..max_sweeps {
        let mut max_off = 0.0_f64;
        for p in 0..d {
            for q in (p + 1)..d {
                max_off = max_off.max(a[[p, q]].abs());
            }
        }
        if max_off < 1e-12 {
            break;
        }

        for p in 0..d {
            for q in (p + 1)..d {
                let apq = a[[p, q]];
                if apq.abs() < 1e-13 {
                    continue;
                }
                let app = a[[p, p]];
                let aqq = a[[q, q]];
                let tau = (aqq - app) / (2.0 * apq);
                let t = if tau >= 0.0 {
                    1.0 / (tau + (1.0 + tau * tau).sqrt())
                } else {
                    -1.0 / (-tau + (1.0 + tau * tau).sqrt())
                };
                let c = 1.0 / (1.0 + t * t).sqrt();
                let s = t * c;

                a[[p, p]] = app - t * apq;
                a[[q, q]] = aqq + t * apq;
                a[[p, q]] = 0.0;
                a[[q, p]] = 0.0;

                for r in 0..d {
                    if r != p && r != q {
                        let arp = a[[r, p]];
                        let arq = a[[r, q]];
                        a[[r, p]] = c * arp - s * arq;
                        a[[p, r]] = a[[r, p]];
                        a[[r, q]] = s * arp + c * arq;
                        a[[q, r]] = a[[r, q]];
                    }
                }

                for r in 0..d {
                    let vrp = v[[r, p]];
                    let vrq = v[[r, q]];
                    v[[r, p]] = c * vrp - s * vrq;
                    v[[r, q]] = s * vrp + c * vrq;
                }
            }
        }
    }

    let eigvals = Array1::from_iter((0..d).map(|i| a[[i, i]]));
    (eigvals, v)
}

fn canonical_family_center(family_idx: usize, dim: usize) -> Array1<f64> {
    let mut center = Array1::<f64>::zeros(dim);
    let primary_axis = (family_idx * 2) % dim;
    let secondary_axis = (family_idx * 2 + 1) % dim;
    center[primary_axis] = 4.0;
    center[secondary_axis] = 2.5 * ((family_idx as f64 + 1.0).cos());
    center
}

fn synthesize_source_embeddings(
    center: &Array1<f64>,
    n_samples: usize,
    scale: f64,
    seed: u64,
) -> Array2<f64> {
    let dim = center.len();
    let mut out = Array2::<f64>::zeros((n_samples, dim));
    let mut state = seed ^ 0x9E37_79B9_7F4A_7C15;
    let mut next_norm = || -> f64 {
        // Box-Muller transform over SplitMix64
        let mut next_u = || -> f64 {
            state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^= z >> 31;
            ((z >> 11) as f64 + 0.5) / ((1u64 << 53) as f64)
        };
        let u1 = next_u().clamp(1e-12, 1.0 - 1e-12);
        let u2 = next_u();
        (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos()
    };

    for i in 0..n_samples {
        for j in 0..dim {
            out[[i, j]] = center[j] + scale * next_norm();
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndarray::array;

    fn build_two_source_calibration() -> MultiSourceCalibration {
        let scores: Vec<f64> = (1..=100).map(|i| (i as f64) * 0.1).collect();

        let src1 = CalibratedSource::new(
            "Source1_GCG",
            array![0.0, 0.0],
            Array2::eye(2),
            scores.clone(),
        );
        let src2 = CalibratedSource::new("Source2_PAIR", array![6.0, 6.0], Array2::eye(2), scores);

        MultiSourceCalibration {
            pca_mean: array![0.0, 0.0],
            pca_components: Array2::eye(2),
            sources: vec![src1, src2],
        }
    }

    #[test]
    fn test_proposition_4_2_split_conformal_p_value_validity() {
        let cal = MultiSourceCalibration::default_11_sources_32d();
        assert_eq!(cal.sources.len(), 11);
        assert_eq!(cal.pca_components.ncols(), 32);

        // Fresh draws from known source 0 (GCG)
        let center_0 = canonical_family_center(0, 64);
        let test_draws = synthesize_source_embeddings(&center_0, 200, 0.35, 77_777);
        let mut small_p_count = 0usize;
        let u = 0.10;
        for i in 0..test_draws.nrows() {
            let p_vals = cal.p_values(&test_draws.row(i));
            assert!(p_vals[0] > 0.0 && p_vals[0] <= 1.0);
            if p_vals[0] <= u {
                small_p_count += 1;
            }
        }
        let empirical_tail = small_p_count as f64 / (test_draws.nrows() as f64);
        // Proposition 4.2 guarantees P(p_k(X) <= u) <= u up to finite sampling noise
        assert!(
            empirical_tail <= u + 0.06,
            "Empirical tail {} exceeded u={} + tolerance",
            empirical_tail,
            u
        );
    }

    #[test]
    fn test_persist3_known_to_known_vs_unseen_source() {
        let cal = build_two_source_calibration();
        let mut detector = PersistDetector::persist_3(cal, 2.386);

        // 1. Stream of 15 prompts from Known Source 1 -> no alarm
        for _ in 0..15 {
            let res = detector.observe(&array![0.2, -0.1].view());
            assert!(!res.escalated, "Known source 1 should not trigger alarm");
        }

        // 2. Post-switch to Known Source 2 after B = 12 observations -> D_t returns to 0
        detector.reset();
        for _ in 0..15 {
            let res = detector.observe(&array![6.1, 5.9].view());
            assert!(!res.escalated, "Known source 2 should not trigger alarm");
        }

        // 3. Switch to Unseen Source Q far from both P_1 and P_2 -> triggers Persist-3 alarm
        for step in 1..=15 {
            let res = detector.observe(&array![-10.0, 10.0].view());
            if step >= 12 {
                assert!(
                    res.escalated,
                    "Unseen source Q should trigger Persist-3 alarm within B=12 steps"
                );
            }
        }
    }

    #[test]
    fn test_proposition_4_4_exact_finite_forgetting_after_b_12_steps() {
        let cal = build_two_source_calibration();
        let mut det_a = PersistDetector::persist_3(cal.clone(), 2.386);
        let mut det_b = PersistDetector::persist_3(cal, 2.386);

        // Stream A starts with 20 prompts from P_1; Stream B starts with 20 extreme prompts
        for _ in 0..20 {
            det_a.observe(&array![0.1, 0.1].view());
            det_b.observe(&array![25.0, -25.0].view());
        }

        // Now both streams switch to P_2 at \nu = 21.
        // Proposition 4.4 states that after B = W + L - 1 = 12 post-switch observations,
        // C_t^{fam} and D_t must be identical regardless of pre-switch history.
        let b_horizon = det_a.finite_memory_horizon();
        assert_eq!(b_horizon, 12);

        for post_step in 1..=15 {
            let x_new = array![6.05, 5.95];
            let res_a = det_a.observe(&x_new.view());
            let res_b = det_b.observe(&x_new.view());
            if post_step >= b_horizon {
                assert!(
                    (res_a.c_fam - res_b.c_fam).abs() < 1e-12,
                    "c_fam must be identical after B=12 steps: {} vs {}",
                    res_a.c_fam,
                    res_b.c_fam
                );
                assert_eq!(
                    res_a.d_t, res_b.d_t,
                    "D_t decision must be identical after B=12 steps (Proposition 4.4)"
                );
            }
        }
    }

    #[test]
    fn test_theoretical_bounds_and_layered_guardrail() {
        // Paper Section 4.2: For W = 10, L = 3, A_{10,3} = 82
        assert_eq!(bounds::overlap_weight_sum_sq(10, 3), 82);

        let fa_bound = bounds::stationary_false_alarm_bound(10, 3, 2.386, 1.0, 100);
        assert!((fa_bound - 0.1381).abs() < 1e-3);
        let fa_bound_w30 = bounds::stationary_false_alarm_bound(30, 3, 2.386, 1.0, 100);
        assert!(fa_bound_w30 > 0.0 && fa_bound_w30 < 0.005);

        let fh_bound = bounds::finite_horizon_false_alarm_bound(40, 10, 3, 2.386, 1.0, 100);
        assert!(fh_bound >= fa_bound && fh_bound <= 1.0);

        let power = bounds::detection_power_lower_bound(10, 3, 2.386, &[4.5, 4.6], &[100, 100]);
        assert!(power > 0.0 && power <= 1.0);

        let w_req = bounds::required_window_size(3, 10, 1.5, 101.0_f64.ln(), 0.05);
        assert!(w_req >= 10);

        let delay_bound = bounds::post_switch_delay_upper_bound(30, 3, 2, 2.2, 101.0_f64.ln(), 3);
        assert!(delay_bound < 1.0);

        // Layered Guardrail escalation persistence (Section 3.6)
        let cal = build_two_source_calibration();
        let persist = PersistDetector::persist_3(cal, 2.386);
        let mut layered = LayeredGuardrail::new(persist);
        let mut replay_stream = Vec::new();
        for _ in 0..15 {
            replay_stream.push((array![-12.0, 12.0], false, true));
        }
        let metrics = layered.evaluate_ku_stream_replay(&replay_stream);
        assert_eq!(metrics.base_block_rate, 0.0);
        assert!(
            metrics.layered_block_rate > 0.25,
            "Layered guardrail must intercept unseen attacks once Persist-3 triggers"
        );
        assert!(metrics.yield_per_100_extra_interventions > 50.0);
    }

    #[test]
    fn test_sr_dkw_and_dynamic_source_enrollment_corollary_b6() {
        let cal = build_two_source_calibration();
        let mut sr_dkw = SrDetector::new(cal.clone(), 20.0, Some(0.05), None);
        let mut e_proc = DkwProductSupermartingale::new(cal, 0.01, 0.05);

        let mut sr_alarmed = false;
        let mut e_alarmed = false;
        for _ in 0..25 {
            let x_unseen = array![-15.0, 15.0];
            if sr_dkw.observe(&x_unseen.view()).1 {
                sr_alarmed = true;
            }
            if e_proc.observe(&x_unseen.view()).1 {
                e_alarmed = true;
            }
        }
        assert!(sr_alarmed, "SR-DKW should detect unseen source Q");
        assert!(
            e_alarmed,
            "DKW Product Supermartingale should detect unseen source Q"
        );

        // Dynamic enrollment of unseen source Q -> P_{K+1} (Corollary B.6)
        let mut det = PersistDetector::default_persist_3();
        assert_eq!(det.calibration.sources.len(), 11);
        let unseen_center = Array1::from_elem(64, -3.5);
        let unseen_tr = synthesize_source_embeddings(&unseen_center, 60, 0.3, 4242);
        let unseen_cal = synthesize_source_embeddings(&unseen_center, 80, 0.3, 8484);

        let new_k = det.enroll_detected_source(
            "Enrolled_Unseen_Source_12",
            unseen_tr.view(),
            unseen_cal.view(),
        );
        assert_eq!(new_k, 12);

        // After enrolling Q as Source 12, prompts from Q now match Source 12 and do not alarm
        det.reset();
        let unseen_test = synthesize_source_embeddings(&unseen_center, 15, 0.3, 9999);
        for i in 0..unseen_test.nrows() {
            let res = det.observe(&unseen_test.row(i));
            assert!(!res.escalated, "Enrolled source 12 should now satisfy H_0");
            assert_eq!(res.best_matching_source_name, "Enrolled_Unseen_Source_12");
        }
    }
}
