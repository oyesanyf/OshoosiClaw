//! Discrete-Time Exponential Control Barrier Functions (CBF) & Fiscal Ledger
//!
//! Enforces mathematical safety guarantees on resource depletion and budget allocation.
//! Formally defined by the discrete-time barrier inequality:
//!
//! $$h_{t+1} = (B_t - c) - B_{\min} \ge (1 - \gamma) h_t \ge 0$$
//!
//! where:
//! - $B_t$ is the current budget balance
//! - $c \ge 0$ is the proposed action fuel expenditure
//! - $B_{\min}$ is the invariant reserve floor threshold
//! - $\gamma \in (0, 1]$ is the maximum fractional safety margin decay rate per step
//! - $h_t = B_t - B_{\min}$ is the barrier safety margin at time $t$
//!
//! If the barrier condition is met, fuel is pre-reserved atomically and a [`CommitReceipt`]
//! is issued. If violated, evaluation fails closed with zero fiscal leakage ($B_{t+1} = B_t$).
//! If downstream actuation aborts, [`FiscalLedger::rollback_reservation`] restores fuel LIFO.

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Epsilon tolerance for floating-point barrier comparisons.
pub const CBF_EPSILON: f64 = 1e-9;

/// Specific violation reason when a Control Barrier Function inequality fails.
#[derive(Debug, Clone, PartialEq, thiserror::Error, Serialize, Deserialize)]
pub enum CbfViolation {
    #[error(
        "Budget below minimum safety floor: projected {projected_budget:.4} < floor {b_min:.4}"
    )]
    FloorBreach { projected_budget: f64, b_min: f64 },

    #[error("Barrier decay rate exceeded: projected h {h_next:.4} < required {h_min_allowed:.4} (gamma={gamma:.4})")]
    DecayRateExceeded {
        h_next: f64,
        h_min_allowed: f64,
        gamma: f64,
    },

    #[error(
        "Current state already in violation: current budget {current_budget:.4} < floor {b_min:.4}"
    )]
    CurrentStateUnsafe { current_budget: f64, b_min: f64 },

    #[error("Invalid parameters: {0}")]
    InvalidParameters(String),

    #[error("Debit reservation not found or already released: {0}")]
    ReservationNotFound(String),

    #[error("Reservation already committed and cannot be rolled back: {0}")]
    AlreadyCommitted(String),
}

/// Cryptographic and accounting receipt issued when fuel cost is safely debited.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CommitReceipt {
    /// Unique identifier of the debit transaction.
    pub debit_id: String,

    /// Fuel quantity reserved for the actuation.
    pub reserved_fuel: f64,

    /// Remaining available budget post-reservation ($B_{t+1}$).
    pub remaining_budget: f64,

    /// Projected safety barrier value post-reservation ($h_{t+1}$).
    pub barrier_val: f64,

    /// Issuance timestamp in Unix epoch seconds.
    pub timestamp: u64,
}

/// Pure mathematical discrete-time Control Barrier Function evaluator.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ControlBarrierFunction {
    /// Maximum fractional safety margin decay rate per step ($\gamma \in (0, 1]$).
    pub gamma: f64,

    /// Invariant safety floor threshold ($B_{\min}$).
    pub b_min: f64,
}

impl Default for ControlBarrierFunction {
    fn default() -> Self {
        Self {
            gamma: 0.1,
            b_min: 10.0,
        }
    }
}

impl ControlBarrierFunction {
    /// Creates a new CBF validator with specified decay rate $\gamma$ and floor $B_{\min}$.
    pub fn new(gamma: f64, b_min: f64) -> Result<Self, CbfViolation> {
        if gamma <= 0.0 || gamma > 1.0 {
            return Err(CbfViolation::InvalidParameters(format!(
                "Decay rate gamma must be in (0, 1], got {}",
                gamma
            )));
        }
        if b_min < 0.0 {
            return Err(CbfViolation::InvalidParameters(format!(
                "Minimum reserve floor b_min must be non-negative, got {}",
                b_min
            )));
        }
        Ok(Self { gamma, b_min })
    }

    /// Evaluates the discrete-time exponential barrier condition:
    ///
    /// $$h_{t+1} = (B_t - c) - B_{\min} \ge (1 - \gamma) h_t \ge 0$$
    ///
    /// Returns $h_{t+1}$ on success or [`CbfViolation`] on failure.
    pub fn evaluate_step(
        &self,
        current_budget: f64,
        cost: f64,
        current_h: f64,
    ) -> Result<f64, CbfViolation> {
        if cost < 0.0 {
            return Err(CbfViolation::InvalidParameters(format!(
                "Cost cannot be negative: {}",
                cost
            )));
        }

        // Current safety margin check
        if current_h < -CBF_EPSILON {
            return Err(CbfViolation::CurrentStateUnsafe {
                current_budget,
                b_min: self.b_min,
            });
        }

        let projected_budget = current_budget - cost;
        let h_next = projected_budget - self.b_min;

        // Condition 1: Non-negativity floor h_{t+1} >= 0
        if h_next < -CBF_EPSILON {
            return Err(CbfViolation::FloorBreach {
                projected_budget,
                b_min: self.b_min,
            });
        }

        // Condition 2: Monotonic decay bound h_{t+1} >= (1 - gamma) * h_t
        let h_min_allowed = (1.0 - self.gamma) * current_h;
        if h_next + CBF_EPSILON < h_min_allowed {
            return Err(CbfViolation::DecayRateExceeded {
                h_next,
                h_min_allowed,
                gamma: self.gamma,
            });
        }

        Ok(h_next)
    }

    /// Full step evaluation computing $h_t$ from $B_t$ and returning $(B_{t+1}, h_{t+1})$.
    pub fn evaluate(&self, current_budget: f64, cost: f64) -> Result<(f64, f64), CbfViolation> {
        let current_h = current_budget - self.b_min;
        let h_next = self.evaluate_step(current_budget, cost, current_h)?;
        let projected_budget = current_budget - cost;
        Ok((projected_budget, h_next))
    }
}

/// Internal tracked reservation entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ReservationEntry {
    debit_id: String,
    amount: f64,
    timestamp: u64,
    committed: bool,
    rolled_back: bool,
}

/// State container for the fiscal ledger.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct LedgerState {
    available_budget: f64,
    initial_budget: f64,
    reservations: Vec<ReservationEntry>,
}

/// Thread-safe fiscal ledger governing resource pre-reservation and LIFO rollback.
pub struct FiscalLedger {
    cbf: ControlBarrierFunction,
    state: RwLock<LedgerState>,
    sequence: AtomicU64,
}

impl FiscalLedger {
    /// Creates a new fiscal ledger initialized with a starting budget and CBF parameters.
    pub fn new(initial_budget: f64, gamma: f64, b_min: f64) -> Result<Self, CbfViolation> {
        let cbf = ControlBarrierFunction::new(gamma, b_min)?;
        if initial_budget < b_min {
            return Err(CbfViolation::CurrentStateUnsafe {
                current_budget: initial_budget,
                b_min,
            });
        }

        Ok(Self {
            cbf,
            state: RwLock::new(LedgerState {
                available_budget: initial_budget,
                initial_budget,
                reservations: Vec::new(),
            }),
            sequence: AtomicU64::new(1),
        })
    }

    /// Creates a new fiscal ledger using default CBF parameters ($\gamma = 0.1, B_{\min} = 10.0$).
    pub fn with_default_cbf(initial_budget: f64) -> Result<Self, CbfViolation> {
        Self::new(initial_budget, 0.1, 10.0)
    }

    /// Returns the current available budget balance.
    pub fn available_budget(&self) -> f64 {
        self.state.read().available_budget
    }

    /// Returns the current barrier safety margin $h_t = B_t - B_{\min}$.
    pub fn barrier_margin(&self) -> f64 {
        let b = self.available_budget();
        b - self.cbf.b_min
    }

    /// Returns the minimum reserve floor $B_{\min}$.
    pub fn floor_threshold(&self) -> f64 {
        self.cbf.b_min
    }

    /// Returns the decay rate $\gamma$.
    pub fn gamma(&self) -> f64 {
        self.cbf.gamma
    }

    /// Atomically evaluates the CBF barrier inequality and pre-reserves fuel cost $c$.
    ///
    /// If the inequality holds:
    /// - Deducts $c$ from available budget
    /// - Records the pending reservation
    /// - Returns a [`CommitReceipt`]
    ///
    /// If the inequality fails:
    /// - Leaves budget untouched (zero fiscal leakage: $B_{t+1} = B_t$)
    /// - Returns [`CbfViolation`]
    pub fn pre_reserve(&self, cost: f64, debit_id: &str) -> Result<CommitReceipt, CbfViolation> {
        let mut state = self.state.write();
        let current_budget = state.available_budget;
        let current_h = current_budget - self.cbf.b_min;

        // Evaluate discrete-time exponential barrier
        let h_next = self.cbf.evaluate_step(current_budget, cost, current_h)?;

        // Deduct cost and advance state
        let remaining_budget = current_budget - cost;
        state.available_budget = remaining_budget;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        state.reservations.push(ReservationEntry {
            debit_id: debit_id.to_string(),
            amount: cost,
            timestamp: now,
            committed: false,
            rolled_back: false,
        });

        self.sequence.fetch_add(1, Ordering::Relaxed);

        Ok(CommitReceipt {
            debit_id: debit_id.to_string(),
            reserved_fuel: cost,
            remaining_budget,
            barrier_val: h_next,
            timestamp: now,
        })
    }

    /// Commits an existing reservation permanently, preventing future rollbacks.
    pub fn commit(&self, debit_id: &str) -> Result<(), CbfViolation> {
        let mut state = self.state.write();
        for entry in state.reservations.iter_mut().rev() {
            if entry.debit_id == debit_id {
                if entry.rolled_back {
                    return Err(CbfViolation::ReservationNotFound(format!(
                        "Reservation {} was already rolled back",
                        debit_id
                    )));
                }
                entry.committed = true;
                return Ok(());
            }
        }
        Err(CbfViolation::ReservationNotFound(debit_id.to_string()))
    }

    /// Rolls back a specific reservation by debit ID, restoring fuel back to the available budget.
    pub fn rollback_reservation(&self, debit_id: &str) -> Result<f64, CbfViolation> {
        let mut state = self.state.write();
        let mut found_amount = None;
        for entry in state.reservations.iter_mut().rev() {
            if entry.debit_id == debit_id {
                if entry.committed {
                    return Err(CbfViolation::AlreadyCommitted(debit_id.to_string()));
                }
                if entry.rolled_back {
                    return Err(CbfViolation::ReservationNotFound(format!(
                        "Reservation {} was already rolled back",
                        debit_id
                    )));
                }

                entry.rolled_back = true;
                found_amount = Some(entry.amount);
                break;
            }
        }
        if let Some(amount) = found_amount {
            state.available_budget += amount;
            Ok(state.available_budget)
        } else {
            Err(CbfViolation::ReservationNotFound(debit_id.to_string()))
        }
    }

    /// Rolls back the most recent pending reservation in LIFO order.
    pub fn rollback_lifo(&self) -> Result<(String, f64), CbfViolation> {
        let mut state = self.state.write();
        let mut found = None;
        for entry in state.reservations.iter_mut().rev() {
            if !entry.committed && !entry.rolled_back {
                entry.rolled_back = true;
                found = Some((entry.debit_id.clone(), entry.amount));
                break;
            }
        }
        if let Some((debit_id, amount)) = found {
            state.available_budget += amount;
            Ok((debit_id, state.available_budget))
        } else {
            Err(CbfViolation::ReservationNotFound(
                "No uncommitted reservations available to rollback".to_string(),
            ))
        }
    }

    /// Returns the number of currently active pending reservations.
    pub fn active_reservation_count(&self) -> usize {
        let state = self.state.read();
        state
            .reservations
            .iter()
            .filter(|r| !r.committed && !r.rolled_back)
            .count()
    }
}
