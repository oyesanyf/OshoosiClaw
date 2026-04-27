use rand_distr::{Laplace, Distribution};
use rand::thread_rng;

fn main() {
    let laplace = Laplace::new(0.0, 1.0).unwrap();
    let val = laplace.sample(&mut thread_rng());
    println!("Val: {}", val);
}
