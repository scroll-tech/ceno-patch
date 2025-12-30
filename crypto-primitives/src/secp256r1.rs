//! Copied from <https://github.com/succinctlabs/sp1/blob/ebb517c1a3f3e3b95ee34bf211fb46a73cf108fe/crates/zkvm/lib/src/secp256r1.rs>

use crate::utils::{AffinePoint, WeierstrassAffinePoint, WeierstrassPoint};
use ceno_syscall::{syscall_secp256r1_add, syscall_secp256r1_double};

/// The number of limbs in [CenoSecp256r1Point].
pub const N: usize = 16;

/// An affine point on the Secp256r1 curve.
#[derive(Copy, Clone, Debug)]
#[repr(align(4))]
pub struct CenoSecp256r1Point(pub WeierstrassPoint<N>);

impl WeierstrassAffinePoint<N> for CenoSecp256r1Point {
    fn infinity() -> Self {
        Self(WeierstrassPoint::Infinity)
    }

    fn is_infinity(&self) -> bool {
        matches!(self.0, WeierstrassPoint::Infinity)
    }
}

impl AffinePoint<N> for CenoSecp256r1Point {
    /// The values are taken from https://en.bitcoin.it/wiki/Secp256r1.
    const GENERATOR: Self = Self(WeierstrassPoint::Affine([
        3633889942, 4104206661, 770388896, 1996717441, 1671708914, 4173129445, 3777774151,
        1796723186, 935285237, 3417718888, 1798397646, 734933847, 2081398294, 2397563722,
        4263149467, 1340293858,
    ]));

    fn new(limbs: [u32; N]) -> Self {
        Self(WeierstrassPoint::Affine(limbs))
    }

    fn identity() -> Self {
        Self::infinity()
    }

    fn inner(&self) -> &WeierstrassPoint<N> {
        &self.0
    }

    fn inner_mut(&mut self) -> &mut WeierstrassPoint<N> {
        &mut self.0
    }

    fn is_identity(&self) -> bool {
        self.is_infinity()
    }

    fn add_assign(&mut self, other: &Self) {
        let a = self.limbs_mut();
        let b = other.limbs_ref();
        syscall_secp256r1_add(a, b);
    }

    fn complete_add_assign(&mut self, other: &Self) {
        self.weierstrass_add_assign(other);
    }

    fn double(&mut self) {
        match &mut self.0 {
            WeierstrassPoint::Infinity => (),
            WeierstrassPoint::Affine(limbs) => syscall_secp256r1_double(limbs),
        }
    }
}
