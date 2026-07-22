#[cfg(target_os = "zkvm")]
use core::arch::asm;

pub const KECCAK_PERMUTE: u32 = 0x00_01_01_09;
pub const KECCAK_XORIN: u32 = 0x00_01_01_30;
pub const SECP256K1_ADD: u32 = 0x00_01_01_0A;
pub const SECP256K1_DOUBLE: u32 = 0x00_00_01_0B;
pub const SECP256K1_DECOMPRESS: u32 = 0x00_00_01_0C;
pub const SECP256K1_SCALAR_SQRT: u32 = 0x00_00_01_0D;
pub const SECP256K1_SCALAR_INVERT: u32 = 0x00_00_01_0E;
pub const SHA_EXTEND: u32 = 0x00_30_01_05;
pub const BN254_ADD: u32 = 0x00_01_01_0E;
pub const BN254_DOUBLE: u32 = 0x00_00_01_0F;
pub const BN254_FP_ADD: u32 = 0x00_01_01_26;
pub const BN254_FP_MUL: u32 = 0x00_01_01_28;
pub const BN254_FP2_ADD: u32 = 0x00_01_01_29;
pub const BN254_FP2_MUL: u32 = 0x00_01_01_2B;
pub const BLS12381_DECOMPRESS: u32 = 0x00_00_01_1C;
pub const BLS12381_ADD: u32 = 0x00_01_01_1E;
pub const BLS12381_DOUBLE: u32 = 0x00_00_01_1F;
pub const BLS12381_FP_ADD: u32 = 0x00_01_01_20;
pub const BLS12381_FP_SUB: u32 = 0x00_01_01_21;
pub const BLS12381_FP_MUL: u32 = 0x00_01_01_22;
pub const BLS12381_FP2_ADD: u32 = 0x00_01_01_23;
pub const BLS12381_FP2_SUB: u32 = 0x00_01_01_24;
pub const BLS12381_FP2_MUL: u32 = 0x00_01_01_25;
pub const SECP256R1_ADD: u32 = 0x00_01_01_2C;
pub const SECP256R1_DOUBLE: u32 = 0x00_00_01_2D;
pub const SECP256R1_DECOMPRESS: u32 = 0x00_00_01_2E;
pub const SECP256R1_SCALAR_INVERT: u32 = 0x00_00_01_2F;
pub const UINT256_MUL: u32 = 0x00_01_01_1D;

pub const PHANTOM_LOG_PC_CYCLE: u32 = 0x00_00_00_03;
pub const PHANTOM_LOG_PRINT: u32 = 0x00_00_00_04;

pub const PUB_IO_COMMIT: u32 = 0x00_00_00_10;
pub const STATE_CONTINUATION: u32 = 0x00_00_00_11;

pub const KECCAK_STATE_WORDS: usize = 25;
pub const KECCAK_RATE_WORDS: usize = 34;

/// Based on https://github.com/succinctlabs/sp1/blob/013c24ea2fa15a0e7ed94f7d11a7ada4baa39ab9/crates/zkvm/entrypoint/src/syscalls/keccak_permute.rs
/// Executes the Keccak256 permutation on the given state.
///
/// ### Spec
///
/// - The caller must ensure that `state` is valid pointer to data that is aligned along a four
///   byte boundary.
#[allow(unused_variables)]
pub fn syscall_keccak_permute(state: &mut [u64; KECCAK_STATE_WORDS]) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
        "ecall",
        in("t0") KECCAK_PERMUTE,
        in("a0") state as *mut [u64; 25],
        );
    }
    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}

/// XORs one zero-padded Keccak rate block into the first 136 bytes of `state`.
///
/// ### Spec
///
/// - `state` and `block` must be aligned to a four-byte boundary.
/// - `state` and `block` must not overlap.
/// - The entire fixed-width block is consumed, including zero padding.
#[allow(unused_variables)]
pub fn syscall_keccak_xorin(
    state: &mut [u64; KECCAK_STATE_WORDS],
    block: &[u32; KECCAK_RATE_WORDS],
) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
            "ecall",
            in("t0") KECCAK_XORIN,
            in("a0") state.as_mut_ptr(),
            in("a1") block.as_ptr(),
        );
    }
    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}

/// Based on https://github.com/succinctlabs/sp1/blob/dbe622aa4a6a33c88d76298c2a29a1d7ef7e90df/crates/zkvm/entrypoint/src/syscalls/secp256k1.rs
/// Adds two Secp256k1 points.
///
/// ### Spec
/// - The caller must ensure that `p` and `q` are valid pointers to data that is aligned along a four
///   byte boundary.
/// - Point representation: the first `8` words describe the X-coordinate, the last `8` describe the Y-coordinate. Each
///   coordinate is encoded as follows: its `32` bytes are ordered from lowest significance to highest and then stored into little endian words.
///   For example, the word `p[0]` contains the least significant `4` bytes of `X` and their significance is maintained w.r.t `p[0]`
/// - The caller must ensure that `p` and `q` are valid points on the `secp256k1` curve, and that `p` and `q` are not equal to each other.
/// - The result is stored in the first point.
#[allow(unused_variables)]
pub fn syscall_secp256k1_add(p: &mut [u32; 16], q: &[u32; 16]) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        let p = p.as_mut_ptr();
        let q = q.as_ptr();
        asm!(
        "ecall",
        in("t0") SECP256K1_ADD,
        in("a0") p,
        in("a1") q
        );
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}

/// Based on: https://github.com/succinctlabs/sp1/blob/dbe622aa4a6a33c88d76298c2a29a1d7ef7e90df/crates/zkvm/entrypoint/src/syscalls/secp256k1.rs
/// Double a Secp256k1 point.
///
/// ### Spec
/// - The caller must ensure that `p` is a valid pointer to data that is aligned along a four byte boundary.
/// - Point representation: the first `8` words describe the X-coordinate, the last `8` describe the Y-coordinate. Each
///   coordinate is encoded as follows: its `32` bytes are ordered from lowest significance to highest and then stored into little endian words.
///   For example, the word `p[0]` contains the least significant `4` bytes of `X` and their significance is maintained w.r.t `p[0]`
/// - The result is stored in p
#[allow(unused_variables)]
pub fn syscall_secp256k1_double(p: &mut [u32; 16]) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        let p = p.as_mut_ptr();
        asm!(
        "ecall",
        in("t0") SECP256K1_DOUBLE,
        in("a0") p
        );
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}

/// Decompresses a compressed Secp256k1 point.
///
/// ### Spec
/// - The input array should be 64 bytes long, with the first 32 bytes containing the X coordinate in
///   big-endian format. Note that this byte ordering is different than the one implied in the spec
///   of the `add` and `double` operations
/// - The second half of the input will be overwritten with the Y coordinate of the
///   decompressed point in big-endian format using the point's parity (is_odd).
/// - The caller must ensure that `point` is valid pointer to data that is aligned along a four byte
///   boundary.
#[allow(unused_variables)]
pub fn syscall_secp256k1_decompress(point: &mut [u8; 64], is_odd: bool) {
    #[cfg(target_os = "zkvm")]
    {
        let p = point.as_mut_ptr();
        unsafe {
            asm!(
            "ecall",
            in("t0") SECP256K1_DECOMPRESS,
            in("a0") p,
            in("a1") is_odd as u8
            );
        }
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}

#[allow(unused_variables)]
pub fn syscall_secp256k1_invert(p: &mut [u32; 8]) {
    #[cfg(target_os = "zkvm")]
    {
        let p = p.as_mut_ptr();
        unsafe {
            asm!(
            "ecall",
            in("t0") SECP256K1_SCALAR_INVERT,
            in("a0") p
            );
        }
    }
}

/// Refer syscall_secp256k1_add
///
/// ### Spec
/// - The caller must ensure that `p` and `q` are valid pointers to data that is aligned along a four
///   byte boundary.
/// - Point representation: the first `8` words describe the X-coordinate, the last `8` describe the Y-coordinate. Each
///   coordinate is encoded as follows: its `32` bytes are ordered from lowest significance to highest and then stored into little endian words.
///   For example, the word `p[0]` contains the least significant `4` bytes of `X` and their significance is maintained w.r.t `p[0]`
/// - The caller must ensure that `p` and `q` are valid points on the `secp256r1` curve, and that `p` and `q` are not equal to each other.
/// - The result is stored in the first point.
#[allow(unused_variables)]
pub fn syscall_secp256r1_add(p: &mut [u32; 16], q: &[u32; 16]) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        let p = p.as_mut_ptr();
        let q = q.as_ptr();
        asm!(
        "ecall",
        in("t0") SECP256R1_ADD,
        in("a0") p,
        in("a1") q
        );
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}

/// Follow syscall_secp256k1_double
/// ### Spec
/// - The caller must ensure that `p` is a valid pointer to data that is aligned along a four byte boundary.
/// - Point representation: the first `8` words describe the X-coordinate, the last `8` describe the Y-coordinate. Each
///   coordinate is encoded as follows: its `32` bytes are ordered from lowest significance to highest and then stored into little endian words.
///   For example, the word `p[0]` contains the least significant `4` bytes of `X` and their significance is maintained w.r.t `p[0]`
/// - The result is stored in p
#[allow(unused_variables)]
pub fn syscall_secp256r1_double(p: &mut [u32; 16]) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        let p = p.as_mut_ptr();
        asm!(
        "ecall",
        in("t0") SECP256R1_DOUBLE,
        in("a0") p
        );
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}

#[allow(unused_variables)]
pub fn syscall_secp256r1_invert(p: &mut [u32; 8]) {
    #[cfg(target_os = "zkvm")]
    {
        let p = p.as_mut_ptr();
        unsafe {
            asm!(
            "ecall",
            in("t0") SECP256R1_SCALAR_INVERT,
            in("a0") p
            );
        }
    }
}

/// Executes one SHA256 extend round in place.
#[allow(unused_variables)]
pub fn syscall_sha256_extend(w_i: &mut u32) {
    #[cfg(target_os = "zkvm")]
    {
        let w_i = w_i as *mut u32;
        unsafe {
            asm!(
            "ecall",
            in("t0") SHA_EXTEND,
            in("a0") w_i,
            );
        }
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}

/// Adds two Bn254 points.
///
/// The result is stored in the first point.
///
/// ### Safety
///
/// The caller must ensure that `p` and `q` are valid pointers to data that is aligned along a four
/// byte boundary.
#[allow(unused_variables)]
#[unsafe(no_mangle)]
pub extern "C" fn syscall_bn254_add(p: &mut [u32; 16], q: &[u32; 16]) {
    #[cfg(target_os = "zkvm")]
    {
        let p = p.as_mut_ptr();
        let q = q.as_ptr();
        unsafe {
            asm!(
            "ecall",
            in("t0") BN254_ADD,
            in("a0") p,
            in("a1") q,
            );
        }
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}

/// Double a Bn254 point.
///
/// The result is stored in the first point.
///
/// ### Safety
///
/// The caller must ensure that `p` is valid pointer to data that is aligned along a four byte
/// boundary.
#[allow(unused_variables)]
#[unsafe(no_mangle)]
pub extern "C" fn syscall_bn254_double(p: &mut [u32; 16]) {
    #[cfg(target_os = "zkvm")]
    {
        let p = p.as_mut_ptr();
        unsafe {
            asm!(
            "ecall",
            in("t0") BN254_DOUBLE,
            in("a0") p,
            in("a1") 0,
            );
        }
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}

/// Fp addition operation.
///
/// The result is written over the first input.
#[allow(unused_variables)]
#[unsafe(no_mangle)]
pub extern "C" fn syscall_bn254_fp_addmod(x: &mut [u32; 8], y: &[u32; 8]) {
    #[cfg(target_os = "zkvm")]
    {
        let x = x.as_mut_ptr();
        let y = y.as_ptr();
        unsafe {
            asm!(
            "ecall",
            in("t0") BN254_FP_ADD,
            in("a0") x,
            in("a1") y,
            );
        }
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}

/// Fp multiplication operation.
///
/// The result is written over the first input.
#[allow(unused_variables)]
#[unsafe(no_mangle)]
pub extern "C" fn syscall_bn254_fp_mulmod(x: &mut [u32; 8], y: &[u32; 8]) {
    #[cfg(target_os = "zkvm")]
    {
        let x = x.as_mut_ptr();
        let y = y.as_ptr();
        unsafe {
            asm!(
            "ecall",
            in("t0") BN254_FP_MUL,
            in("a0") x,
            in("a1") y,
            );
        }
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}

/// BN254 Fp2 addition operation.
///
/// The result is written over the first input.
#[allow(unused_variables)]
#[unsafe(no_mangle)]
pub extern "C" fn syscall_bn254_fp2_addmod(x: &mut [u32; 16], y: &[u32; 16]) {
    #[cfg(target_os = "zkvm")]
    {
        let x = x.as_mut_ptr();
        let y = y.as_ptr();
        unsafe {
            asm!(
            "ecall",
            in("t0") BN254_FP2_ADD,
            in("a0") x,
            in("a1") y,
            );
        }
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}

/// BN254 Fp2 multiplication operation.
///
/// The result is written over the first input.
#[allow(unused_variables)]
#[unsafe(no_mangle)]
pub extern "C" fn syscall_bn254_fp2_mulmod(x: &mut [u32; 16], y: &[u32; 16]) {
    #[cfg(target_os = "zkvm")]
    {
        let x = x.as_mut_ptr();
        let y = y.as_ptr();
        unsafe {
            asm!(
            "ecall",
            in("t0") BN254_FP2_MUL,
            in("a0") x,
            in("a1") y,
            );
        }
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}

/// Adds two BLS12-381 G1 points in canonical little-endian word representation.
///
/// The result is written over the first input.
#[allow(unused_variables)]
#[unsafe(no_mangle)]
pub extern "C" fn syscall_bls12381_add(p: &mut [u32; 24], q: &[u32; 24]) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
            "ecall",
            in("t0") BLS12381_ADD,
            in("a0") p.as_mut_ptr(),
            in("a1") q.as_ptr(),
        );
    }
    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}

/// Doubles a BLS12-381 G1 point in canonical little-endian word representation.
#[allow(unused_variables)]
#[unsafe(no_mangle)]
pub extern "C" fn syscall_bls12381_double(p: &mut [u32; 24]) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
            "ecall",
            in("t0") BLS12381_DOUBLE,
            in("a0") p.as_mut_ptr(),
            in("a1") 0,
        );
    }
    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}

/// Decompresses a BLS12-381 G1 x-coordinate in canonical little-endian word
/// representation and writes the y-coordinate into the second half.
#[allow(unused_variables)]
#[unsafe(no_mangle)]
pub extern "C" fn syscall_bls12381_decompress(point: &mut [u32; 24], sign: bool) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
            "ecall",
            in("t0") BLS12381_DECOMPRESS,
            in("a0") point.as_mut_ptr(),
            in("a1") sign as u8,
        );
    }
    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}

macro_rules! bls12381_binary_syscall {
    ($name:ident, $code:ident, $words:expr) => {
        #[allow(unused_variables)]
        #[unsafe(no_mangle)]
        pub extern "C" fn $name(x: &mut [u32; $words], y: &[u32; $words]) {
            #[cfg(target_os = "zkvm")]
            unsafe {
                asm!(
                    "ecall",
                    in("t0") $code,
                    in("a0") x.as_mut_ptr(),
                    in("a1") y.as_ptr(),
                );
            }
            #[cfg(not(target_os = "zkvm"))]
            unreachable!()
        }
    };
}

bls12381_binary_syscall!(syscall_bls12381_fp_addmod, BLS12381_FP_ADD, 12);
bls12381_binary_syscall!(syscall_bls12381_fp_submod, BLS12381_FP_SUB, 12);
bls12381_binary_syscall!(syscall_bls12381_fp_mulmod, BLS12381_FP_MUL, 12);
bls12381_binary_syscall!(syscall_bls12381_fp2_addmod, BLS12381_FP2_ADD, 24);
bls12381_binary_syscall!(syscall_bls12381_fp2_submod, BLS12381_FP2_SUB, 24);
bls12381_binary_syscall!(syscall_bls12381_fp2_mulmod, BLS12381_FP2_MUL, 24);

/// Uint256 multiplication operation.
///
/// The result is written over the first input.
#[allow(unused_variables)]
#[unsafe(no_mangle)]
pub extern "C" fn syscall_uint256_mul(x: &mut [u32; 8], y_and_modulus: &[u32; 16]) {
    #[cfg(target_os = "zkvm")]
    {
        let x = x.as_mut_ptr();
        let y = y_and_modulus.as_ptr();
        unsafe {
            asm!(
            "ecall",
            in("t0") UINT256_MUL,
            in("a0") x,
            in("a1") y,
            );
        }
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}

/// phantom syscall
pub fn syscall_phantom_log_pc_cycle(label: &str) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        let ptr = label.as_ptr();
        let len = label.len();

        asm!(
        "ecall",
        in("t0") PHANTOM_LOG_PC_CYCLE,
        in("a0") ptr,
        in("a1") len,
        );
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!("syscall_log_pc_cycle should only run inside zkvm");
}

/// Prints a formatted log line inside the phantom host.
pub fn syscall_phantom_log_print(message: &str) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        let ptr = message.as_ptr();
        let len = message.len();

        asm!(
        "ecall",
        in("t0") PHANTOM_LOG_PRINT,
        in("a0") ptr,
        in("a1") len,
        );
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!("syscall_phantom_log_print should only run inside zkvm");
}

/// Commit a 256-bit value to the public IO channel.
#[allow(unused_variables)]
pub fn syscall_pub_io_commit(value: &[u32; 8]) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        let ptr = value.as_ptr();

        asm!(
        "ecall",
        in("t0") PUB_IO_COMMIT,
        in("a0") ptr,
        );
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!("syscall_pub_io_commit should only run inside zkvm");
}

/// Advances the VM state to the continuation point for the next execution phase.
pub fn syscall_state_continuation() {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
        "ecall",
        in("t0") STATE_CONTINUATION,
        );
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!("syscall_state_continuation should only run inside zkvm");
}
