use clar2wasm::tools::crosscheck_compare_only;
use proptest::proptest;

use crate::{int, uint};

proptest! {
    #![proptest_config(super::runtime_config())]
    #[test]
    fn crossprop_bit_shift_left(val in int(), shamt in uint()) {
        crosscheck_compare_only(
            &format!("(bit-shift-left {val} {shamt})"),
        )
    }
}
