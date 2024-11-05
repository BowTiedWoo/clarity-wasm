#[cfg(not(feature = "test-clarity-v1"))]
#[cfg(test)]
mod clarity_v2_v3 {
    use clar2wasm::tools::crosscheck_compare_only;
    use proptest::proptest;

    use crate::{int, runtime_config, uint};

    const ONE_OP: [&str; 1] = ["bit-not"];
    const TWO_OPS: [&str; 2] = ["bit-shift-left", "bit-shift-right"];
    const MULTI_OPS: [&str; 3] = ["bit-and", "bit-or", "bit-xor"];

    proptest! {
        #![proptest_config(runtime_config())]

        #[test]
        fn crossprop_bitwise_one_op_int(val in int()) {
            for op in &ONE_OP {
                crosscheck_compare_only(
                    &format!("({op} {val})")
                )
            }
        }
    }

    proptest! {
        #![proptest_config(runtime_config())]

        #[test]
        fn crossprop_bitwise_one_op_uint(val in uint()) {
            for op in &ONE_OP {
                crosscheck_compare_only(
                    &format!("({op} {val})")
                )
            }
        }
    }

    proptest! {
        #![proptest_config(runtime_config())]

        #[test]
        fn crossprop_bitwise_two_ops(val1 in int(), val2 in uint()) {
            for op in &TWO_OPS {
                crosscheck_compare_only(
                    &format!("({op} {val1} {val2})")
                )
            }
        }
    }

    proptest! {
        #![proptest_config(runtime_config())]

        #[test]
        fn crossprop_bitwise_two_ops_uint(val1 in uint(), val2 in uint()) {
            for op in &TWO_OPS {
                crosscheck_compare_only(
                    &format!("({op} {val1} {val2})")
                )
            }
        }
    }

    proptest! {
        #![proptest_config(runtime_config())]

        #[test]
        fn crossprop_bitwise_multi_ops_int(values in proptest::collection::vec(int(), 1..=10)) {
            for op in &MULTI_OPS {
                let values_str = values.iter().map(|v| v.to_string()).collect::<Vec<_>>().join(" ");
                crosscheck_compare_only(
                    &format!("({op} {values_str})")
                )
            }
        }
    }

    proptest! {
        #![proptest_config(runtime_config())]

        #[test]
        fn crossprop_bitwise_multi_ops_uint(values in proptest::collection::vec(uint(), 1..=10)) {
            for op in &MULTI_OPS {
                let values_str = values.iter().map(|v| v.to_string()).collect::<Vec<_>>().join(" ");
                crosscheck_compare_only(
                    &format!("({op} {values_str})")
                )
            }
        }
    }

    proptest! {
        #![proptest_config(runtime_config())]

        #[test]
        fn crossprop_xor_int(val1 in int(), val2 in int()) {
            crosscheck_compare_only(
                &format!("(xor {val1} {val2})")
            )
        }
    }

    proptest! {
        #![proptest_config(runtime_config())]

        #[test]
        fn crossprop_xor_uint(val1 in uint(), val2 in uint()) {
            crosscheck_compare_only(
                &format!("(xor {val1} {val2})")
            )
        }
    }
}
