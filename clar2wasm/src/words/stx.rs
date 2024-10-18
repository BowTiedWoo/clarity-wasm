use clarity::vm::types::TypeSignature;
use clarity::vm::{ClarityName, SymbolicExpression};

use super::{ComplexWord, SimpleWord};
use crate::error_mapping::ErrorMap;
use crate::wasm_generator::{ArgumentsExt, GeneratorError, WasmGenerator};
use crate::wasm_utils::get_global;

#[derive(Debug)]
pub struct StxBurn;

impl SimpleWord for StxBurn {
    fn name(&self) -> ClarityName {
        "stx-burn?".into()
    }

    fn visit(
        &self,
        generator: &mut WasmGenerator,
        builder: &mut walrus::InstrSeqBuilder,
        _arg_types: &[TypeSignature],
        _return_type: &TypeSignature,
    ) -> Result<(), GeneratorError> {
        // Amount and sender are on the stack, so just call the host interface
        // function, `stx_burn`
        builder.call(generator.func_by_name("stdlib.stx_burn"));

        Ok(())
    }
}

#[derive(Debug)]
pub struct StxGetBalance;

impl SimpleWord for StxGetBalance {
    fn name(&self) -> ClarityName {
        "stx-get-balance".into()
    }

    fn visit(
        &self,
        generator: &mut WasmGenerator,
        builder: &mut walrus::InstrSeqBuilder,
        _arg_types: &[TypeSignature],
        _return_type: &TypeSignature,
    ) -> Result<(), GeneratorError> {
        builder.call(generator.func_by_name("stdlib.stx_get_balance"));
        Ok(())
    }
}

#[derive(Debug)]
pub struct StxTransfer;

impl ComplexWord for StxTransfer {
    fn name(&self) -> ClarityName {
        "stx-transfer?".into()
    }

    fn traverse(
        &self,
        generator: &mut WasmGenerator,
        builder: &mut walrus::InstrSeqBuilder,
        _expr: &SymbolicExpression,
        args: &[SymbolicExpression],
    ) -> Result<(), GeneratorError> {
        if args.len() != 3 {
            let (arg_name_offset_start, arg_name_len_expected) =
                generator.add_literal(&clarity::vm::Value::UInt(3))?;
            let (_, arg_name_len_got) =
                generator.add_literal(&clarity::vm::Value::UInt(args.len() as u128))?;
            builder
                .i32_const(arg_name_offset_start as i32)
                .global_set(get_global(&generator.module, "runtime-error-arg-offset")?)
                .i32_const((arg_name_len_expected + arg_name_len_got) as i32)
                .global_set(get_global(&generator.module, "runtime-error-arg-len")?)
                .i32_const(ErrorMap::ArgumentCountMismatch as i32)
                .call(generator.func_by_name("stdlib.runtime-error"));
        };

        let amount = args.get_expr(0)?;
        let sender = args.get_expr(1)?;
        let recipient = args.get_expr(2)?;

        generator.traverse_expr(builder, amount)?;
        generator.traverse_expr(builder, sender)?;
        generator.traverse_expr(builder, recipient)?;

        // placeholder for memo
        builder.i32_const(0).i32_const(0);
        builder.call(generator.func_by_name("stdlib.stx_transfer"));
        Ok(())
    }
}

#[derive(Debug)]
pub struct StxTransferMemo;

impl ComplexWord for StxTransferMemo {
    fn name(&self) -> ClarityName {
        "stx-transfer-memo?".into()
    }

    fn traverse(
        &self,
        generator: &mut WasmGenerator,
        builder: &mut walrus::InstrSeqBuilder,
        _expr: &SymbolicExpression,
        args: &[SymbolicExpression],
    ) -> Result<(), GeneratorError> {
        if args.len() != 4 {
            let (arg_name_offset_start, arg_name_len_expected) =
                generator.add_literal(&clarity::vm::Value::UInt(4))?;
            let (_, arg_name_len_got) =
                generator.add_literal(&clarity::vm::Value::UInt(args.len() as u128))?;
            builder
                .i32_const(arg_name_offset_start as i32)
                .global_set(get_global(&generator.module, "runtime-error-arg-offset")?)
                .i32_const((arg_name_len_expected + arg_name_len_got) as i32)
                .global_set(get_global(&generator.module, "runtime-error-arg-len")?)
                .i32_const(ErrorMap::ArgumentCountMismatch as i32)
                .call(generator.func_by_name("stdlib.runtime-error"));
        };

        let amount = args.get_expr(0)?;
        let sender = args.get_expr(1)?;
        let recipient = args.get_expr(2)?;
        let memo = args.get_expr(3)?;

        generator.traverse_expr(builder, amount)?;
        generator.traverse_expr(builder, sender)?;
        generator.traverse_expr(builder, recipient)?;
        generator.traverse_expr(builder, memo)?;

        builder.call(generator.func_by_name("stdlib.stx_transfer"));
        Ok(())
    }
}

#[derive(Debug)]
pub struct StxGetAccount;

impl SimpleWord for StxGetAccount {
    fn name(&self) -> ClarityName {
        "stx-account".into()
    }

    fn visit(
        &self,
        generator: &mut WasmGenerator,
        builder: &mut walrus::InstrSeqBuilder,
        _arg_types: &[TypeSignature],
        _return_type: &TypeSignature,
    ) -> Result<(), GeneratorError> {
        builder.call(generator.func_by_name("stdlib.stx_account"));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::tools::{crosscheck, evaluate};

    #[test]
    fn stx_transfer_less_than_three_args() {
        let result = evaluate("(stx-transfer? u100 'S1G2081040G2081040G2081040G208105NK8PE5)");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("expecting 3 arguments, got 2"));
    }

    #[test]
    fn stx_transfer_more_than_three_args() {
        let result = evaluate("(stx-transfer? u100 'S1G2081040G2081040G2081040G208105NK8PE5 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM 0x12345678)");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("expecting 3 arguments, got 4"));
    }

    #[test]
    fn stx_transfer_memo_less_than_four_args() {
        let result = evaluate("(stx-transfer-memo? u100 'S1G2081040G2081040G2081040G208105NK8PE5 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM)");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("expecting 4 arguments, got 3"));
    }

    #[test]
    fn stx_transfer_memo_more_than_four_args() {
        let result = evaluate("(stx-transfer-memo? u100 'S1G2081040G2081040G2081040G208105NK8PE5 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM 0x12345678 0x12345678)");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("expecting 4 arguments, got 5"));
    }

    #[test]
    fn stx_get_balance() {
        crosscheck(
            "
(define-public (test-stx-get-balance)
  (ok (stx-get-balance 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM)))

(test-stx-get-balance)
",
            evaluate("(ok u0)"),
        )
    }

    #[test]
    fn stx_test_burn_ok() {
        crosscheck(
            "(stx-burn? u100 'S1G2081040G2081040G2081040G208105NK8PE5)",
            evaluate("(ok true)"),
        )
    }

    #[test]
    fn stx_test_burn_err_1() {
        // not enough balance
        crosscheck(
            "(stx-burn? u5000000000 'S1G2081040G2081040G2081040G208105NK8PE5)",
            evaluate("(err u1)"),
        )
    }

    #[test]
    fn stx_test_burn_err_3() {
        // non-positive amount
        crosscheck(
            "(stx-burn? u0 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM)",
            evaluate("(err u3)"),
        )
    }

    #[test]
    fn stx_test_burn_err_4() {
        // sender is not tx-sender
        crosscheck(
            "(stx-burn? u100 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM)",
            evaluate("(err u4)"),
        )
    }

    #[test]
    fn stx_transfer_ok() {
        //
        crosscheck(
            "(stx-transfer? u100 'S1G2081040G2081040G2081040G208105NK8PE5 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM)",
            evaluate("(ok true)"),
        )
    }

    #[test]
    fn stx_transfer_err_1() {
        // not enough balance
        crosscheck("(stx-transfer? u5000000000 'S1G2081040G2081040G2081040G208105NK8PE5 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM)", evaluate("(err u1)"))
    }

    #[test]
    fn stx_transfer_err_2() {
        // sender is recipient
        crosscheck(
            "(stx-transfer? u5000000000 tx-sender 'S1G2081040G2081040G2081040G208105NK8PE5)",
            evaluate("(err u2)"),
        )
    }

    #[test]
    fn stx_transfer_err_3() {
        // non-positive amount
        crosscheck(
            "(stx-transfer? u0 tx-sender 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM)",
            evaluate("(err u3)"),
        )
    }

    #[test]
    fn stx_transfer_err_4() {
        // sender is not tx-sender
        crosscheck(
            "(stx-transfer? u100 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM tx-sender)",
            evaluate("(err u4)"),
        )
    }

    //
    // Module with tests that should only be executed
    // when running Clarity::V2 or Clarity::v3.
    //
    #[cfg(not(feature = "test-clarity-v1"))]
    #[cfg(test)]
    mod clarity_v2_v3 {
        use clarity::vm::Value;

        use super::*;
        use crate::tools::crosscheck_validate;

        #[test]
        fn stx_account() {
            crosscheck_validate(
                "(stx-account 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM)",
                |val| match val {
                    Value::Tuple(tuple_data) => {
                        assert_eq!(tuple_data.data_map.len(), 3);
                        assert_eq!(tuple_data.data_map.get("locked").unwrap(), &Value::UInt(0));
                        assert_eq!(
                            tuple_data.data_map.get("unlocked").unwrap(),
                            &Value::UInt(0)
                        );
                        assert_eq!(
                            tuple_data.data_map.get("unlock-height").unwrap(),
                            &Value::UInt(0)
                        );
                    }
                    _ => panic!("Unexpected result received from Wasm function call."),
                },
            )
        }

        #[test]
        fn stx_transfer_memo_ok() {
            //
            crosscheck(
                "(stx-transfer-memo? u100 'S1G2081040G2081040G2081040G208105NK8PE5 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM 0x12345678)",
                evaluate("(ok true)"),
            )
        }
    }
}
