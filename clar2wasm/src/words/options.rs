use clarity::vm::types::TypeSignature;
use clarity::vm::{ClarityName, SymbolicExpression};
use walrus::ir::BinaryOp;

use super::ComplexWord;
use crate::error_mapping::ErrorMap;
use crate::wasm_generator::{drop_value, ArgumentsExt, GeneratorError, WasmGenerator};
use crate::wasm_utils::get_global;

pub fn traverse_optional(
    generator: &mut WasmGenerator,
    builder: &mut walrus::InstrSeqBuilder,
    args: &[SymbolicExpression],
) -> Result<(), GeneratorError> {
    let opt = args.get_expr(0)?;
    generator.traverse_expr(builder, opt)?;
    // there is an optional type on top of the stack.

    // Get the type of the optional expression
    let ty = generator
        .get_expr_type(opt)
        .ok_or_else(|| GeneratorError::TypeError("input expression must be typed".to_owned()))?
        .clone();

    let some_ty = if let TypeSignature::OptionalType(some_type) = &ty {
        &**some_type
    } else {
        return Err(GeneratorError::TypeError(format!(
            "Expected an Optional type. Found {:?}",
            ty
        )));
    };

    // Drop the some type.
    drop_value(builder, some_ty);

    Ok(())
}

#[derive(Debug)]
pub struct IsSome;

impl ComplexWord for IsSome {
    fn name(&self) -> ClarityName {
        "is-some".into()
    }

    fn traverse(
        &self,
        generator: &mut WasmGenerator,
        builder: &mut walrus::InstrSeqBuilder,
        _expr: &SymbolicExpression,
        args: &[SymbolicExpression],
    ) -> Result<(), GeneratorError> {
        if args.len() != 1 {
            let (arg_name_offset_start, arg_name_len_expected) =
                generator.add_literal(&clarity::vm::Value::UInt(1))?;
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

        traverse_optional(generator, builder, args)
    }
}

#[derive(Debug)]
pub struct IsNone;

impl ComplexWord for IsNone {
    fn name(&self) -> ClarityName {
        "is-none".into()
    }

    fn traverse(
        &self,
        generator: &mut WasmGenerator,
        builder: &mut walrus::InstrSeqBuilder,
        _expr: &SymbolicExpression,
        args: &[SymbolicExpression],
    ) -> Result<(), GeneratorError> {
        if args.len() != 1 {
            let (arg_name_offset_start, arg_name_len_expected) =
                generator.add_literal(&clarity::vm::Value::UInt(1))?;
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

        traverse_optional(generator, builder, args)?;

        // Add one to stack
        // and proceed with a XOR operation
        // to invert the indicator value
        builder.i32_const(1).binop(BinaryOp::I32Xor);

        // Xor'ed indicator is on stack.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::tools::evaluate;

    #[test]
    fn test_is_some_no_args() {
        let result = evaluate("(is-some)");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("expecting 1 arguments, got 0"));
    }

    #[test]
    fn test_is_some_more_than_one_arg() {
        let result = evaluate("(is-some x y)");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("expecting 1 arguments, got 2"));
    }

    #[test]
    fn test_is_none_no_args() {
        let result = evaluate("(is-none)");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("expecting 1 arguments, got 0"));
    }

    #[test]
    fn test_is_none_more_than_one_arg() {
        let result = evaluate("(is-none x y)");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("expecting 1 arguments, got 2"));
    }
}
