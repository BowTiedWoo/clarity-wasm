use clarity::vm::types::TypeSignature;
use clarity::vm::{ClarityName, SymbolicExpression};

use super::ComplexWord;
use crate::wasm_generator::{ArgumentsExt, GeneratorError, WasmGenerator};

#[derive(Debug)]
pub struct DefineFungibleToken;

impl ComplexWord for DefineFungibleToken {
    fn name(&self) -> ClarityName {
        "define-fungible-token".into()
    }

    fn traverse(
        &self,
        generator: &mut WasmGenerator,
        builder: &mut walrus::InstrSeqBuilder,
        _expr: &SymbolicExpression,
        args: &[SymbolicExpression],
    ) -> Result<(), GeneratorError> {
        let name = args.get_name(0)?;
        // Making sure if name is not reserved
        if generator.is_reserved_name(name) {
            return Err(GeneratorError::InternalError(format!(
                "Name already used {:?}",
                name
            )));
        }

        let supply = args.get(1);

        // Store the identifier as a string literal in the memory
        let (name_offset, name_length) = generator.add_string_literal(name)?;

        // Push the name onto the data stack
        builder
            .i32_const(name_offset as i32)
            .i32_const(name_length as i32);

        // Push the supply to the stack, as an optional uint
        // (first i32 indicates some/none)
        if let Some(supply) = supply {
            builder.i32_const(1);
            generator.traverse_expr(builder, supply)?;
        } else {
            builder.i32_const(0).i64_const(0).i64_const(0);
        }

        builder.call(generator.func_by_name("stdlib.define_ft"));
        Ok(())
    }
}

#[derive(Debug)]
pub struct BurnFungibleToken;

impl ComplexWord for BurnFungibleToken {
    fn name(&self) -> ClarityName {
        "ft-burn?".into()
    }

    fn traverse(
        &self,
        generator: &mut WasmGenerator,
        builder: &mut walrus::InstrSeqBuilder,
        _expr: &SymbolicExpression,
        args: &[SymbolicExpression],
    ) -> Result<(), GeneratorError> {
        let token = args.get_name(0)?;
        let amount = args.get_expr(1)?;
        let sender = args.get_expr(2)?;

        // Push the token name onto the stack
        let (id_offset, id_length) = generator.add_string_literal(token)?;
        builder
            .i32_const(id_offset as i32)
            .i32_const(id_length as i32);

        // Push the amount and sender onto the stack
        generator.traverse_expr(builder, amount)?;
        generator.traverse_expr(builder, sender)?;

        // Call the host interface function `ft_burn`
        builder.call(generator.func_by_name("stdlib.ft_burn"));

        Ok(())
    }
}

#[derive(Debug)]
pub struct TransferFungibleToken;

impl ComplexWord for TransferFungibleToken {
    fn name(&self) -> ClarityName {
        "ft-transfer?".into()
    }

    fn traverse(
        &self,
        generator: &mut WasmGenerator,
        builder: &mut walrus::InstrSeqBuilder,
        _expr: &SymbolicExpression,
        args: &[SymbolicExpression],
    ) -> Result<(), GeneratorError> {
        let token = args.get_name(0)?;
        let amount = args.get_expr(1)?;
        let sender = args.get_expr(2)?;
        let recipient = args.get_expr(3)?;

        // Push the token name onto the stack
        let (id_offset, id_length) = generator.add_string_literal(token)?;
        builder
            .i32_const(id_offset as i32)
            .i32_const(id_length as i32);

        // Push the amount, sender, and recipient onto the stack
        generator.traverse_expr(builder, amount)?;
        generator.traverse_expr(builder, sender)?;
        generator.traverse_expr(builder, recipient)?;

        // Call the host interface function `ft_transfer`
        builder.call(generator.func_by_name("stdlib.ft_transfer"));

        Ok(())
    }
}

#[derive(Debug)]
pub struct MintFungibleToken;

impl ComplexWord for MintFungibleToken {
    fn name(&self) -> ClarityName {
        "ft-mint?".into()
    }

    fn traverse(
        &self,
        generator: &mut WasmGenerator,
        builder: &mut walrus::InstrSeqBuilder,
        _expr: &SymbolicExpression,
        args: &[SymbolicExpression],
    ) -> Result<(), GeneratorError> {
        let token = args.get_name(0)?;
        let amount = args.get_expr(1)?;
        let recipient = args.get_expr(2)?;

        let (id_offset, id_length) = generator.add_string_literal(token)?;
        builder
            .i32_const(id_offset as i32)
            .i32_const(id_length as i32);

        // Push the amount and recipient onto the stack
        generator.traverse_expr(builder, amount)?;
        generator.traverse_expr(builder, recipient)?;

        // Call the host interface function `ft_mint`
        builder.call(generator.func_by_name("stdlib.ft_mint"));

        Ok(())
    }
}

#[derive(Debug)]
pub struct GetSupplyOfFungibleToken;

impl ComplexWord for GetSupplyOfFungibleToken {
    fn name(&self) -> ClarityName {
        "ft-get-supply".into()
    }

    fn traverse(
        &self,
        generator: &mut WasmGenerator,
        builder: &mut walrus::InstrSeqBuilder,
        _expr: &SymbolicExpression,
        args: &[SymbolicExpression],
    ) -> Result<(), GeneratorError> {
        let token = args.get_name(0)?;

        let (id_offset, id_length) = generator.add_string_literal(token)?;
        builder
            .i32_const(id_offset as i32)
            .i32_const(id_length as i32);

        builder.call(generator.func_by_name("stdlib.ft_get_supply"));

        Ok(())
    }
}

#[derive(Debug)]
pub struct GetBalanceOfFungibleToken;

impl ComplexWord for GetBalanceOfFungibleToken {
    fn name(&self) -> ClarityName {
        "ft-get-balance".into()
    }

    fn traverse(
        &self,
        generator: &mut WasmGenerator,
        builder: &mut walrus::InstrSeqBuilder,
        _expr: &SymbolicExpression,
        args: &[SymbolicExpression],
    ) -> Result<(), GeneratorError> {
        let token = args.get_name(0)?;
        let owner = args.get_expr(1)?;

        // Push the token name onto the stack
        let (id_offset, id_length) = generator.add_string_literal(token)?;
        builder
            .i32_const(id_offset as i32)
            .i32_const(id_length as i32);

        // Push the owner onto the stack
        generator.traverse_expr(builder, owner)?;

        // Call the host interface function `ft_get_balance`
        builder.call(generator.func_by_name("stdlib.ft_get_balance"));

        Ok(())
    }
}

//////////////////////////////////////////////////////////////////////////////////////////

#[derive(Debug)]
pub struct DefineNonFungibleToken;

impl ComplexWord for DefineNonFungibleToken {
    fn name(&self) -> ClarityName {
        "define-non-fungible-token".into()
    }

    fn traverse(
        &self,
        generator: &mut WasmGenerator,
        builder: &mut walrus::InstrSeqBuilder,
        _expr: &SymbolicExpression,
        args: &[SymbolicExpression],
    ) -> Result<(), GeneratorError> {
        let name = args.get_name(0)?;
        // Making sure if name is not reserved
        if generator.is_reserved_name(name) {
            return Err(GeneratorError::InternalError(format!(
                "Name already used {:?}",
                name
            )));
        }

        let _nft_type = args.get_expr(1)?;

        // Store the identifier as a string literal in the memory
        let (name_offset, name_length) = generator.add_string_literal(name)?;

        // Push the name onto the data stack
        builder
            .i32_const(name_offset as i32)
            .i32_const(name_length as i32);

        builder.call(
            generator
                .module
                .funcs
                .by_name("stdlib.define_nft")
                .ok_or_else(|| {
                    GeneratorError::InternalError("stdlib.define_nft not found".to_owned())
                })?,
        );
        Ok(())
    }
}

#[derive(Debug)]
pub struct BurnNonFungibleToken;

impl ComplexWord for BurnNonFungibleToken {
    fn name(&self) -> ClarityName {
        "nft-burn?".into()
    }

    fn traverse(
        &self,
        generator: &mut WasmGenerator,
        builder: &mut walrus::InstrSeqBuilder,
        _expr: &SymbolicExpression,
        args: &[SymbolicExpression],
    ) -> Result<(), GeneratorError> {
        let token = args.get_name(0)?;
        let identifier = args.get_expr(1)?;
        let sender = args.get_expr(2)?;

        // Push the token name onto the stack
        let (id_offset, id_length) = generator.add_string_literal(token)?;
        builder
            .i32_const(id_offset as i32)
            .i32_const(id_length as i32);

        // Push the identifier onto the stack
        generator.traverse_expr(builder, identifier)?;

        let identifier_ty = generator
            .get_expr_type(identifier)
            .ok_or_else(|| GeneratorError::TypeError("NFT identifier must be typed".to_owned()))?
            .clone();

        // Allocate space on the stack for the identifier
        let (id_offset, id_size) =
            generator.create_call_stack_local(builder, &identifier_ty, true, false);

        // Write the identifier to the stack (since the host needs to handle generic types)
        generator.write_to_memory(builder, id_offset, 0, &identifier_ty)?;

        // Push the offset and size to the data stack
        builder.local_get(id_offset).i32_const(id_size);

        // Push the sender onto the stack
        generator.traverse_expr(builder, sender)?;

        // Call the host interface function `nft_burn`
        builder.call(generator.func_by_name("stdlib.nft_burn"));

        Ok(())
    }
}

#[derive(Debug)]
pub struct TransferNonFungibleToken;

impl ComplexWord for TransferNonFungibleToken {
    fn name(&self) -> ClarityName {
        "nft-transfer?".into()
    }

    fn traverse(
        &self,
        generator: &mut WasmGenerator,
        builder: &mut walrus::InstrSeqBuilder,
        _expr: &SymbolicExpression,
        args: &[SymbolicExpression],
    ) -> Result<(), GeneratorError> {
        let token = args.get_name(0)?;
        let identifier = args.get_expr(1)?;
        let sender = args.get_expr(2)?;
        let recipient = args.get_expr(3)?;

        // Push the token name onto the stack
        let (id_offset, id_length) = generator.add_string_literal(token)?;
        builder
            .i32_const(id_offset as i32)
            .i32_const(id_length as i32);

        // Push the identifier onto the stack
        generator.traverse_expr(builder, identifier)?;

        let identifier_ty = generator
            .get_expr_type(identifier)
            .ok_or_else(|| GeneratorError::TypeError("NFT identifier must be typed".to_owned()))?
            .clone();

        // Allocate space on the stack for the identifier
        let (id_offset, id_size) =
            generator.create_call_stack_local(builder, &identifier_ty, true, false);

        // Write the identifier to the stack (since the host needs to handle generic types)
        generator.write_to_memory(builder, id_offset, 0, &identifier_ty)?;

        // Push the offset and size to the data stack
        builder.local_get(id_offset).i32_const(id_size);

        // Push the sender onto the stack
        generator.traverse_expr(builder, sender)?;

        // Push the recipient onto the stack
        generator.traverse_expr(builder, recipient)?;

        // Call the host interface function `nft_transfer`
        builder.call(generator.func_by_name("stdlib.nft_transfer"));

        Ok(())
    }
}

#[derive(Debug)]
pub struct MintNonFungibleToken;

impl ComplexWord for MintNonFungibleToken {
    fn name(&self) -> ClarityName {
        "nft-mint?".into()
    }

    fn traverse(
        &self,
        generator: &mut WasmGenerator,
        builder: &mut walrus::InstrSeqBuilder,
        _expr: &SymbolicExpression,
        args: &[SymbolicExpression],
    ) -> Result<(), GeneratorError> {
        let token = args.get_name(0)?;
        let identifier = args.get_expr(1)?;
        let recipient = args.get_expr(2)?;

        // Push the token name onto the stack
        let (id_offset, id_length) = generator.add_string_literal(token)?;
        builder
            .i32_const(id_offset as i32)
            .i32_const(id_length as i32);

        // Push the identifier onto the stack
        generator.traverse_expr(builder, identifier)?;

        let identifier_ty = generator
            .get_expr_type(identifier)
            .ok_or_else(|| GeneratorError::TypeError("NFT identifier must be typed".to_owned()))?
            .clone();

        // Allocate space on the stack for the identifier
        let (id_offset, id_size) =
            generator.create_call_stack_local(builder, &identifier_ty, true, false);

        // Write the identifier to the stack (since the host needs to handle generic types)
        generator.write_to_memory(builder, id_offset, 0, &identifier_ty)?;

        // Push the offset and size to the data stack
        builder.local_get(id_offset).i32_const(id_size);

        // Push the recipient onto the stack
        generator.traverse_expr(builder, recipient)?;

        // Call the host interface function `nft_mint`
        builder.call(generator.func_by_name("stdlib.nft_mint"));

        Ok(())
    }
}

#[derive(Debug)]
pub struct GetOwnerOfNonFungibleToken;

impl ComplexWord for GetOwnerOfNonFungibleToken {
    fn name(&self) -> ClarityName {
        "nft-get-owner?".into()
    }

    fn traverse(
        &self,
        generator: &mut WasmGenerator,
        builder: &mut walrus::InstrSeqBuilder,
        _expr: &SymbolicExpression,
        args: &[SymbolicExpression],
    ) -> Result<(), GeneratorError> {
        let token = args.get_name(0)?;
        let identifier = args.get_expr(1)?;

        // Push the token name onto the stack
        let (id_offset, id_length) = generator.add_string_literal(token)?;
        builder
            .i32_const(id_offset as i32)
            .i32_const(id_length as i32);

        // Push the identifier onto the stack
        generator.traverse_expr(builder, identifier)?;

        let identifier_ty = generator
            .get_expr_type(identifier)
            .ok_or_else(|| GeneratorError::TypeError("NFT identifier must be typed".to_owned()))?
            .clone();

        // Allocate space on the stack for the identifier
        let (id_offset, id_size) =
            generator.create_call_stack_local(builder, &identifier_ty, true, false);

        // Write the identifier to the stack (since the host needs to handle generic types)
        generator.write_to_memory(builder, id_offset, 0, &identifier_ty)?;

        // Push the offset and size to the data stack
        builder.local_get(id_offset).i32_const(id_size);

        // Reserve stack space for the return value, a principal
        let return_offset;
        let return_size;
        (return_offset, return_size) =
            generator.create_call_stack_local(builder, &TypeSignature::PrincipalType, false, true);

        // Push the offset and size to the data stack
        builder.local_get(return_offset).i32_const(return_size);

        // Call the host interface function `nft_get_owner`
        builder.call(generator.func_by_name("stdlib.nft_get_owner"));

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use clarity::types::StacksEpochId;

    use crate::tools::{crosscheck, crosscheck_with_epoch};
    use clarity::vm::errors::{Error, WasmError};

    #[ignore = "compilation error"]
    #[test]
    fn bar_mint_too_many() {
        crosscheck(
            "(ft-mint? bar u1000001 tx-sender)",
            Err(Error::Wasm(WasmError::WasmGeneratorError(
                "[TODO] change that".to_string(),
            ))),
        );
    }

    #[ignore = "compilation error"]
    #[test]
    fn bar_mint_too_many_2() {
        crosscheck(
            "
(define-public (bar-mint-too-many-2)
  (begin
    (unwrap-panic (ft-mint? bar u5555555 tx-sender))
    (ft-mint? bar u5555555 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM)))

(bar-mint-too-many-2)
",
            Err(Error::Wasm(WasmError::WasmGeneratorError(
                "[TODO] change that".to_string(),
            ))),
        );
    }

    #[test]
    fn validate_define_fungible_tokens() {
        // Reserved keyword
        crosscheck("(define-fungible-token map u100)", Err(()));
        // Custom fungible token name
        crosscheck("(define-fungible-token a u100)", Ok(None));
        // Custom fungible token name duplicate
        crosscheck(
            "(define-fungible-token a u100) (define-fungible-token a u100)",
            Err(()),
        );
    }

    #[test]
    fn validate_define_fungible_tokens_epoch() {
        // Epoch20
        crosscheck_with_epoch(
            "(define-fungible-token index-of u100)",
            Err(()),
            StacksEpochId::Epoch20,
        );
        crosscheck_with_epoch(
            "(define-fungible-token index-of? u100)",
            Ok(None),
            StacksEpochId::Epoch20,
        );

        // Latest Epoch and Clarity Version
        crosscheck("(define-fungible-token index-of? u100)", Err(()));
        crosscheck("(define-fungible-token index-of u100)", Err(()));
    }

    #[test]
    fn validate_define_non_fungible_tokens() {
        // Reserved keyword
        crosscheck("(define-non-fungible-token map (buff 50))", Err(()));
        // Custom nft name
        crosscheck("(define-non-fungible-token a (buff 50))", Ok(None));
        // Custom nft name duplicate
        crosscheck(
            "(define-non-fungible-token a (buff 50)) (define-non-fungible-token a (buff 50))",
            Err(()),
        );
    }

    #[test]
    fn validate_define_non_fungible_tokens_epoch() {
        // Epoch20
        crosscheck_with_epoch(
            "(define-non-fungible-token index-of (buff 50))",
            Err(()),
            StacksEpochId::Epoch20,
        );
        crosscheck_with_epoch(
            "(define-non-fungible-token index-of? (buff 50))",
            Ok(None),
            StacksEpochId::Epoch20,
        );

        // Latest Epoch and Clarity Version
        crosscheck("(define-non-fungible-token index-of (buff 50))", Err(()));
        crosscheck("(define-non-fungible-token index-of? (buff 50))", Err(()));
    }
}
