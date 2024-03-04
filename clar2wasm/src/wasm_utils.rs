#![allow(non_camel_case_types)]

use clarity::vm::analysis::CheckErrors;
use clarity::vm::clarity_wasm::get_type_size;
use clarity::vm::clarity_wasm::is_in_memory_type;
use clarity::vm::errors::{Error, WasmError};
use clarity::vm::types::{
    ASCIIData, BuffData, CharType, ListData, OptionalData, PrincipalData,
    QualifiedContractIdentifier, ResponseData, SequenceData, StandardPrincipalData, TupleData,
};
use clarity::vm::types::{BufferLength, SequenceSubtype, StringSubtype, TypeSignature};
use clarity::vm::ContractName;
use clarity::vm::Value;

use stacks_common::types::StacksEpochId;
use wasmtime::{AsContextMut, Memory, Val, ValType};

use crate::wasm_generator::clar2wasm_ty;

// Bytes for principal version
pub const PRINCIPAL_VERSION_BYTES: usize = 1;
// Number of bytes in principal hash
pub const PRINCIPAL_HASH_BYTES: usize = 20;
// Standard principal version + hash
pub const PRINCIPAL_BYTES: usize = PRINCIPAL_VERSION_BYTES + PRINCIPAL_HASH_BYTES;
// Number of bytes used to store the length of the contract name
pub const CONTRACT_NAME_LENGTH_BYTES: usize = 1;
// 1 byte for version, 20 bytes for hash, 4 bytes for contract name length (0)
pub const STANDARD_PRINCIPAL_BYTES: usize = PRINCIPAL_BYTES + CONTRACT_NAME_LENGTH_BYTES;
// Max length of a contract name
pub const CONTRACT_NAME_MAX_LENGTH: usize = 128;
// Standard principal, but at most 128 character function name
pub const PRINCIPAL_BYTES_MAX: usize = STANDARD_PRINCIPAL_BYTES + CONTRACT_NAME_MAX_LENGTH;

pub enum MintAssetErrorCodes {
    ALREADY_EXIST = 1,
}

pub enum MintTokenErrorCodes {
    NON_POSITIVE_AMOUNT = 1,
}

pub enum TransferAssetErrorCodes {
    NOT_OWNED_BY = 1,
    SENDER_IS_RECIPIENT = 2,
    DOES_NOT_EXIST = 3,
}

pub enum TransferTokenErrorCodes {
    NOT_ENOUGH_BALANCE = 1,
    SENDER_IS_RECIPIENT = 2,
    NON_POSITIVE_AMOUNT = 3,
}

pub enum BurnAssetErrorCodes {
    NOT_OWNED_BY = 1,
    DOES_NOT_EXIST = 3,
}

pub enum BurnTokenErrorCodes {
    NOT_ENOUGH_BALANCE_OR_NON_POSITIVE = 1,
}

pub enum StxErrorCodes {
    NOT_ENOUGH_BALANCE = 1,
    SENDER_IS_RECIPIENT = 2,
    NON_POSITIVE_AMOUNT = 3,
    SENDER_IS_NOT_TX_SENDER = 4,
}

/// Write a value to the Wasm memory at `offset` given the provided Clarity
/// `TypeSignature`. If the value is an in-memory type, then it will be written
/// to the memory at `in_mem_offset`, and if `include_repr` is true, the offset
/// and length of the value will be written to the memory at `offset`.
/// Returns the number of bytes written at `offset` and at `in_mem_offset`.
pub fn write_to_wasm(
    mut store: impl AsContextMut,
    memory: Memory,
    ty: &TypeSignature,
    offset: i32,
    in_mem_offset: i32,
    value: &Value,
    include_repr: bool,
) -> Result<(i32, i32), Error> {
    match ty {
        TypeSignature::IntType => {
            let mut buffer: [u8; 8] = [0; 8];
            let i = value_as_i128(&value)?;
            let high = (i >> 64) as u64;
            let low = (i & 0xffff_ffff_ffff_ffff) as u64;
            buffer.copy_from_slice(&low.to_le_bytes());
            memory
                .write(&mut store, offset as usize, &buffer)
                .map_err(|e| Error::Wasm(WasmError::UnableToWriteMemory(e.into())))?;
            buffer.copy_from_slice(&high.to_le_bytes());
            memory
                .write(&mut store, (offset + 8) as usize, &buffer)
                .map_err(|e| Error::Wasm(WasmError::UnableToWriteMemory(e.into())))?;
            Ok((16, 0))
        }
        TypeSignature::UIntType => {
            let mut buffer: [u8; 8] = [0; 8];
            let i = value_as_u128(&value)?;
            let high = (i >> 64) as u64;
            let low = (i & 0xffff_ffff_ffff_ffff) as u64;
            buffer.copy_from_slice(&low.to_le_bytes());
            memory
                .write(&mut store, offset as usize, &buffer)
                .map_err(|e| Error::Wasm(WasmError::UnableToWriteMemory(e.into())))?;
            buffer.copy_from_slice(&high.to_le_bytes());
            memory
                .write(&mut store, (offset + 8) as usize, &buffer)
                .map_err(|e| Error::Wasm(WasmError::UnableToWriteMemory(e.into())))?;
            Ok((16, 0))
        }
        TypeSignature::SequenceType(SequenceSubtype::BufferType(_length)) => {
            let buffdata = value_as_buffer(value.clone())?;
            let mut written = 0;
            let mut in_mem_written = 0;

            // Write the value to `in_mem_offset`
            memory
                .write(
                    &mut store,
                    (in_mem_offset + in_mem_written) as usize,
                    &buffdata.data,
                )
                .map_err(|e| Error::Wasm(WasmError::UnableToWriteMemory(e.into())))?;
            in_mem_written += buffdata.data.len() as i32;

            if include_repr {
                // Write the representation (offset and length) of the value to
                // `offset`.
                let offset_buffer = (in_mem_offset as i32).to_le_bytes();
                memory
                    .write(&mut store, (offset) as usize, &offset_buffer)
                    .map_err(|e| Error::Wasm(WasmError::UnableToWriteMemory(e.into())))?;
                written += 4;
                let len_buffer = (in_mem_written as i32).to_le_bytes();
                memory
                    .write(&mut store, (offset + written) as usize, &len_buffer)
                    .map_err(|e| Error::Wasm(WasmError::UnableToWriteMemory(e.into())))?;
                written += 4;
            }

            Ok((written, in_mem_written))
        }
        TypeSignature::SequenceType(SequenceSubtype::StringType(StringSubtype::ASCII(_length))) => {
            let string = value_as_string_ascii(value.clone())?;
            let mut written = 0;
            let mut in_mem_written = 0;

            // Write the value to `in_mem_offset`
            memory
                .write(
                    &mut store,
                    (in_mem_offset + in_mem_written) as usize,
                    &string.data,
                )
                .map_err(|e| Error::Wasm(WasmError::UnableToWriteMemory(e.into())))?;
            in_mem_written += string.data.len() as i32;

            if include_repr {
                // Write the representation (offset and length) of the value to
                // `offset`.
                let offset_buffer = (in_mem_offset as i32).to_le_bytes();
                memory
                    .write(&mut store, (offset) as usize, &offset_buffer)
                    .map_err(|e| Error::Wasm(WasmError::UnableToWriteMemory(e.into())))?;
                written += 4;
                let len_buffer = (in_mem_written as i32).to_le_bytes();
                memory
                    .write(&mut store, (offset + written) as usize, &len_buffer)
                    .map_err(|e| Error::Wasm(WasmError::UnableToWriteMemory(e.into())))?;
                written += 4;
            }

            Ok((written, in_mem_written))
        }
        TypeSignature::SequenceType(SequenceSubtype::ListType(list)) => {
            let mut written = 0;
            let list_data = value_as_list(value)?;
            let elem_ty = list.get_list_item_type();
            // For a list, the values are written to the memory at
            // `in_mem_offset`, and the representation (offset and length) is
            // written to the memory at `offset`. The `in_mem_offset` for the
            // list elements should be after their representations.
            let val_offset = in_mem_offset;
            let val_in_mem_offset = in_mem_offset
                + list_data.data.len() as i32
                    * get_type_size(list_data.type_signature.get_list_item_type());
            let mut val_written = 0;
            let mut val_in_mem_written = 0;
            for elem in &list_data.data {
                let (new_written, new_in_mem_written) = write_to_wasm(
                    store.as_context_mut(),
                    memory,
                    elem_ty,
                    val_offset + val_written,
                    val_in_mem_offset + val_in_mem_written,
                    &elem,
                    true,
                )?;
                val_written += new_written;
                val_in_mem_written += new_in_mem_written;
            }

            if include_repr {
                // Write the representation (offset and length) of the value to
                // `offset`.
                let offset_buffer = (in_mem_offset as i32).to_le_bytes();
                memory
                    .write(&mut store, (offset) as usize, &offset_buffer)
                    .map_err(|e| Error::Wasm(WasmError::UnableToWriteMemory(e.into())))?;
                written += 4;
                let len_buffer = (val_written as i32).to_le_bytes();
                memory
                    .write(&mut store, (offset + 4) as usize, &len_buffer)
                    .map_err(|e| Error::Wasm(WasmError::UnableToWriteMemory(e.into())))?;
                written += 4;
            }

            Ok((written, val_written + val_in_mem_written))
        }
        TypeSignature::SequenceType(_) => todo!("type not yet implemented: {:?}", ty),
        TypeSignature::ResponseType(inner_types) => {
            let mut written = 0;
            let mut in_mem_written = 0;
            let res = value_as_response(value)?;
            let indicator = if res.committed { 1i32 } else { 0i32 };
            let indicator_bytes = indicator.to_le_bytes();
            memory
                .write(&mut store, (offset) as usize, &indicator_bytes)
                .map_err(|e| Error::Wasm(WasmError::UnableToWriteMemory(e.into())))?;
            written += 4;
            if res.committed {
                let (new_written, new_in_mem_written) = write_to_wasm(
                    store,
                    memory,
                    &inner_types.0,
                    offset + written,
                    in_mem_offset,
                    &res.data,
                    true,
                )?;
                written += new_written;
                in_mem_written += new_in_mem_written;

                // Skip space for the err value
                written += get_type_size(&inner_types.1);
            } else {
                // Skip space for the ok value
                written += get_type_size(&inner_types.0);

                let (new_written, new_in_mem_written) = write_to_wasm(
                    store,
                    memory,
                    &inner_types.1,
                    offset + written,
                    in_mem_offset,
                    &res.data,
                    true,
                )?;
                written += new_written;
                in_mem_written += new_in_mem_written;
            }
            Ok((written, in_mem_written))
        }
        TypeSignature::BoolType => {
            let bool_val = value_as_bool(&value)?;
            let val = if bool_val { 1u32 } else { 0u32 };
            let val_bytes = val.to_le_bytes();
            memory
                .write(&mut store, (offset) as usize, &val_bytes)
                .map_err(|e| Error::Wasm(WasmError::UnableToWriteMemory(e.into())))?;
            Ok((4, 0))
        }
        TypeSignature::NoType => {
            let val_bytes = [0u8; 4];
            memory
                .write(&mut store, (offset) as usize, &val_bytes)
                .map_err(|e| Error::Wasm(WasmError::UnableToWriteMemory(e.into())))?;
            Ok((4, 0))
        }
        TypeSignature::OptionalType(inner_ty) => {
            let mut written = 0;
            let mut in_mem_written = 0;
            let opt_data = value_as_optional(value)?;
            let indicator = if opt_data.data.is_some() { 1i32 } else { 0i32 };
            let indicator_bytes = indicator.to_le_bytes();
            memory
                .write(&mut store, (offset) as usize, &indicator_bytes)
                .map_err(|e| Error::Wasm(WasmError::UnableToWriteMemory(e.into())))?;
            written += 4;
            if let Some(inner) = opt_data.data.as_ref() {
                let (new_written, new_in_mem_written) = write_to_wasm(
                    store,
                    memory,
                    inner_ty,
                    offset + written,
                    in_mem_offset,
                    inner,
                    true,
                )?;
                written += new_written;
                in_mem_written += new_in_mem_written;
            } else {
                written += get_type_size(&inner_ty);
            }
            Ok((written, in_mem_written))
        }
        TypeSignature::PrincipalType
        | TypeSignature::CallableType(_)
        | TypeSignature::TraitReferenceType(_) => {
            let principal = value_as_principal(&value)?;
            let (standard, contract_name) = match principal {
                PrincipalData::Standard(s) => (s, ""),
                PrincipalData::Contract(contract_identifier) => (
                    &contract_identifier.issuer,
                    contract_identifier.name.as_str(),
                ),
            };
            let mut written = 0;
            let mut in_mem_written = 0;

            // Write the value to in_mem_offset
            memory
                .write(
                    &mut store,
                    (in_mem_offset + in_mem_written) as usize,
                    &[standard.0],
                )
                .map_err(|e| Error::Wasm(WasmError::UnableToWriteMemory(e.into())))?;
            in_mem_written += 1;
            memory
                .write(
                    &mut store,
                    (in_mem_offset + in_mem_written) as usize,
                    &standard.1,
                )
                .map_err(|e| Error::Wasm(WasmError::UnableToWriteMemory(e.into())))?;
            in_mem_written += standard.1.len() as i32;
            if !contract_name.is_empty() {
                let len_buffer = [contract_name.len() as u8];
                memory
                    .write(
                        &mut store,
                        (in_mem_offset + in_mem_written) as usize,
                        &len_buffer,
                    )
                    .map_err(|e| Error::Wasm(WasmError::UnableToWriteMemory(e.into())))?;
                in_mem_written += 1;
                let bytes = contract_name.as_bytes();
                memory
                    .write(&mut store, (in_mem_offset + in_mem_written) as usize, bytes)
                    .map_err(|e| Error::Wasm(WasmError::UnableToWriteMemory(e.into())))?;
                in_mem_written += bytes.len() as i32;
            } else {
                let len_buffer = [0u8];
                memory
                    .write(
                        &mut store,
                        (in_mem_offset + in_mem_written) as usize,
                        &len_buffer,
                    )
                    .map_err(|e| Error::Wasm(WasmError::UnableToWriteMemory(e.into())))?;
                in_mem_written += 1;
            }

            if include_repr {
                // Write the representation (offset and length of the value) to the
                // offset
                let offset_buffer = (in_mem_offset as i32).to_le_bytes();
                memory
                    .write(&mut store, (offset) as usize, &offset_buffer)
                    .map_err(|e| Error::Wasm(WasmError::UnableToWriteMemory(e.into())))?;
                written += 4;
                let len_buffer = (in_mem_written as i32).to_le_bytes();
                memory
                    .write(&mut store, (offset + written) as usize, &len_buffer)
                    .map_err(|e| Error::Wasm(WasmError::UnableToWriteMemory(e.into())))?;
                written += 4;
            }

            Ok((written, in_mem_written))
        }
        TypeSignature::TupleType(type_sig) => {
            let tuple_data = value_as_tuple(value)?;
            let mut written = 0;
            let mut in_mem_written = 0;

            for (key, val) in &tuple_data.data_map {
                let val_type = type_sig
                    .field_type(&key)
                    .ok_or(Error::Wasm(WasmError::ValueTypeMismatch))?;
                let (new_written, new_in_mem_written) = write_to_wasm(
                    store.as_context_mut(),
                    memory,
                    val_type,
                    offset + written,
                    in_mem_offset + in_mem_written,
                    val,
                    true,
                )?;
                written += new_written;
                in_mem_written += new_in_mem_written;
            }

            Ok((written, in_mem_written))
        }
        TypeSignature::ListUnionType(_) => {
            unreachable!("not a value type")
        }
    }
}

/// Convert a Wasm value into a Clarity `Value`. Depending on the type, the
/// values may be directly passed in the Wasm `Val`s or may be read from the
/// Wasm memory, via an offset and size.
/// - `type_sig` is the Clarity type of the value.
/// - `value_index` is the index of the value in the array of Wasm `Val`s.
/// - `buffer` is the array of Wasm `Val`s.
/// - `memory` is the Wasm memory.
/// - `store` is the Wasm store.
/// Returns the Clarity `Value` and the number of Wasm `Val`s that were used.
pub fn wasm_to_clarity_value(
    type_sig: &TypeSignature,
    value_index: usize,
    buffer: &[Val],
    memory: Memory,
    mut store: &mut impl AsContextMut,
    epoch: StacksEpochId,
) -> Result<(Option<Value>, usize), Error> {
    match type_sig {
        TypeSignature::IntType => {
            let lower = buffer[value_index]
                .i64()
                .ok_or(Error::Wasm(WasmError::ValueTypeMismatch))?;
            let upper = buffer[value_index + 1]
                .i64()
                .ok_or(Error::Wasm(WasmError::ValueTypeMismatch))?;
            Ok((
                Some(Value::Int(((upper as i128) << 64) | (lower as u64) as i128)),
                2,
            ))
        }
        TypeSignature::UIntType => {
            let lower = buffer[value_index]
                .i64()
                .ok_or(Error::Wasm(WasmError::ValueTypeMismatch))?;
            let upper = buffer[value_index + 1]
                .i64()
                .ok_or(Error::Wasm(WasmError::ValueTypeMismatch))?;
            Ok((
                Some(Value::UInt(
                    ((upper as u128) << 64) | (lower as u64) as u128,
                )),
                2,
            ))
        }
        TypeSignature::BoolType => Ok((
            Some(Value::Bool(
                buffer[value_index]
                    .i32()
                    .ok_or(Error::Wasm(WasmError::ValueTypeMismatch))?
                    != 0,
            )),
            1,
        )),
        TypeSignature::OptionalType(optional) => {
            let value_types = clar2wasm_ty(optional);
            Ok((
                if buffer[value_index]
                    .i32()
                    .ok_or(Error::Wasm(WasmError::ValueTypeMismatch))?
                    == 1
                {
                    let (value, _) = wasm_to_clarity_value(
                        optional,
                        value_index + 1,
                        buffer,
                        memory,
                        store,
                        epoch,
                    )?;
                    Some(Value::some(value.ok_or(Error::Unchecked(
                        CheckErrors::CouldNotDetermineType,
                    ))?)?)
                } else {
                    Some(Value::none())
                },
                1 + value_types.len(),
            ))
        }
        TypeSignature::ResponseType(response) => {
            let ok_types = clar2wasm_ty(&response.0);
            let err_types = clar2wasm_ty(&response.1);

            Ok((
                if buffer[value_index]
                    .i32()
                    .ok_or(Error::Wasm(WasmError::ValueTypeMismatch))?
                    == 1
                {
                    let (ok, _) = wasm_to_clarity_value(
                        &response.0,
                        value_index + 1,
                        buffer,
                        memory,
                        store,
                        epoch,
                    )?;
                    Some(Value::okay(ok.ok_or(Error::Unchecked(
                        CheckErrors::CouldNotDetermineResponseOkType,
                    ))?)?)
                } else {
                    let (err, _) = wasm_to_clarity_value(
                        &response.1,
                        value_index + 1 + ok_types.len(),
                        buffer,
                        memory,
                        store,
                        epoch,
                    )?;
                    Some(Value::error(err.ok_or(Error::Unchecked(
                        CheckErrors::CouldNotDetermineResponseErrType,
                    ))?)?)
                },
                1 + ok_types.len() + err_types.len(),
            ))
        }
        TypeSignature::SequenceType(SequenceSubtype::StringType(StringSubtype::ASCII(_))) => {
            let offset = buffer[value_index]
                .i32()
                .ok_or(Error::Wasm(WasmError::ValueTypeMismatch))?;
            let length = buffer[value_index + 1]
                .i32()
                .ok_or(Error::Wasm(WasmError::ValueTypeMismatch))?;
            let mut string_buffer: Vec<u8> = vec![0; length as usize];
            memory
                .read(store, offset as usize, &mut string_buffer)
                .map_err(|e| Error::Wasm(WasmError::UnableToReadMemory(e.into())))?;
            Ok((Some(Value::string_ascii_from_bytes(string_buffer)?), 2))
        }
        // A `NoType` will be a dummy value that should not be used.
        TypeSignature::NoType => Ok((None, 1)),
        TypeSignature::SequenceType(SequenceSubtype::StringType(StringSubtype::UTF8(_))) => {
            let offset = buffer[value_index]
                .i32()
                .ok_or(Error::Wasm(WasmError::ValueTypeMismatch))?;
            let length = buffer[value_index + 1]
                .i32()
                .ok_or(Error::Wasm(WasmError::ValueTypeMismatch))?;
            let mut string_buffer: Vec<u8> = vec![0; length as usize];
            memory
                .read(store, offset as usize, &mut string_buffer)
                .map_err(|e| Error::Wasm(WasmError::UnableToReadMemory(e.into())))?;
            Ok((
                Some(Value::string_utf8_from_unicode_scalars(string_buffer)?),
                2,
            ))
        }
        TypeSignature::SequenceType(SequenceSubtype::BufferType(_buffer_length)) => {
            let offset = buffer[value_index]
                .i32()
                .ok_or(Error::Wasm(WasmError::ValueTypeMismatch))?;
            let length = buffer[value_index + 1]
                .i32()
                .ok_or(Error::Wasm(WasmError::ValueTypeMismatch))?;
            let mut buff: Vec<u8> = vec![0; length as usize];
            memory
                .read(store, offset as usize, &mut buff)
                .map_err(|e| Error::Wasm(WasmError::UnableToReadMemory(e.into())))?;
            Ok((Some(Value::buff_from(buff)?), 2))
        }
        TypeSignature::SequenceType(SequenceSubtype::ListType(_)) => {
            let offset = buffer[value_index]
                .i32()
                .ok_or(Error::Wasm(WasmError::ValueTypeMismatch))?;
            let length = buffer[value_index + 1]
                .i32()
                .ok_or(Error::Wasm(WasmError::ValueTypeMismatch))?;

            let value = read_from_wasm(memory, store, type_sig, offset, length, epoch)?;
            Ok((Some(value), 2))
        }
        TypeSignature::PrincipalType
        | TypeSignature::CallableType(_)
        | TypeSignature::TraitReferenceType(_) => {
            let offset = buffer[value_index]
                .i32()
                .ok_or(Error::Wasm(WasmError::ValueTypeMismatch))?;
            let mut principal_bytes: [u8; 1 + PRINCIPAL_HASH_BYTES] = [0; 1 + PRINCIPAL_HASH_BYTES];
            memory
                .read(&mut store, offset as usize, &mut principal_bytes)
                .map_err(|e| Error::Wasm(WasmError::UnableToReadMemory(e.into())))?;
            let mut buffer: [u8; CONTRACT_NAME_LENGTH_BYTES] = [0; CONTRACT_NAME_LENGTH_BYTES];
            memory
                .read(&mut store, offset as usize + 21, &mut buffer)
                .map_err(|e| Error::Wasm(WasmError::UnableToReadMemory(e.into())))?;
            let standard =
                StandardPrincipalData(principal_bytes[0], principal_bytes[1..].try_into().unwrap());
            let contract_name_length = buffer[0] as usize;
            if contract_name_length == 0 {
                Ok((Some(Value::Principal(PrincipalData::Standard(standard))), 2))
            } else {
                let mut contract_name: Vec<u8> = vec![0; contract_name_length];
                memory
                    .read(
                        store,
                        (offset + STANDARD_PRINCIPAL_BYTES as i32) as usize,
                        &mut contract_name,
                    )
                    .map_err(|e| Error::Wasm(WasmError::UnableToReadMemory(e.into())))?;
                Ok((
                    Some(Value::Principal(PrincipalData::Contract(
                        QualifiedContractIdentifier {
                            issuer: standard,
                            name: ContractName::try_from(
                                String::from_utf8(contract_name).map_err(|e| {
                                    Error::Wasm(WasmError::UnableToReadIdentifier(e))
                                })?,
                            )?,
                        },
                    ))),
                    2,
                ))
            }
        }
        TypeSignature::TupleType(t) => {
            let mut index = value_index;
            let mut data_map = Vec::new();
            for (name, ty) in t.get_type_map() {
                let (value, increment) =
                    wasm_to_clarity_value(ty, index, buffer, memory, store, epoch)?;
                data_map.push((
                    name.clone(),
                    value.ok_or(Error::Unchecked(CheckErrors::BadTupleConstruction))?,
                ));
                index += increment;
            }
            let tuple = TupleData::from_data(data_map)?;
            Ok((Some(tuple.into()), index - value_index))
        }
        TypeSignature::ListUnionType(_lu) => {
            todo!("Wasm value type not implemented: {:?}", type_sig)
        }
    }
}

/// Read a value from the Wasm memory at `offset` with `length`, given the
/// provided Clarity `TypeSignature`.
pub fn read_from_wasm(
    memory: Memory,
    mut store: &mut impl AsContextMut,
    ty: &TypeSignature,
    offset: i32,
    length: i32,
    epoch: StacksEpochId,
) -> Result<Value, Error> {
    match ty {
        TypeSignature::UIntType => {
            debug_assert!(
                length == 16,
                "expected uint length to be 16 bytes, found {length}"
            );
            let mut buffer: [u8; 8] = [0; 8];
            memory
                .read(&mut store, offset as usize, &mut buffer)
                .map_err(|e| Error::Wasm(WasmError::Runtime(e.into())))?;
            let low = u64::from_le_bytes(buffer) as u128;
            memory
                .read(store, (offset + 8) as usize, &mut buffer)
                .map_err(|e| Error::Wasm(WasmError::Runtime(e.into())))?;
            let high = u64::from_le_bytes(buffer) as u128;
            Ok(Value::UInt((high << 64) | low))
        }
        TypeSignature::IntType => {
            debug_assert!(
                length == 16,
                "expected int length to be 16 bytes, found {length}"
            );
            let mut buffer: [u8; 8] = [0; 8];
            memory
                .read(&mut store, offset as usize, &mut buffer)
                .map_err(|e| Error::Wasm(WasmError::Runtime(e.into())))?;
            let low = u64::from_le_bytes(buffer) as u128;
            memory
                .read(store, (offset + 8) as usize, &mut buffer)
                .map_err(|e| Error::Wasm(WasmError::Runtime(e.into())))?;
            let high = u64::from_le_bytes(buffer) as u128;
            Ok(Value::Int(((high << 64) | low) as i128))
        }
        TypeSignature::SequenceType(SequenceSubtype::StringType(StringSubtype::ASCII(
            type_length,
        ))) => {
            debug_assert!(
                type_length >= &BufferLength::try_from(length as u32)?,
                "expected string length to be less than the type length"
            );
            let mut buffer: Vec<u8> = vec![0; length as usize];
            memory
                .read(store, offset as usize, &mut buffer)
                .map_err(|e| Error::Wasm(WasmError::Runtime(e.into())))?;
            Value::string_ascii_from_bytes(buffer)
        }
        TypeSignature::SequenceType(SequenceSubtype::StringType(StringSubtype::UTF8(_s))) => {
            let mut buffer: Vec<u8> = vec![0; length as usize];
            memory
                .read(store, offset as usize, &mut buffer)
                .map_err(|e| Error::Wasm(WasmError::Runtime(e.into())))?;
            Value::string_utf8_from_unicode_scalars(buffer)
        }
        TypeSignature::PrincipalType
        | TypeSignature::CallableType(_)
        | TypeSignature::TraitReferenceType(_) => {
            debug_assert!(
                length >= STANDARD_PRINCIPAL_BYTES as i32 && length <= PRINCIPAL_BYTES_MAX as i32
            );
            let mut current_offset = offset as usize;
            let mut version: [u8; PRINCIPAL_VERSION_BYTES] = [0; PRINCIPAL_VERSION_BYTES];
            let mut hash: [u8; PRINCIPAL_HASH_BYTES] = [0; PRINCIPAL_HASH_BYTES];
            memory
                .read(&mut store, current_offset, &mut version)
                .map_err(|e| Error::Wasm(WasmError::Runtime(e.into())))?;
            current_offset += PRINCIPAL_VERSION_BYTES;
            memory
                .read(&mut store, current_offset, &mut hash)
                .map_err(|e| Error::Wasm(WasmError::Runtime(e.into())))?;
            current_offset += PRINCIPAL_HASH_BYTES;
            let principal = StandardPrincipalData(version[0], hash);
            let mut contract_length_buf: [u8; CONTRACT_NAME_LENGTH_BYTES] =
                [0; CONTRACT_NAME_LENGTH_BYTES];
            memory
                .read(&mut store, current_offset, &mut contract_length_buf)
                .map_err(|e| Error::Wasm(WasmError::Runtime(e.into())))?;
            current_offset += CONTRACT_NAME_LENGTH_BYTES;
            let contract_length = contract_length_buf[0];
            if contract_length == 0 {
                Ok(Value::Principal(principal.into()))
            } else {
                let mut contract_name: Vec<u8> = vec![0; contract_length as usize];
                memory
                    .read(store, current_offset, &mut contract_name)
                    .map_err(|e| Error::Wasm(WasmError::Runtime(e.into())))?;
                let contract_name = String::from_utf8(contract_name)
                    .map_err(|e| Error::Wasm(WasmError::Runtime(e.into())))?;
                Ok(Value::Principal(PrincipalData::Contract(
                    QualifiedContractIdentifier {
                        issuer: principal,
                        name: ContractName::try_from(contract_name)?,
                    },
                )))
            }
        }
        TypeSignature::SequenceType(SequenceSubtype::BufferType(_b)) => {
            let mut buffer: Vec<u8> = vec![0; length as usize];
            memory
                .read(store, offset as usize, &mut buffer)
                .map_err(|e| Error::Wasm(WasmError::Runtime(e.into())))?;
            Value::buff_from(buffer)
        }
        TypeSignature::SequenceType(SequenceSubtype::ListType(list)) => {
            let elem_ty = list.get_list_item_type();
            let elem_length = get_type_size(elem_ty);
            let end = offset + length;
            let mut buffer: Vec<Value> = Vec::new();
            let mut current_offset = offset;
            while current_offset < end {
                let elem = read_from_wasm_indirect(memory, store, elem_ty, current_offset, epoch)?;
                buffer.push(elem);
                current_offset += elem_length;
            }
            Value::cons_list_unsanitized(buffer)
        }
        TypeSignature::BoolType => {
            debug_assert!(
                length == 4,
                "expected bool length to be 4 bytes, found {length}"
            );
            let mut buffer: [u8; 4] = [0; 4];
            memory
                .read(&mut store, offset as usize, &mut buffer)
                .map_err(|e| Error::Wasm(WasmError::Runtime(e.into())))?;
            let bool_val = u32::from_le_bytes(buffer);
            Ok(Value::Bool(bool_val != 0))
        }
        TypeSignature::TupleType(type_sig) => {
            let mut data = Vec::new();
            let mut current_offset = offset;
            for (field_key, field_ty) in type_sig.get_type_map() {
                let field_length = get_type_size(field_ty);
                let field_value =
                    read_from_wasm_indirect(memory, store, field_ty, current_offset, epoch)?;
                data.push((field_key.clone(), field_value));
                current_offset += field_length;
            }
            Ok(Value::Tuple(TupleData::from_data(data)?))
        }
        TypeSignature::ResponseType(response_type) => {
            let mut current_offset = offset;

            // Read the indicator
            let mut indicator_bytes = [0u8; 4];
            memory
                .read(&mut store, current_offset as usize, &mut indicator_bytes)
                .map_err(|e| Error::Wasm(WasmError::Runtime(e.into())))?;
            current_offset += 4;
            let indicator = i32::from_le_bytes(indicator_bytes);

            // Read the ok or err value, depending on the indicator
            match indicator {
                0 => {
                    current_offset += get_type_size(&response_type.0);
                    let err_value = read_from_wasm_indirect(
                        memory,
                        store,
                        &response_type.1,
                        current_offset,
                        epoch,
                    )?;
                    Value::error(err_value).map_err(|_| Error::Wasm(WasmError::ValueTypeMismatch))
                }
                1 => {
                    let ok_value = read_from_wasm_indirect(
                        memory,
                        store,
                        &response_type.0,
                        current_offset,
                        epoch,
                    )?;
                    Value::okay(ok_value).map_err(|_| Error::Wasm(WasmError::ValueTypeMismatch))
                }
                _ => Err(Error::Wasm(WasmError::InvalidIndicator(indicator))),
            }
        }
        TypeSignature::OptionalType(type_sig) => {
            let mut current_offset = offset;

            // Read the indicator
            let mut indicator_bytes = [0u8; 4];
            memory
                .read(&mut store, current_offset as usize, &mut indicator_bytes)
                .map_err(|e| Error::Wasm(WasmError::Runtime(e.into())))?;
            current_offset += 4;
            let indicator = i32::from_le_bytes(indicator_bytes);

            match indicator {
                0 => Ok(Value::none()),
                1 => {
                    let value =
                        read_from_wasm_indirect(memory, store, type_sig, current_offset, epoch)?;
                    Ok(
                        Value::some(value)
                            .map_err(|_| Error::Wasm(WasmError::ValueTypeMismatch))?,
                    )
                }
                _ => Err(Error::Wasm(WasmError::InvalidIndicator(indicator))),
            }
        }
        TypeSignature::NoType => todo!("type not yet implemented: {:?}", ty),
        TypeSignature::ListUnionType(_subtypes) => todo!("type not yet implemented: {:?}", ty),
    }
}

/// Read a value from the Wasm memory at `offset` with `length` given the
/// provided Clarity `TypeSignature`. In-memory values require one extra level
/// of indirection, so this function will read the offset and length from the
/// memory, then read the actual value.
pub fn read_from_wasm_indirect(
    memory: Memory,
    store: &mut impl AsContextMut,
    ty: &TypeSignature,
    mut offset: i32,
    epoch: StacksEpochId,
) -> Result<Value, Error> {
    let mut length = get_type_size(ty);

    // For in-memory types, first read the offset and length from the memory,
    // then read the actual value.
    if is_in_memory_type(ty) {
        (offset, length) = read_indirect_offset_and_length(memory, store, offset)?;
    };

    read_from_wasm(memory, store, ty, offset, length, epoch)
}

pub fn read_indirect_offset_and_length(
    memory: Memory,
    mut store: &mut impl AsContextMut,
    offset: i32,
) -> Result<(i32, i32), Error> {
    let mut buffer: [u8; 4] = [0; 4];
    memory
        .read(&mut store, offset as usize, &mut buffer)
        .map_err(|e| Error::Wasm(WasmError::Runtime(e.into())))?;
    let indirect_offset = i32::from_le_bytes(buffer);
    memory
        .read(&mut store, (offset + 4) as usize, &mut buffer)
        .map_err(|e| Error::Wasm(WasmError::Runtime(e.into())))?;
    let length = i32::from_le_bytes(buffer);
    Ok((indirect_offset, length))
}

/// Read bytes from the WASM memory at `offset` with `length`
pub fn read_bytes_from_wasm(
    memory: Memory,
    store: &mut impl AsContextMut,
    offset: i32,
    length: i32,
) -> Result<Vec<u8>, Error> {
    let mut buffer: Vec<u8> = vec![0; length as usize];
    memory
        .read(store, offset as usize, &mut buffer)
        .map_err(|e| Error::Wasm(WasmError::Runtime(e.into())))?;
    Ok(buffer)
}

pub fn value_as_bool(value: &Value) -> Result<bool, Error> {
    match value {
        Value::Bool(b) => Ok(*b),
        _ => Err(Error::Wasm(WasmError::ValueTypeMismatch)),
    }
}

pub fn value_as_i128(value: &Value) -> Result<i128, Error> {
    match value {
        Value::Int(n) => Ok(*n),
        _ => Err(Error::Wasm(WasmError::ValueTypeMismatch)),
    }
}

pub fn value_as_u128(value: &Value) -> Result<u128, Error> {
    match value {
        Value::UInt(n) => Ok(*n),
        _ => Err(Error::Wasm(WasmError::ValueTypeMismatch)),
    }
}

pub fn value_as_principal(value: &Value) -> Result<&PrincipalData, Error> {
    match value {
        Value::Principal(p) => Ok(p),
        _ => Err(Error::Wasm(WasmError::ValueTypeMismatch)),
    }
}

pub fn value_as_buffer(value: Value) -> Result<BuffData, Error> {
    match value {
        Value::Sequence(SequenceData::Buffer(buffdata)) => Ok(buffdata),
        _ => Err(Error::Wasm(WasmError::ValueTypeMismatch)),
    }
}

pub fn value_as_optional(value: &Value) -> Result<&OptionalData, Error> {
    match value {
        Value::Optional(opt_data) => Ok(opt_data),
        _ => Err(Error::Wasm(WasmError::ValueTypeMismatch)),
    }
}

pub fn value_as_response(value: &Value) -> Result<&ResponseData, Error> {
    match value {
        Value::Response(res_data) => Ok(res_data),
        _ => Err(Error::Wasm(WasmError::ValueTypeMismatch)),
    }
}

pub fn value_as_string_ascii(value: Value) -> Result<ASCIIData, Error> {
    match value {
        Value::Sequence(SequenceData::String(CharType::ASCII(string_data))) => Ok(string_data),
        _ => Err(Error::Wasm(WasmError::ValueTypeMismatch)),
    }
}

pub fn value_as_tuple(value: &Value) -> Result<&TupleData, Error> {
    match value {
        Value::Tuple(d) => Ok(d),
        _ => Err(Error::Wasm(WasmError::ValueTypeMismatch)),
    }
}

pub fn value_as_list(value: &Value) -> Result<&ListData, Error> {
    match value {
        Value::Sequence(SequenceData::List(list_data)) => Ok(list_data),
        _ => Err(Error::Wasm(WasmError::ValueTypeMismatch)),
    }
}

/// Read an identifier (string) from the WASM memory at `offset` with `length`.
pub fn read_identifier_from_wasm(
    memory: Memory,
    store: &mut impl AsContextMut,
    offset: i32,
    length: i32,
) -> Result<String, Error> {
    let buffer = read_bytes_from_wasm(memory, store, offset, length)?;
    String::from_utf8(buffer).map_err(|e| Error::Wasm(WasmError::UnableToReadIdentifier(e)))
}

/// Push a placeholder value for Wasm type `ty` onto the data stack.
pub fn placeholder_for_type(ty: ValType) -> Val {
    match ty {
        ValType::I32 => Val::I32(0),
        ValType::I64 => Val::I64(0),
        ValType::F32 => Val::F32(0),
        ValType::F64 => Val::F64(0),
        ValType::V128 => Val::V128(0.into()),
        ValType::ExternRef => unimplemented!("ExternRef"),
        ValType::FuncRef => unimplemented!("FuncRef"),
    }
}
