use clarity::types::StacksEpochId;
use clarity::vm::errors::{CheckErrors, Error, RuntimeErrorType, ShortReturnType, WasmError};
use clarity::vm::types::ResponseData;
use clarity::vm::{ClarityVersion, Value};
use wasmtime::{AsContextMut, Instance, Trap};

use crate::wasm_utils::{
    read_from_wasm_indirect, read_identifier_from_wasm, signature_from_string,
};

const LOG2_ERROR_MESSAGE: &str = "log2 must be passed a positive integer";
const SQRTI_ERROR_MESSAGE: &str = "sqrti must be passed a positive integer";
const POW_ERROR_MESSAGE: &str = "Power argument to (pow ...) must be a u32 integer";

pub enum ErrorMap {
    NotClarityError = -1,
    ArithmeticOverflow = 0,
    ArithmeticUnderflow = 1,
    DivisionByZero = 2,
    ArithmeticLog2Error = 3,
    ArithmeticSqrtiError = 4,
    UnwrapFailure = 5,
    Panic = 6,
    ShortReturnAssertionFailure = 7,
    ArithmeticPowError = 8,
    NameAlreadyUsed = 9,
    ShortReturnExpectedValueResponse = 10,
    ShortReturnExpectedValueOptional = 11,
    ShortReturnExpectedValue = 12,
    NotMapped = 99,
}

impl From<i32> for ErrorMap {
    fn from(error_code: i32) -> Self {
        match error_code {
            -1 => ErrorMap::NotClarityError,
            0 => ErrorMap::ArithmeticOverflow,
            1 => ErrorMap::ArithmeticUnderflow,
            2 => ErrorMap::DivisionByZero,
            3 => ErrorMap::ArithmeticLog2Error,
            4 => ErrorMap::ArithmeticSqrtiError,
            5 => ErrorMap::UnwrapFailure,
            6 => ErrorMap::Panic,
            7 => ErrorMap::ShortReturnAssertionFailure,
            8 => ErrorMap::ArithmeticPowError,
            9 => ErrorMap::NameAlreadyUsed,
            10 => ErrorMap::ShortReturnExpectedValueResponse,
            11 => ErrorMap::ShortReturnExpectedValueOptional,
            12 => ErrorMap::ShortReturnExpectedValue,
            _ => ErrorMap::NotMapped,
        }
    }
}

pub(crate) fn resolve_error(
    e: wasmtime::Error,
    instance: Instance,
    mut store: impl AsContextMut,
    epoch_id: &StacksEpochId,
    clarity_version: &ClarityVersion,
) -> Error {
    if let Some(vm_error) = e.root_cause().downcast_ref::<Error>() {
        // SAFETY:
        //
        // This unsafe operation returns the value of a location pointed by `*mut T`.
        //
        // The purpose of this code is to take the ownership of the `vm_error` value
        // since clarity::vm::errors::Error is not a Clonable type.
        //
        // Converting a `&T` (vm_error) to a `*mut T` doesn't cause any issues here
        // because the reference is not borrowed elsewhere.
        //
        // The replaced `T` value is deallocated after the operation. Therefore, the chosen `T`
        // is a dummy value, solely to satisfy the signature of the replace function
        // and not cause harm when it is deallocated.
        //
        // Specifically, Error::Wasm(WasmError::ModuleNotFound) was selected as the placeholder value.
        return unsafe {
            core::ptr::replace(
                (vm_error as *const Error) as *mut Error,
                Error::Wasm(WasmError::ModuleNotFound),
            )
        };
    }

    if let Some(vm_error) = e.root_cause().downcast_ref::<CheckErrors>() {
        // SAFETY:
        //
        // This unsafe operation returns the value of a location pointed by `*mut T`.
        //
        // The purpose of this code is to take the ownership of the `vm_error` value
        // since clarity::vm::errors::Error is not a Clonable type.
        //
        // Converting a `&T` (vm_error) to a `*mut T` doesn't cause any issues here
        // because the reference is not borrowed elsewhere.
        //
        // The replaced `T` value is deallocated after the operation. Therefore, the chosen `T`
        // is a dummy value, solely to satisfy the signature of the replace function
        // and not cause harm when it is deallocated.
        //
        // Specifically, CheckErrors::ExpectedName was selected as the placeholder value.
        return unsafe {
            let err = core::ptr::replace(
                (vm_error as *const CheckErrors) as *mut CheckErrors,
                CheckErrors::ExpectedName,
            );

            <CheckErrors as std::convert::Into<Error>>::into(err)
        };
    }

    // Check if the error is caused by
    // an unreachable Wasm trap.
    //
    // In this case, runtime errors are handled
    // by being mapped to the corresponding ClarityWasm Errors.
    if let Some(Trap::UnreachableCodeReached) = e.root_cause().downcast_ref::<Trap>() {
        return from_runtime_error_code(instance, &mut store, e, epoch_id, clarity_version);
    }

    // All other errors are treated as general runtime errors.
    Error::Wasm(WasmError::Runtime(e))
}

fn from_runtime_error_code(
    instance: Instance,
    mut store: impl AsContextMut,
    e: wasmtime::Error,
    epoch_id: &StacksEpochId,
    clarity_version: &ClarityVersion,
) -> Error {
    let global = "runtime-error-code";
    let runtime_error_code = instance
        .get_global(&mut store, global)
        .and_then(|glob| glob.get(&mut store).i32())
        .unwrap_or_else(|| panic!("Could not find {global} global with i32 value"));

    match ErrorMap::from(runtime_error_code) {
        ErrorMap::NotClarityError => Error::Wasm(WasmError::Runtime(e)),
        ErrorMap::ArithmeticOverflow => {
            Error::Runtime(RuntimeErrorType::ArithmeticOverflow, Some(Vec::new()))
        }
        ErrorMap::ArithmeticUnderflow => {
            Error::Runtime(RuntimeErrorType::ArithmeticUnderflow, Some(Vec::new()))
        }
        ErrorMap::DivisionByZero => {
            Error::Runtime(RuntimeErrorType::DivisionByZero, Some(Vec::new()))
        }
        ErrorMap::ArithmeticLog2Error => Error::Runtime(
            RuntimeErrorType::Arithmetic(LOG2_ERROR_MESSAGE.into()),
            Some(Vec::new()),
        ),
        ErrorMap::ArithmeticSqrtiError => Error::Runtime(
            RuntimeErrorType::Arithmetic(SQRTI_ERROR_MESSAGE.into()),
            Some(Vec::new()),
        ),
        ErrorMap::UnwrapFailure => {
            Error::Runtime(RuntimeErrorType::UnwrapFailure, Some(Vec::new()))
        }
        ErrorMap::Panic => {
            panic!("An error has been detected in the code")
        }
        ErrorMap::ShortReturnAssertionFailure => {
            let val_offset = instance
                .get_global(&mut store, "runtime-error-value-offset")
                .and_then(|glob| glob.get(&mut store).i32())
                .unwrap_or_else(|| {
                    panic!("Could not find $runtime-error-value-offset global with i32 value")
                });

            let type_ser_offset = instance
                .get_global(&mut store, "runtime-error-type-ser-offset")
                .and_then(|glob| glob.get(&mut store).i32())
                .unwrap_or_else(|| {
                    panic!("Could not find $runtime-error-type-ser-offset global with i32 value")
                });

            let type_ser_len = instance
                .get_global(&mut store, "runtime-error-type-ser-len")
                .and_then(|glob| glob.get(&mut store).i32())
                .unwrap_or_else(|| {
                    panic!("Could not find $runtime-error-type-ser-len global with i32 value")
                });

            let memory = instance
                .get_memory(&mut store, "memory")
                .unwrap_or_else(|| panic!("Could not find wasm instance memory"));

            let type_ser_str =
                read_identifier_from_wasm(memory, &mut store, type_ser_offset, type_ser_len)
                    .unwrap_or_else(|e| panic!("Could not recover stringified type: {e}"));

            let value_ty = signature_from_string(&type_ser_str, *clarity_version, *epoch_id)
                .unwrap_or_else(|e| panic!("Could not recover thrown value: {e}"));

            let clarity_val =
                read_from_wasm_indirect(memory, &mut store, &value_ty, val_offset, *epoch_id)
                    .unwrap_or_else(|e| panic!("Could not read thrown value from memory: {e}"));

            Error::ShortReturn(ShortReturnType::AssertionFailed(clarity_val))
        }
        ErrorMap::ArithmeticPowError => Error::Runtime(
            RuntimeErrorType::Arithmetic(POW_ERROR_MESSAGE.into()),
            Some(Vec::new()),
        ),
        ErrorMap::NameAlreadyUsed => {
            let runtime_error_arg_offset = instance
                .get_global(&mut store, "runtime-error-arg-offset")
                .and_then(|glob| glob.get(&mut store).i32())
                .unwrap_or_else(|| {
                    panic!("Could not find $runtime-error-arg-offset global with i32 value")
                });

            let runtime_error_arg_len = instance
                .get_global(&mut store, "runtime-error-arg-len")
                .and_then(|glob| glob.get(&mut store).i32())
                .unwrap_or_else(|| {
                    panic!("Could not find $runtime-error-arg-len global with i32 value")
                });

            let memory = instance
                .get_memory(&mut store, "memory")
                .unwrap_or_else(|| panic!("Could not find wasm instance memory"));
            let arg_name = read_identifier_from_wasm(
                memory,
                &mut store,
                runtime_error_arg_offset,
                runtime_error_arg_len,
            )
            .unwrap_or_else(|e| panic!("Could not recover arg_name: {e}"));

            Error::Unchecked(CheckErrors::NameAlreadyUsed(arg_name))
        }
        ErrorMap::ShortReturnExpectedValueResponse => {
            let val_offset = instance
                .get_global(&mut store, "runtime-error-value-offset")
                .and_then(|glob| glob.get(&mut store).i32())
                .unwrap_or_else(|| {
                    panic!("Could not find $runtime-error-value-offset global with i32 value")
                });

            let type_ser_offset = instance
                .get_global(&mut store, "runtime-error-type-ser-offset")
                .and_then(|glob| glob.get(&mut store).i32())
                .unwrap_or_else(|| {
                    panic!("Could not find $runtime-error-type-ser-offset global with i32 value")
                });

            let type_ser_len = instance
                .get_global(&mut store, "runtime-error-type-ser-len")
                .and_then(|glob| glob.get(&mut store).i32())
                .unwrap_or_else(|| {
                    panic!("Could not find $runtime-error-type-ser-len global with i32 value")
                });

            let memory = instance
                .get_memory(&mut store, "memory")
                .unwrap_or_else(|| panic!("Could not find wasm instance memory"));

            let type_ser_str =
                read_identifier_from_wasm(memory, &mut store, type_ser_offset, type_ser_len)
                    .unwrap_or_else(|e| panic!("Could not recover stringified type: {e}"));

            let value_ty = signature_from_string(&type_ser_str, *clarity_version, *epoch_id)
                .unwrap_or_else(|e| panic!("Could not recover thrown value: {e}"));

            let clarity_val =
                read_from_wasm_indirect(memory, &mut store, &value_ty, val_offset, *epoch_id)
                    .unwrap_or_else(|e| panic!("Could not read thrown value from memory: {e}"));

            Error::ShortReturn(ShortReturnType::ExpectedValue(Value::Response(
                ResponseData {
                    committed: false,
                    data: Box::new(clarity_val),
                },
            )))
        }
        ErrorMap::ShortReturnExpectedValueOptional => {
            Error::ShortReturn(ShortReturnType::ExpectedValue(Value::Optional(
                clarity::vm::types::OptionalData { data: None },
            )))
        }
        ErrorMap::ShortReturnExpectedValue => {
            let val_offset = instance
                .get_global(&mut store, "runtime-error-value-offset")
                .and_then(|glob| glob.get(&mut store).i32())
                .unwrap_or_else(|| {
                    panic!("Could not find $runtime-error-value-offset global with i32 value")
                });

            let type_ser_offset = instance
                .get_global(&mut store, "runtime-error-type-ser-offset")
                .and_then(|glob| glob.get(&mut store).i32())
                .unwrap_or_else(|| {
                    panic!("Could not find $runtime-error-type-ser-offset global with i32 value")
                });

            let type_ser_len = instance
                .get_global(&mut store, "runtime-error-type-ser-len")
                .and_then(|glob| glob.get(&mut store).i32())
                .unwrap_or_else(|| {
                    panic!("Could not find $runtime-error-type-ser-len global with i32 value")
                });

            let memory = instance
                .get_memory(&mut store, "memory")
                .unwrap_or_else(|| panic!("Could not find wasm instance memory"));

            let type_ser_str =
                read_identifier_from_wasm(memory, &mut store, type_ser_offset, type_ser_len)
                    .unwrap_or_else(|e| panic!("Could not recover stringified type: {e}"));

            let value_ty = signature_from_string(&type_ser_str, *clarity_version, *epoch_id)
                .unwrap_or_else(|e| panic!("Could not recover thrown value: {e}"));

            let clarity_val =
                read_from_wasm_indirect(memory, &mut store, &value_ty, val_offset, *epoch_id)
                    .unwrap_or_else(|e| panic!("Could not read thrown value from memory: {e}"));

            Error::ShortReturn(ShortReturnType::ExpectedValue(clarity_val))
        }
        _ => panic!("Runtime error code {} not supported", runtime_error_code),
    }
}
