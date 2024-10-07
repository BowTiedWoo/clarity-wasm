use clarity::types::StacksEpochId;
use clarity::vm::errors::{CheckErrors, Error, RuntimeErrorType, ShortReturnType, WasmError};
use clarity::vm::types::{OptionalData, ResponseData};
use clarity::vm::{ClarityVersion, Value};
use wasmtime::{AsContextMut, Instance, Memory, Trap};

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
        return from_runtime_error_code(&instance, &mut store, e, epoch_id, clarity_version);
    }

    // All other errors are treated as general runtime errors.
    Error::Wasm(WasmError::Runtime(e))
}

/// Converts a runtime error code from WebAssembly execution into a Clarity `Error`.
///
/// This function interprets the runtime error code stored in the WebAssembly instance's global
/// variables and converts it into an appropriate Clarity `Error` type. It handles various error
/// scenarios including arithmetic errors, short returns, and other runtime issues.
///
/// # Arguments
///
/// * `instance` - A reference to the WebAssembly `Instance` that encountered the error.
/// * `store` - A mutable reference to the WebAssembly store, which provides access to runtime data.
/// * `e` - The original `wasmtime::Error` that triggered this error handling.
/// * `epoch_id` - A reference to the current `StacksEpochId`, used for epoch-specific behavior.
/// * `clarity_version` - A reference to the `ClarityVersion` in use, for version-specific handling.
///
/// # Returns
///
/// Returns a Clarity `Error` that corresponds to the runtime error encountered during WebAssembly execution.
///
/// # Panics
///
/// This function will panic in the following scenarios:
/// - If it encounters an unsupported runtime error code.
/// - If it fails to retrieve expected global variables or memory from the WebAssembly instance.
/// - If it encounters an `ErrorMap::Panic` variant.
///
fn from_runtime_error_code(
    instance: &Instance,
    mut store: impl AsContextMut,
    e: wasmtime::Error,
    epoch_id: &StacksEpochId,
    clarity_version: &ClarityVersion,
) -> Error {
    let runtime_error_code = get_global_i32(instance, &mut store, "runtime-error-code");

    match ErrorMap::from(runtime_error_code) {
        ErrorMap::NotClarityError => Error::Wasm(WasmError::Runtime(e)),
        ErrorMap::ArithmeticOverflow => create_runtime_error(RuntimeErrorType::ArithmeticOverflow),
        ErrorMap::ArithmeticUnderflow => {
            create_runtime_error(RuntimeErrorType::ArithmeticUnderflow)
        }
        ErrorMap::DivisionByZero => create_runtime_error(RuntimeErrorType::DivisionByZero),
        ErrorMap::ArithmeticLog2Error => {
            create_runtime_error(RuntimeErrorType::Arithmetic(LOG2_ERROR_MESSAGE.into()))
        }
        ErrorMap::ArithmeticSqrtiError => {
            create_runtime_error(RuntimeErrorType::Arithmetic(SQRTI_ERROR_MESSAGE.into()))
        }
        ErrorMap::UnwrapFailure => create_runtime_error(RuntimeErrorType::UnwrapFailure),
        ErrorMap::ArithmeticPowError => {
            create_runtime_error(RuntimeErrorType::Arithmetic(POW_ERROR_MESSAGE.into()))
        }
        ErrorMap::NameAlreadyUsed => handle_name_already_used(instance, &mut store),
        ErrorMap::ShortReturnExpectedValue => handle_short_return(
            instance,
            &mut store,
            epoch_id,
            clarity_version,
            ShortReturnType::ExpectedValue,
        ),
        ErrorMap::ShortReturnAssertionFailure => handle_short_return(
            instance,
            &mut store,
            epoch_id,
            clarity_version,
            ShortReturnType::AssertionFailed,
        ),
        ErrorMap::ShortReturnExpectedValueResponse => {
            handle_short_return_response(instance, &mut store, epoch_id, clarity_version)
        }
        ErrorMap::ShortReturnExpectedValueOptional => Error::ShortReturn(
            ShortReturnType::ExpectedValue(Value::Optional(OptionalData { data: None })),
        ),
        ErrorMap::Panic => panic!("An error has been detected in the code"),
        _ => panic!("Runtime error code {} not supported", runtime_error_code),
    }
}

fn get_global_i32(instance: &Instance, store: &mut impl AsContextMut, name: &str) -> i32 {
    instance
        .get_global(&mut *store, name)
        .and_then(|glob| glob.get(store).i32())
        .unwrap_or_else(|| panic!("Could not find ${} global with i32 value", name))
}

fn create_runtime_error(error_type: RuntimeErrorType) -> Error {
    Error::Runtime(error_type, Some(Vec::new()))
}

fn handle_name_already_used(instance: &Instance, store: &mut impl AsContextMut) -> Error {
    let offset = get_global_i32(instance, store, "runtime-error-arg-offset");
    let len = get_global_i32(instance, store, "runtime-error-arg-len");
    let memory = get_memory(instance, store);
    let arg_name = read_identifier_from_wasm(memory, store, offset, len)
        .unwrap_or_else(|e| panic!("Could not recover arg_name: {}", e));
    Error::Unchecked(CheckErrors::NameAlreadyUsed(arg_name))
}

fn handle_short_return(
    instance: &Instance,
    store: &mut impl AsContextMut,
    epoch_id: &StacksEpochId,
    clarity_version: &ClarityVersion,
    return_type: fn(Value) -> ShortReturnType,
) -> Error {
    let val_offset = get_global_i32(instance, store, "runtime-error-value-offset");
    let type_ser_offset = get_global_i32(instance, store, "runtime-error-type-ser-offset");
    let type_ser_len = get_global_i32(instance, store, "runtime-error-type-ser-len");
    let memory = get_memory(instance, store);

    let type_ser_str = read_identifier_from_wasm(memory, store, type_ser_offset, type_ser_len)
        .unwrap_or_else(|e| panic!("Could not recover stringified type: {}", e));

    let value_ty = signature_from_string(&type_ser_str, *clarity_version, *epoch_id)
        .unwrap_or_else(|e| panic!("Could not recover thrown value: {}", e));

    let clarity_val = read_from_wasm_indirect(memory, store, &value_ty, val_offset, *epoch_id)
        .unwrap_or_else(|e| panic!("Could not read thrown value from memory: {}", e));

    Error::ShortReturn(return_type(clarity_val))
}

fn handle_short_return_response(
    instance: &Instance,
    store: &mut impl AsContextMut,
    epoch_id: &StacksEpochId,
    clarity_version: &ClarityVersion,
) -> Error {
    let clarity_val = handle_short_return(
        instance,
        store,
        epoch_id,
        clarity_version,
        ShortReturnType::ExpectedValue,
    );
    if let Error::ShortReturn(ShortReturnType::ExpectedValue(val)) = clarity_val {
        Error::ShortReturn(ShortReturnType::ExpectedValue(Value::Response(
            ResponseData {
                committed: false,
                data: Box::new(val),
            },
        )))
    } else {
        panic!("Unexpected error type in handle_short_return_response")
    }
}

fn get_memory(instance: &Instance, store: &mut impl AsContextMut) -> Memory {
    instance
        .get_memory(store, "memory")
        .unwrap_or_else(|| panic!("Could not find wasm instance memory"))
}
