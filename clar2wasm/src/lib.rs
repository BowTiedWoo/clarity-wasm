extern crate lazy_static;

use clarity::types::StacksEpochId;
use clarity::vm::analysis::{run_analysis, AnalysisDatabase, ContractAnalysis};
use clarity::vm::ast::{build_ast_with_diagnostics, ContractAST};
use clarity::vm::costs::{ExecutionCost, LimitedCostTracker};
use clarity::vm::diagnostic::Diagnostic;
use clarity::vm::types::QualifiedContractIdentifier;
use clarity::vm::ClarityVersion;
pub use walrus::Module;
use wasm_generator::{GeneratorError, WasmGenerator};

use crate::costs::Cost;

mod costs;
mod deserialize;
mod initialize;
mod linker;
mod serialize;
pub mod wasm_generator;
mod wasm_utils;
mod words;

#[cfg(feature = "developer-mode")]
pub mod datastore;
#[cfg(feature = "developer-mode")]
pub mod tools;

// FIXME: This is copied from stacks-blockchain
// Block limit in Stacks 2.1
pub const BLOCK_LIMIT_MAINNET_21: ExecutionCost = ExecutionCost {
    write_length: 15_000_000,
    write_count: 15_000,
    read_length: 100_000_000,
    read_count: 15_000,
    runtime: 5_000_000_000,
};

#[derive(Debug)]
pub struct CompileResult {
    pub ast: ContractAST,
    pub diagnostics: Vec<Diagnostic>,
    pub module: Module,
    pub contract_analysis: ContractAnalysis,
    pub cost: Cost,
}

#[derive(Debug)]
pub enum CompileError {
    Generic {
        ast: ContractAST,
        diagnostics: Vec<Diagnostic>,
        cost_tracker: Box<LimitedCostTracker>,
    },
}

pub fn compile(
    source: &str,
    contract_id: &QualifiedContractIdentifier,
    mut cost_tracker: LimitedCostTracker,
    clarity_version: ClarityVersion,
    epoch: StacksEpochId,
    analysis_db: &mut AnalysisDatabase,
) -> Result<CompileResult, CompileError> {
    // Parse the contract
    let (ast, mut diagnostics, success) = build_ast_with_diagnostics(
        contract_id,
        source,
        &mut cost_tracker,
        clarity_version,
        epoch,
    );

    if !success {
        return Err(CompileError::Generic {
            ast,
            diagnostics,
            cost_tracker: Box::new(cost_tracker),
        });
    }

    // Run the analysis passes
    let mut contract_analysis = match run_analysis(
        contract_id,
        &ast.expressions,
        analysis_db,
        false,
        cost_tracker,
        epoch,
        clarity_version,
    ) {
        Ok(contract_analysis) => contract_analysis,
        Err((e, cost_track)) => {
            diagnostics.push(Diagnostic::err(&e.err));
            return Err(CompileError::Generic {
                ast,
                diagnostics,
                cost_tracker: Box::new(cost_track),
            });
        }
    };

    // Now that the typechecker pass is done, we can concretize the expressions types which
    // might contain `ListUnionType` or `CallableType`
    #[allow(clippy::expect_used)]
    match contract_analysis.type_map.as_mut() {
        Some(typemap) => typemap.concretize().map_err(|e| {
            diagnostics.push(e.diagnostic);
            CompileError::Generic {
                ast: ast.clone(),
                diagnostics: diagnostics.clone(),
                cost_tracker: Box::new(
                    contract_analysis
                        .cost_track
                        .take()
                        .expect("Failed to take cost tracker from contract analysis"),
                ),
            }
        })?,
        None => unreachable!("Typechecker was called at that moment"),
    }

    #[allow(clippy::expect_used)]
    match WasmGenerator::new(contract_analysis.clone()).and_then(WasmGenerator::generate) {
        Ok((module, cost)) => Ok(CompileResult {
            ast,
            diagnostics,
            module,
            cost,
            contract_analysis,
        }),
        Err(e) => {
            diagnostics.push(Diagnostic::err(&e));
            Err(CompileError::Generic {
                ast,
                diagnostics,
                cost_tracker: Box::new(
                    contract_analysis
                        .cost_track
                        .take()
                        .expect("Failed to take cost tracker from contract analysis"),
                ),
            })
        }
    }
}

// pub fn compile_contract(contract_analysis: ContractAnalysis) -> Result<Module, GeneratorError> {
//     let generator = WasmGenerator::new(contract_analysis)?;
//     generator.generate()
// }
