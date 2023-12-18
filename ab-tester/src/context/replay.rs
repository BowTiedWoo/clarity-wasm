use blockstack_lib::chainstate::stacks::TransactionPayload;
use ::clarity::vm::ast::ASTRules;
use ::clarity::vm::{ContractContext, ClarityVersion};
use ::clarity::vm::clarity::TransactionConnection;
use ::clarity::vm::types::{QualifiedContractIdentifier, PrincipalData, StandardPrincipalData};
use color_eyre::eyre::ensure;
use color_eyre::Result;
use log::*;
use stacks_common::types::StacksEpochId;

use super::BlockContext;
use super::callbacks::ReplayCallbackHandler;
use crate::context::Block;
use crate::environments::{ReadableEnv, WriteableEnv};
use crate::errors::AppError;
use crate::types::BlockHeader;
use crate::{ok, stacks};

/// Options for replaying an environment's chain into another environment.
pub struct ReplayOpts<C>
where
    C: ReplayCallbackHandler,
{
    pub from_height: Option<u32>,
    pub to_height: Option<u32>,
    pub max_blocks: Option<u32>,
    pub callbacks: C,
    pub working_dir: String,
}

impl<C> Default for ReplayOpts<C>
where
    C: ReplayCallbackHandler + Default,
{
    fn default() -> Self {
        Self {
            from_height: Default::default(),
            to_height: Default::default(),
            max_blocks: Default::default(),
            callbacks: C::default(),
            working_dir: Default::default(),
        }
    }
}

/// Validation/assertion helper methods for [ReplayOpts].
impl<C: ReplayCallbackHandler> ReplayOpts<C> {
    pub fn with_working_dir(&mut self, working_dir: &str) -> &mut Self {
        self.working_dir = working_dir.to_string();
        self
    }
    pub fn with_callbacks(&mut self, callbacks: C) -> &mut Self {
        self.callbacks = callbacks;
        self
    }

    pub fn build(self) -> Self {
        self
    }

    /// Asserts that the current `processeed_block_count` hasn't exceedeed the
    /// provided block count parameter.
    pub fn assert_max_processed_block_count(&self, processed_block_count: u32) -> Result<()> {
        if let Some(max_blocks) = self.max_blocks {
            ensure!(
                processed_block_count < max_blocks,
                AppError::Graceful("number of blocks processed has reached the specified maximum")
            );
        }

        ok!()
    }

    /// Asserts that the provided block height doesn't exceed the max block height,
    /// if provided.
    pub fn assert_block_height_under_max_height(&self, block_height: u32) -> Result<()> {
        if let Some(to_height) = self.to_height {
            ensure!(
                block_height <= to_height,
                AppError::Graceful(
                    "block height has reached the specified maximum block height (to-height)"
                )
            )
        }

        ok!()
    }
}

/// Provides methods for replaying a [ReadableEnv] into a [WriteableEnv].
pub struct ChainStateReplayer {}

impl ChainStateReplayer {
    pub fn replay<'a, C: ReplayCallbackHandler>(
        source: &'a (impl ReadableEnv + ?Sized),
        target: &'a mut (impl WriteableEnv + ?Sized),
        opts: &ReplayOpts<C>,
    ) -> Result<()> {
        info!(
            "aggregating contract calls starting at block height {}...",
            opts.from_height.unwrap_or(0)
        );

        let mut processed_block_count = 0;

        let blocks = source.blocks()?;
        opts.callbacks.replay_start(source, target, blocks.len());

        for block in source.blocks()?.into_iter() {
            opts.callbacks
                .replay_block_start(source, target, block.block_height()?);

            let (header, stacks_block) = match &block {
                Block::Genesis(inner) => {
                    // We can't process genesis (doesn't exist in chainstate), so skip it.
                    //info!("genesis block - skipping '{:?}'", gen.index_block_hash);
                    //continue;
                    info!("genesis block: '{:?}'", inner.header.index_block_hash);
                    (inner.header.clone(), None)
                }
                Block::Regular(inner) => (inner.header.clone(), Some(inner.stacks_block.clone())),
            };

            // Ensure that we've reached the specified block-height before beginning
            // processing.
            if header.block_height < opts.from_height.unwrap_or(0) {
                continue;
            }

            // Ensure that we haven't exceeded the specified max-blocks for processing.
            opts.assert_max_processed_block_count(processed_block_count)?;

            // Ensure that we haven't reached the specified max block-height for processing.
            opts.assert_block_height_under_max_height(header.block_height)?;

            if let Some(stacks_block) = stacks_block {
                info!(
                    "processing REGULAR block #{} ({})",
                    header.block_height,
                    hex::encode(header.index_block_hash)
                );

                // Now we have ensured that we are not in genesis and that the
                // StacksBlock could be retrieved. Replay the block into `target`.
                Self::replay_block_into(&header, &block, &stacks_block, target)?;
            } else {
                info!(
                    "processing GENESIS block #{} ({})",
                    header.block_height,
                    hex::encode(header.index_block_hash)
                );

                info!("beginning genesis block in target");
                target.block_begin(&block)?;
            }

            opts.callbacks.replay_block_finish(source, target);
            processed_block_count += 1;
        }

        opts.callbacks.replay_finish(source, target);
        info!("blocks processed: {processed_block_count}");

        ok!()
    }

    /// Replays the specified block into `target`.
    fn replay_block_into<'a, Target: WriteableEnv + ?Sized + 'a>(
        _header: &BlockHeader,
        block: &Block,
        stacks_block: &stacks::StacksBlock,
        target: &'a mut Target,
    ) -> Result<()> {
        //let block_id = header.index_block_hash;
        debug!("beginning block in target");
        let block_tx = target.block_begin(block)?;

        // Begin a new block in `target`.
        match block_tx {
            BlockContext::Regular(ctx) => {
                debug!("beginning chainstate transaction/clarity tx");
                let mut clarity_tx = ctx.chainstate.block_begin(
                    ctx.burn_db,
                    &ctx.parent_consensus_hash,
                    &ctx.parent_block_hash,
                    &ctx.new_consensus_hash,
                    &ctx.new_block_hash,
                );

                debug!("fetching clarity block connection");
                let block_conn = clarity_tx.connection();

                for block_tx in stacks_block.txs.iter() {
                    // If a sponsor has been provided, convert it to a `PrincipalData`.
                    let sponsor_addr = block_tx.sponsor_address()
                        .map(|addr| PrincipalData::Standard(StandardPrincipalData::from(addr)));
                    if sponsor_addr.is_some() {
                        debug!("a sponsor address has been provided: {:?}", &sponsor_addr);
                    }
                    
                    match &block_tx.payload {
                        TransactionPayload::SmartContract(ref contract, clarity_version) => {
                            // Use the provided Clarity version, if supplied, otherwise use latest.
                            let clarity_version = clarity_version
                                .unwrap_or(ClarityVersion::latest());
                                
                            // Construct a `QualifiedContractIdentifier` from the contract details.
                            let contract_id = QualifiedContractIdentifier::new(
                                block_tx.origin_address().into(), 
                                contract.name.clone());

                            info!("installing contract: {}", &contract_id);

                            // If a sponsor has been provided, convert it to a `PrincipalData`.
                            let sponsor_addr = block_tx.sponsor_address()
                                .map(|addr| PrincipalData::Standard(StandardPrincipalData::from(addr)));
                            if sponsor_addr.is_some() {
                                debug!("a sponsor address has been provided: {:?}", &sponsor_addr);
                            }

                            // Begin a new Clarity transaction in `target` and process the
                            // source transaction.
                            block_conn.as_transaction(|tx| {
                                // Perform a contract analysis so that we can get ahold of the
                                // contract's parsed AST, which is needed for the install/init
                                // phase below.
                                debug!("performing contract analysis");
                                let (contract_ast, _contract_analysis) = tx.analyze_smart_contract(
                                    &contract_id, 
                                    clarity_version, 
                                    &contract.code_body.to_string(),
                                    ASTRules::PrecheckSize
                                ).expect("failed to analyze smart contract");

                                // Initialize the smart contract.
                                debug!("initializing smart contract");
                                tx.initialize_smart_contract(
                                    &contract_id, 
                                    clarity_version, 
                                    &contract_ast, 
                                    &contract.code_body.to_string(), 
                                    sponsor_addr, 
                                    |assets, _db| {
                                        warn!("entered abort callback");
                                        warn!("assets: {:?}", assets);
                                        false
                                    }).expect("failed to initialize smart contract");

                                debug!("contract initialized");
                            });
                        },
                        TransactionPayload::ContractCall(call) => {
                            info!("contract call");
                                
                            // Construct a `QualifiedContractIdentifier` from the contract details.
                            let contract_id = call.to_clarity_contract_id();

                            let sender_addr = PrincipalData::Standard(
                                StandardPrincipalData::from(block_tx.origin_address()));

                            // Begin a new Clarity transaction in `target` and process the
                            // source transaction.
                            block_conn.as_transaction(|tx| {
                                tx.run_contract_call(
                                    &sender_addr,
                                    sponsor_addr.as_ref(), 
                                    &contract_id, 
                                    &call.function_name, 
                                    &call.function_args, 
                                    |assets, db| {
                                        warn!("entered abort callback");
                                        warn!("assets: {:?}", assets);
                                        false
                                    }
                                ).expect("failed to execute contract call");
                            });
                        },
                        TransactionPayload::Coinbase(_coinbase, _principal) => {
                            warn!("coinbase");
                        },
                        TransactionPayload::TokenTransfer(_address, _stx , _memo) => {
                            warn!("token transfer");
                        },
                        TransactionPayload::PoisonMicroblock(_, _) => {
                            warn!("poison microblock");
                        }
                        
                    }
                }

                clarity_tx.commit_to_block(&ctx.new_consensus_hash, &ctx.new_block_hash);
            },
            BlockContext::Genesis => {},
        }

        Ok(())
    }
}

pub struct ReplayResult {}

impl ReplayResult {
    pub fn do_nothing(&self) {}
}




/*
for tx in stacks_block.txs.iter() {
                    
                
                    info!("processing tx: {}", tx.txid());

                    //let origin_principal = clarity::StandardPrincipalData::from(tx.origin_address());

                    // Begin a new Clarity transaction in `target` and process the source
                    // transaction. This transaction will be automatically committed.
                    block_ctx
                        .clarity_block_conn
                        .as_transaction(|_clarity_tx| -> Result<()> {
                            debug!("IN PROCESS TX SCOPE");

                            #[allow(clippy::single_match)]
                            match &tx.payload {
                                stacks::TransactionPayload::ContractCall(call) => {
                                    let contract_id = clarity::QualifiedContractIdentifier::parse(
                                        &format!("{}.{}", call.address, call.contract_name),
                                    )?;
                                    info!(
                                        "contract call at block id: {block_id:?}, contract id: {}",
                                        contract_id.to_string()
                                    );
                                }
                                stacks::TransactionPayload::SmartContract(contract, _) => {
                                    let contract_id = clarity::QualifiedContractIdentifier::new(
                                        origin_principal,
                                        contract.name.clone(),
                                    );

                                    info!(
                                        "install contract at block id: {block_id:?}, contract id: {}",
                                        contract_id.to_string()
                                    );
                                }
                                _ => {}
                            }

                            ok!()
                        })?;
 }                   */