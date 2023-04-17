//! Invalid transaction proof.

use crate::domain_extrinsics_builder::BuildDomainExtrinsics;
use codec::{Decode, Encode};
use domain_block_preprocessor::runtime_api_light::RuntimeApiLight;
use domain_runtime_primitives::DomainCoreApi;
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_core::traits::CodeExecutor;
use sp_core::H256;
use sp_domains::fraud_proof::{InvalidTransactionProof, VerificationError};
use sp_domains::{DomainId, ExecutorApi};
use sp_runtime::traits::{BlakeTwo256, Block as BlockT, Header as HeaderT};
use sp_runtime::{OpaqueExtrinsic, Storage};
use sp_trie::{read_trie_value, LayoutV1};
use std::marker::PhantomData;
use std::sync::Arc;

// TODO: refactor `VerifyPrePostStateRoot` in invalid_state_transition_proof?
/// Get primary block hash.
pub trait GetPrimaryHash {
    /// Returns the hash of primary block corresponding to `domain_id` and `domain_block_number`.
    fn primary_hash(
        &self,
        domain_id: DomainId,
        domain_block_number: u32,
    ) -> Result<H256, VerificationError>;
}

/// Invalid transaction proof verifier.
pub struct InvalidTransactionProofVerifier<
    PBlock,
    Client,
    Hash,
    Exec,
    PrimaryHashProvider,
    DomainExtrinsicsBuilder,
> {
    client: Arc<Client>,
    executor: Arc<Exec>,
    primary_hash_provider: PrimaryHashProvider,
    domain_extrinsics_builder: DomainExtrinsicsBuilder,
    _phantom: PhantomData<(PBlock, Hash)>,
}

impl<PBlock, Client, Hash, Exec, PrimaryHashProvider, DomainExtrinsicsBuilder> Clone
    for InvalidTransactionProofVerifier<
        PBlock,
        Client,
        Hash,
        Exec,
        PrimaryHashProvider,
        DomainExtrinsicsBuilder,
    >
where
    PrimaryHashProvider: Clone,
    DomainExtrinsicsBuilder: Clone,
{
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
            executor: self.executor.clone(),
            primary_hash_provider: self.primary_hash_provider.clone(),
            domain_extrinsics_builder: self.domain_extrinsics_builder.clone(),
            _phantom: self._phantom,
        }
    }
}

impl<PBlock, Client, Hash, Exec, PrimaryHashProvider, DomainExtrinsicsBuilder>
    InvalidTransactionProofVerifier<
        PBlock,
        Client,
        Hash,
        Exec,
        PrimaryHashProvider,
        DomainExtrinsicsBuilder,
    >
where
    PBlock: BlockT,
    Hash: Encode + Decode,
    H256: Into<PBlock::Hash>,
    Client: HeaderBackend<PBlock> + ProvideRuntimeApi<PBlock> + Send + Sync,
    Client::Api: ExecutorApi<PBlock, Hash>,
    PrimaryHashProvider: GetPrimaryHash,
    DomainExtrinsicsBuilder: BuildDomainExtrinsics<PBlock>,
    Exec: CodeExecutor + 'static,
{
    /// Constructs a new instance of [`InvalidStateTransitionProofVerifier`].
    pub fn new(
        client: Arc<Client>,
        executor: Arc<Exec>,
        primary_hash_provider: PrimaryHashProvider,
        domain_extrinsics_builder: DomainExtrinsicsBuilder,
    ) -> Self {
        Self {
            client,
            executor,
            primary_hash_provider,
            domain_extrinsics_builder,
            _phantom: Default::default(),
        }
    }

    /// Verifies the invalid state transition proof.
    pub fn verify(
        &self,
        invalid_transaction_proof: &InvalidTransactionProof,
    ) -> Result<(), VerificationError> {
        let InvalidTransactionProof {
            domain_id,
            block_number,
            extrinsic_index,
            storage_proof,
        } = invalid_transaction_proof;

        let primary_hash: PBlock::Hash = self
            .primary_hash_provider
            .primary_hash(*domain_id, *block_number)?
            .into();

        let header = self.client.header(primary_hash)?.ok_or_else(|| {
            sp_blockchain::Error::Backend(format!("Header for {primary_hash} not found"))
        })?;
        let primary_hash = header.hash();
        let primary_parent_hash = *header.parent_hash();

        let domain_runtime_code = crate::domain_runtime_code::retrieve_domain_runtime_code(
            *domain_id,
            primary_parent_hash,
            &self.client,
        )?;

        let domain_extrinsics = self
            .domain_extrinsics_builder
            .build_domain_extrinsics(
                *domain_id,
                primary_hash,
                domain_runtime_code.wasm_bundle.to_vec(),
            )
            .map_err(|_| VerificationError::FailedToBuildDomainExtrinsics)?;

        let extrinsic = domain_extrinsics
            .into_iter()
            .nth(*extrinsic_index as usize)
            .ok_or(VerificationError::DomainExtrinsicNotFound(*extrinsic_index))?;

        // TODO: convert StorageProof into Storage
        let db = storage_proof.clone().into_memory_db::<BlakeTwo256>();
        let state_root = H256::default();
        let read_value = |storage_key| {
            read_trie_value::<LayoutV1<BlakeTwo256>, _>(&db, &state_root, storage_key, None, None)
                .map_err(|_| VerificationError::InvalidStorageProof)
        };

        let next_fee_multiplier_storage_key = b"stoage key".to_vec();
        let next_fee_multiplier_value = read_value(&next_fee_multiplier_storage_key)?;

        let balance_storage_key = b"storage key".to_vec();
        let balance_value = read_value(&balance_storage_key)?;

        // let storage = Storage {
        // top: [
        // (
        // next_fee_multiplier_storage_key,
        // next_fee_multiplier_value.encode(),
        // ),
        // (balance_storage_key, balance_value.encode()),
        // ]
        // .into_iter()
        // .collect(),
        // children_default: Default::default(),
        // };

        let mut storage = Storage::default();
        sp_state_machine::BasicExternalities::execute_with_storage(&mut storage, || {
            // TODO: use default value when it's None?
            if let Some(value) = next_fee_multiplier_value {
                sp_io::storage::set(&next_fee_multiplier_storage_key, &value);
            }
            if let Some(value) = balance_value {
                sp_io::storage::set(&balance_storage_key, &value);
            }
            Ok::<(), sp_blockchain::Error>(())
        })?;

        let runtime_api_light = RuntimeApiLight::new(
            self.executor.clone(),
            domain_runtime_code.wasm_bundle,
            Some(storage),
        );

        let check_result = <RuntimeApiLight<Exec> as DomainCoreApi<
            domain_runtime_primitives::opaque::Block,
            domain_runtime_primitives::AccountId,
            domain_runtime_primitives::Balance,
        >>::check_transaction_fee(
            &runtime_api_light,
            Default::default(),
            OpaqueExtrinsic::from_bytes(&extrinsic)?,
        )?;

        if check_result.is_ok() {
            Err(VerificationError::SufficientBalance)
        } else {
            Ok(())
        }
    }
}
