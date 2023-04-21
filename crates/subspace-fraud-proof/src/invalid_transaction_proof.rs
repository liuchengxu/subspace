//! Invalid transaction proof.

use crate::domain_extrinsics_builder::BuildDomainExtrinsics;
use codec::{Decode, Encode};
use domain_block_preprocessor::runtime_api_light::RuntimeApiLight;
use domain_runtime_primitives::opaque::Block;
use domain_runtime_primitives::{AccountId, Balance, DomainCoreApi, Index};
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_core::traits::CodeExecutor;
use sp_core::H256;
use sp_domains::fraud_proof::{InvalidTransactionProof, VerificationError};
use sp_domains::{DomainId, ExecutorApi};
use sp_receipts::ReceiptsApi;
use sp_runtime::traits::{BlakeTwo256, Block as BlockT, Header as HeaderT, NumberFor};
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

    // TODO: retrieve from ReceiptsApi
    fn state_root(
        &self,
        domain_id: DomainId,
        domain_block_number: u32,
        domain_block_hash: H256,
    ) -> Result<domain_runtime_primitives::Hash, VerificationError>;
}

/// Verifier of `pre_state_root` in [`InvalidStateTransitionProof`].
pub struct ParentChainClient<Block, Client> {
    client: Arc<Client>,
    _phantom: PhantomData<Block>,
}

impl<Block, Client> Clone for ParentChainClient<Block, Client> {
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
            _phantom: self._phantom,
        }
    }
}

impl<Block, Client> ParentChainClient<Block, Client> {
    /// Constructs a new instance of [`ParentChainClient`].
    pub fn new(client: Arc<Client>) -> Self {
        Self {
            client,
            _phantom: Default::default(),
        }
    }
}

impl<Block, Client> GetPrimaryHash for ParentChainClient<Block, Client>
where
    Block: BlockT,
    Client: ProvideRuntimeApi<Block> + HeaderBackend<Block>,
    Client::Api: ReceiptsApi<Block, domain_runtime_primitives::Hash>,
{
    fn primary_hash(
        &self,
        domain_id: DomainId,
        domain_block_number: u32,
    ) -> Result<H256, VerificationError> {
        self.client
            .runtime_api()
            .primary_hash(
                self.client.info().best_hash,
                domain_id,
                domain_block_number.into(),
            )?
            .and_then(|primary_hash| Decode::decode(&mut primary_hash.encode().as_slice()).ok())
            .ok_or(VerificationError::PrimaryHashNotFound)
    }

    fn state_root(
        &self,
        domain_id: DomainId,
        domain_block_number: u32,
        domain_block_hash: H256,
    ) -> Result<domain_runtime_primitives::Hash, VerificationError> {
        self.client
            .runtime_api()
            .state_root(
                self.client.info().best_hash,
                domain_id,
                NumberFor::<Block>::from(domain_block_number),
                Block::Hash::decode(&mut domain_block_hash.encode().as_slice())?,
            )?
            .ok_or(VerificationError::DomainStateRootNotFound)
    }
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

struct AccountStorageInstance;

impl frame_support::traits::StorageInstance for AccountStorageInstance {
    fn pallet_prefix() -> &'static str {
        "System"
    }
    const STORAGE_PREFIX: &'static str = "Account";
}

type AccountInfo = frame_system::AccountInfo<Index, pallet_balances::AccountData<Balance>>;

type AccountStorageMap = frame_support::storage::types::StorageMap<
    AccountStorageInstance,
    frame_support::Blake2_128Concat,
    AccountId,
    AccountInfo,
>;

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
            domain_block_hash,
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
        let state_root = self
            .primary_hash_provider
            .state_root(*domain_id, *block_number, *domain_block_hash)
            .expect("Can not fetch state root");

        let db = storage_proof.clone().into_memory_db::<BlakeTwo256>();
        let read_value = |storage_key| {
            read_trie_value::<LayoutV1<BlakeTwo256>, _>(&db, &state_root, storage_key, None, None)
                .map_err(|_| VerificationError::InvalidStorageProof)
        };

        // <NextFeeMultiplier<Runtime>>::hashed_key()
        let next_fee_multiplier_storage_key = [
            63, 20, 103, 160, 150, 188, 215, 26, 91, 106, 12, 129, 85, 226, 8, 16, 63, 46, 223, 59,
            223, 56, 29, 235, 227, 49, 171, 116, 70, 173, 223, 220,
        ];
        let next_fee_multiplier_value = read_value(&next_fee_multiplier_storage_key)?;

        // let mut storage = Storage::default();
        // sp_state_machine::BasicExternalities::execute_with_storage(&mut storage, || {
        // // TODO: use default value when it's None?
        // if let Some(value) = next_fee_multiplier_value {
        // sp_io::storage::set(&next_fee_multiplier_storage_key, &value);
        // }
        // if let Some(value) = balance_value {
        // sp_io::storage::set(&balance_storage_key, &value);
        // }
        // Ok::<(), sp_blockchain::Error>(())
        // })?;

        let mut runtime_api_light =
            RuntimeApiLight::new(self.executor.clone(), domain_runtime_code.wasm_bundle);

        let sender =
            <RuntimeApiLight<Exec> as DomainCoreApi<Block, AccountId, Balance>>::extract_signer(
                &runtime_api_light,
                Default::default(),
                vec![OpaqueExtrinsic::from_bytes(&extrinsic)?],
            )?
            .into_iter()
            .next()
            .and_then(|(maybe_signer, _)| maybe_signer)
            .ok_or(VerificationError::SignerNotFound)?;

        let account_storage_key = AccountStorageMap::hashed_key_for(sender);
        let account_value = read_value(&account_storage_key)?;

        let storage = Storage {
            top: [
                (
                    next_fee_multiplier_storage_key.to_vec(),
                    next_fee_multiplier_value.encode(),
                ),
                (account_storage_key, account_value.encode()),
            ]
            .into_iter()
            .collect(),
            children_default: Default::default(),
        };

        runtime_api_light.set_storage(storage);

        let check_result = <RuntimeApiLight<Exec> as DomainCoreApi<
            Block,
            AccountId,
            Balance,
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

    /// Verifies the invalid state transition proof.
    #[cfg(test)]
    pub fn verify_with_extrinsic(
        &self,
        extrinsic: Vec<u8>,
        invalid_transaction_proof: &InvalidTransactionProof,
    ) -> Result<(), VerificationError> {
        let InvalidTransactionProof {
            domain_id,
            block_number,
            domain_block_hash,
            extrinsic_index: _,
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

        // TODO: convert StorageProof into Storage
        let state_root = self
            .primary_hash_provider
            .state_root(*domain_id, *block_number, *domain_block_hash)
            .expect("Can not fetch state root");

        let db = storage_proof.clone().into_memory_db::<BlakeTwo256>();
        let read_value = |storage_key| {
            read_trie_value::<LayoutV1<BlakeTwo256>, _>(&db, &state_root, storage_key, None, None)
                .map_err(|_| VerificationError::InvalidStorageProof)
        };

        // <NextFeeMultiplier<Runtime>>::hashed_key()
        let next_fee_multiplier_storage_key = [
            63, 20, 103, 160, 150, 188, 215, 26, 91, 106, 12, 129, 85, 226, 8, 16, 63, 46, 223, 59,
            223, 56, 29, 235, 227, 49, 171, 116, 70, 173, 223, 220,
        ];
        let next_fee_multiplier_value = read_value(&next_fee_multiplier_storage_key)?;

        // let mut storage = Storage::default();
        // sp_state_machine::BasicExternalities::execute_with_storage(&mut storage, || {
        // // TODO: use default value when it's None?
        // if let Some(value) = next_fee_multiplier_value {
        // sp_io::storage::set(&next_fee_multiplier_storage_key, &value);
        // }
        // if let Some(value) = balance_value {
        // sp_io::storage::set(&balance_storage_key, &value);
        // }
        // Ok::<(), sp_blockchain::Error>(())
        // })?;

        let mut runtime_api_light =
            RuntimeApiLight::new(self.executor.clone(), domain_runtime_code.wasm_bundle);

        let sender =
            <RuntimeApiLight<Exec> as DomainCoreApi<Block, AccountId, Balance>>::extract_signer(
                &runtime_api_light,
                Default::default(),
                vec![OpaqueExtrinsic::from_bytes(&extrinsic)?],
            )?
            .into_iter()
            .next()
            .and_then(|(maybe_signer, _)| maybe_signer)
            .ok_or(VerificationError::SignerNotFound)?;

        let account_storage_key = AccountStorageMap::hashed_key_for(&sender);
        println!("=============== sender {sender:?}, account storage key: {account_storage_key:?}");
        let account_value = read_value(&account_storage_key)?;

        println!("=================== account storage key: {account_storage_key:?}, account_value: {account_value:?}");

        let storage = Storage {
            top: [
                (
                    next_fee_multiplier_storage_key.to_vec(),
                    next_fee_multiplier_value.encode(),
                ),
                (account_storage_key, account_value.encode()),
            ]
            .into_iter()
            .collect(),
            children_default: Default::default(),
        };

        runtime_api_light.set_storage(storage);

        let check_result = <RuntimeApiLight<Exec> as DomainCoreApi<
            Block,
            AccountId,
            Balance,
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

/// Verifies invalid transaction proof.
pub trait VerifyInvalidTransactionProof {
    /// Returns `Ok(())` if given `invalid_state_transition_proof` is legitimate.
    fn verify_invalid_transaction_proof(
        &self,
        invalid_transaction_proof: &InvalidTransactionProof,
    ) -> Result<(), VerificationError>;

    #[cfg(test)]
    fn verify_with_extrinsic(
        &self,
        extrinsic: Vec<u8>,
        invalid_transaction_proof: &InvalidTransactionProof,
    ) -> Result<(), VerificationError>;
}

impl<PBlock, Client, Hash, Exec, PrimaryHashProvider, DomainExtrinsicsBuilder>
    VerifyInvalidTransactionProof
    for InvalidTransactionProofVerifier<
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
    fn verify_invalid_transaction_proof(
        &self,
        invalid_transaction_proof: &InvalidTransactionProof,
    ) -> Result<(), VerificationError> {
        self.verify(invalid_transaction_proof)
    }

    #[cfg(test)]
    fn verify_with_extrinsic(
        &self,
        extrinsic: Vec<u8>,
        invalid_transaction_proof: &InvalidTransactionProof,
    ) -> Result<(), VerificationError> {
        self.verify_with_extrinsic(extrinsic, invalid_transaction_proof)
    }
}
