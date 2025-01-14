// utility.rs

use anyhow::Context;
use anyhow::Result;
use identity_iota::core::Url;
use identity_iota::iota::rebased::client::convert_to_address;
use identity_iota::iota::rebased::client::get_sender_public_key;
use identity_iota::iota::rebased::client::IdentityClient;
use identity_iota::iota::rebased::client::IdentityClientReadOnly;
use identity_iota::iota::rebased::client::IotaKeySignature;
use identity_iota::iota::rebased::transaction::Transaction;
use identity_iota::iota::rebased::utils::request_funds;
use identity_iota::iota::IotaDocument;
use identity_iota::storage::{JwkMemStore, JwkStorage, KeyIdMemstore, Storage};
use identity_iota::storage::{KeyType, StorageSigner};
use identity_iota::verification::jws::JwsAlgorithm;
use identity_iota::verification::MethodScope;
use iota_sdk::types::crypto::IotaKeyPair;
use iota_sdk::IotaClientBuilder;
use iota_sdk::IOTA_LOCAL_NETWORK_URL;
use secret_storage::Signer;
use std::sync::Arc;
use tokio::sync::Mutex;

pub const TEST_GAS_BUDGET: u64 = 50_000_000;
pub type MemStorage = Storage<JwkMemStore, KeyIdMemstore>;

pub async fn get_memstorage() -> anyhow::Result<MemStorage> {
    Ok(MemStorage::new(JwkMemStore::new(), KeyIdMemstore::new()))
}

pub async fn get_client_and_create_account<K, I>(
    storage: &Storage<K, I>,
) -> Result<IdentityClient<StorageSigner<K, I>>, anyhow::Error>
where
    K: identity_iota::storage::JwkStorage,
    I: identity_iota::storage::KeyIdStorage,
{
    let api_endpoint =
        std::env::var("API_ENDPOINT").unwrap_or_else(|_| IOTA_LOCAL_NETWORK_URL.to_string());
    let iota_client = IotaClientBuilder::default()
        .build(&api_endpoint)
        .await
        .map_err(|err| anyhow::anyhow!(format!("failed to connect to network; {}", err)))?;

    // generate new key
    let generate = storage
        .key_storage()
        .generate(KeyType::new("Ed25519"), JwsAlgorithm::EdDSA)
        .await?;
    let public_key_jwk = generate
        .jwk
        .to_public()
        .expect("public components should be derivable");
    let public_key_bytes = get_sender_public_key(&public_key_jwk)?;
    let sender_address = convert_to_address(&public_key_bytes)?;
    request_funds(&sender_address).await?;
    let package_id = std::env::var("IOTA_IDENTITY_PKG_ID")
        .map_err(|e| {
            anyhow::anyhow!(
                "env variable IOTA_IDENTITY_PKG_ID must be set in order to run the examples"
            )
            .context(e)
        })
        .and_then(|pkg_str| pkg_str.parse().context("invalid package id"))?;

    let read_only_client = IdentityClientReadOnly::new_with_pkg_id(iota_client, package_id).await?;

    let signer = StorageSigner::new(storage, generate.key_id, public_key_jwk);

    let identity_client = IdentityClient::new(read_only_client, signer).await?;

    Ok(identity_client)
}

/// Creates and publishes a new DID Document
pub async fn create_did_document<K, I, S>(
    identity_client: &IdentityClient<S>,
    storage: &Storage<K, I>,
) -> anyhow::Result<IotaDocument>
where
    K: identity_iota::storage::JwkStorage,
    I: identity_iota::storage::KeyIdStorage,
    S: Signer<IotaKeySignature> + Sync,
{
    // Create a new DID document with a placeholder DID.
    let mut unpublished: IotaDocument = IotaDocument::new(identity_client.network());

    // Publish the DID document and get the output.
    let document = identity_client
        .publish_did_document(unpublished)
        .execute_with_gas(TEST_GAS_BUDGET, identity_client)
        .await?
        .output;

    Ok(document)
}
