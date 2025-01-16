// add_verification.rs

mod utility;
use anyhow::Result;
use identity_iota::{did::DID, iota::{DidResolutionHandler, IotaDID, IotaDocument}, storage::{JwkDocumentExt, JwkMemStore}, verification::{jws::JwsAlgorithm, verification_method, MethodScope}};
use iota_sdk::IOTA_LOCAL_NETWORK_URL;
use std::{env, fmt::format};
use crate::utility::{get_memstorage, get_client_and_create_account};

#[tokio::main]
async fn main() -> Result<()> {
    // Get the DID ID from user input
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <DID_ID>", args[0]);
        std::process::exit(1);
    }
    let did_id_str = &args[1];
    let network_name = "local";
    let did_id = IotaDID::from_object_id(&did_id_str, &IOTA_LOCAL_NETWORK_URL);

    println!("Adding verification method to DID: {}", did_id);

    pub const TEST_GAS_BUDGET: u64 = 50_000_000;

    // Initialize storage and get the client
    let storage = get_memstorage().await?;
    let identity_client = get_client_and_create_account(&storage).await?;

    let resolved_document = identity_client.resolve_did(&did_id).await?;

    println!("Retrieved DID document: {:#?}", resolved_document);

    // Generate verification method fragment
    let verification_method_fragment = resolved_document
        .generate_method(
            &storage,
            JwkMemStore::ED25519_KEY_TYPE,
            JwsAlgorithm::EdDSA,
            None,
            MethodScope::VerificationMethod,
        )
        .await?;

    resolved_document.attach_method_relationship(
        &resolved_document.id().to_url().join(format!("#{verification_method_fragment}"))?,
        verification_method::MethodRelationship::Authentication,
    )?;

    // Publish the updated DID Document
    let updated_document = identity_client
        .publish_did_document_update(resolved_document.clone(), TEST_GAS_BUDGET)
        .await?;
    println!("Updated DID document result: {updated_document:#}");

    let resolved: IotaDocument = identity_client.resolve_did(&did_id).await?;
    println!("Updated DID document resolved from chain: {resolved:#}");

    Ok(())
}
