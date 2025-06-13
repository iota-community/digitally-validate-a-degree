mod utility;

use crate::utility::{
    create_did_document, get_client_and_create_account, get_memstorage, get_stronghold_storage,
    pretty_print_json, save_to_stronghold,
};
use anyhow::Result;
use identity_stronghold::StrongholdStorage;
use iota_sdk_legacy::client::stronghold;
use std::env;

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command-line arguments for the entity name
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <entity_name>", args[0]);
        std::process::exit(1);
    }
    let entity_name = &args[1];
    println!("Creating DID for entity: {}", entity_name);

    // Initialize in-memory storage
    let storage = get_memstorage().await?;

    // Create the identity client
    let identity_client = get_client_and_create_account(&storage).await?;

    // Create and publish a DID document
    let mut document = create_did_document(&identity_client, &storage).await?;

    // Save the entity name to the DID document's metadata
    document
        .metadata
        .properties_mut()
        .insert("name".to_string(), entity_name.as_str().into());

    let did_id = document.id().to_string();
    println!("Created DID with ID for '{}': {}", entity_name, did_id);

    // Pretty print the created DID document
    let document_json = serde_json::to_string(document.as_ref())?;
    pretty_print_json("Created DID Document", &document_json);

    // Resolve the published DID document
    let resolved = identity_client.resolve_did(document.id()).await?;
    println!("Resolved DID document: {resolved:#}");

    // Save the private key, DID ID, and entity name to Stronghold
    let stronghold_storage = get_stronghold_storage(None)?;

    // Retrieve the private key of the IOTA client from the storage
    let iota_client_private_key = storage
        .key_storage()
        .get_private_key()
        .await
        .expect("Failed to retrieve IOTA client private key");

    save_to_stronghold(&stronghold_storage, &private_key, &did_id, entity_name)?;

    println!("Private key, DID ID, and entity name saved to Stronghold!");

    Ok(())
}
