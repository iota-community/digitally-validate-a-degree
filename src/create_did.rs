mod utility;

use anyhow::Result;
use identity_iota::document;
use identity_iota::iota::rebased::utils::get_client;
use crate::utility::{create_did_document, get_memstorage, get_client_and_create_account};
use std::sync::Arc;
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

    // Create the identity client using initialize_client_manager
    let identity_client = get_client_and_create_account(&storage).await?;

    // Create and publish a DID document
    let mut document = create_did_document(&identity_client, &storage).await?;

    // Save the entity name to the DID document's metadata
    document
        .metadata
        .properties_mut()
        .insert("name".to_string(), entity_name.as_str().into());

    let did_id = document.id().to_string();
    println!("Created DID with ID for '{}': {:#?}", entity_name, did_id);

    // Resolve the published DID document
    let resolved = identity_client.resolve_did(document.id()).await?;
    println!("Resolved DID document: {:#?}", resolved);

    Ok(())
}