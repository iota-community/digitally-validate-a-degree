mod utility;
use identity_iota::document;

use crate::utility::{create_did_document, get_client_and_create_account, get_memstorage};
use std::env;

/// Demonstrates how to create a DID Document and publish it on chain.
///
/// In this example we connect to a locally running private network, but it can be adapted
/// to run on any IOTA node by setting the network and faucet endpoints.
///
/// See the following instructions on running your own private network
/// https://github.com/iotaledger/hornet/tree/develop/private_tangle
#[tokio::main]
async fn main() -> anyhow::Result<()> {

    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <name>", args[0]);
        std::process::exit(1);
    }
    let entity_name = &args[1];

    println!("Creating DID for: {entity_name}");

    // create new client to interact with chain and get funded account with keys
    let storage = get_memstorage()?;
    let identity_client = get_client_and_create_account(&storage).await?;

    // create new DID document and publish it
    let (mut document, _) = create_did_document(&identity_client, &storage).await?;

    // Add the entity name to the DID Document metadata (optional)
    document.metadata.properties_mut.insert("name".to_string(), entity_name.into());

    println!("Published DID document for {entity_name}: {document:#}");

    // check if we can resolve it via client
    let resolved = identity_client.resolve_did(document.id()).await?;
    println!("Resolved DID document: {resolved:#}");

    Ok(())
}
