// holder.rs
use anyhow::Result;
use identity_iota::core::{Duration, FromJson, Timestamp, ToJson};
use identity_iota::credential::{Jwt, JwtPresentationOptions, Presentation, PresentationBuilder};
use identity_iota::iota::IotaDocument;
use identity_storage::{JwkDocumentExt, JwsSignatureOptions};
use shared_utils::{create_did_document, get_stronghold_storage, get_funded_client};
use std::fs;
use std::path::PathBuf;
use identity_iota::did::DID;

#[tokio::main]
async fn main() -> Result<()> {
    // Use a fixed stronghold file so keys survive between runs
    let holder_storage = get_stronghold_storage(Some(PathBuf::from("./holder.stronghold")))?;

    // STEP 1: If holder DID does NOT exist, create & save
    let did_file = "./holder_doc.json";
    let fragment_file = "./holder_fragment.txt";

    if !PathBuf::from(did_file).exists() {
        println!("📦 No holder DID found, creating...");
        let holder_client = get_funded_client(&holder_storage).await?;
        let (holder_doc, holder_fragment) = create_did_document(&holder_client, &holder_storage).await?;

        fs::write(did_file, holder_doc.to_json()?)?;
        fs::write(fragment_file, &holder_fragment)?;
        println!("✅ Created holder DID: {}", holder_doc.id());
        println!("✅ Saved fragment: {}", holder_fragment);
        println!("ℹ️  Next: run issuer to issue a VC, then come back to create VP.");
        return Ok(());
    }

    // STEP 2: Build VP using VC passed as argument
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: cargo run --bin holder <VC_JWT>");
        return Err(anyhow::anyhow!("Missing VC JWT argument."));
    }
    let vc_jwt = &args[1];

    let holder_doc_json = fs::read_to_string(did_file)?;
    let holder_doc = IotaDocument::from_json(&holder_doc_json)?;
    let holder_fragment = fs::read_to_string(fragment_file)?.trim().to_string();

    println!("🔑 Using holder DID: {}", holder_doc.id());
    println!("🔑 Using fragment to sign: {}", holder_fragment);

    let challenge = "challenge-123";
    let expires = Timestamp::now_utc().checked_add(Duration::minutes(10)).unwrap();

    let presentation: Presentation<Jwt> = PresentationBuilder::new(holder_doc.id().to_url().into(), Default::default())
        .credential(Jwt::new(vc_jwt.clone()))
        .build()?;
    println!("✅ Built presentation structure");

    let vp_jwt: Jwt = holder_doc
        .create_presentation_jwt(
            &presentation,
            &holder_storage,
            &holder_fragment,
            &JwsSignatureOptions::default().nonce(challenge.to_owned()),
            &JwtPresentationOptions::default().expiration_date(expires),
        )
        .await?;

    println!("\n✅ Created VP JWT:\n{}", vp_jwt.as_str());
    fs::write("vp.jwt", vp_jwt.as_str())?;
    println!("📦 Saved VP JWT to vp.jwt");
    println!("ℹ️  Next: run verifier to verify the VP.");
    Ok(())
}
