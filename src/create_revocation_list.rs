use std::env;

use anyhow::anyhow;
use identity_eddsa_verifier::EdDSAJwsVerifier;
use identity_iota::core::json;
use identity_iota::core::FromJson;
use identity_iota::core::Object;
use identity_iota::core::Url;
use identity_iota::credential::CompoundCredentialValidationError;
use identity_iota::credential::Credential;
use identity_iota::credential::CredentialBuilder;
use identity_iota::credential::DecodedJwtCredential;
use identity_iota::credential::FailFast;
use identity_iota::credential::Jwt;
use identity_iota::credential::JwtCredentialValidationOptions;
use identity_iota::credential::JwtCredentialValidator;
use identity_iota::credential::JwtCredentialValidatorUtils;
use identity_iota::credential::JwtValidationError;
use identity_iota::credential::RevocationBitmap;
use identity_iota::credential::RevocationBitmapStatus;
use identity_iota::credential::Status;
use identity_iota::credential::Subject;
use identity_iota::did::DIDUrl;
use identity_iota::did::DID;
use identity_iota::document::Service;
use identity_iota::iota::IotaDocument;
use identity_iota::prelude::IotaDID;
use identity_iota::resolver::Resolver;
use identity_iota::storage::JwkDocumentExt;
use identity_iota::storage::JwsSignatureOptions;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Get the DID IDs from user input or a configuration file
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: {} <DID_ID_1> <DID_ID_2>", args[0]);
        std::process::exit(1);
    }

    // Extract the two DID IDs from the command-line arguments
    let did_id_str_1 = &args[1];
    let did_id_str_2 = &args[2];

    // Set the network name (e.g., local or custom)
    let network_name = "local";

    // Convert the DID strings into IotaDID objects
    let did_id_1 = IotaDID::from_object_id(did_id_str_1, &IOTA_LOCAL_NETWORK_URL);
    let did_id_2 = IotaDID::from_object_id(did_id_str_2, &IOTA_LOCAL_NETWORK_URL);

    pub const TEST_GAS_BUDGET: u64 = 50_000_000;

    // Create a new empty revocation bitmap. No credential is revoked yet.
    let revocation_bitmap: RevocationBitmap = RevocationBitmap::new();

    // Add the revocation bitmap to the DID document of the issuer as a service.
    let service_id: DIDUrl = did_id_2
        .id()
        .to_url()
        .join("#my-revocation-service")?;
    let service: Service = revocation_bitmap.to_service(service_id)?;

    assert!(did_id_2.insert_service(service).is_ok());

    // Resolve the latest output and update it with the given document.
    did_id_2 = issuer_identity_client
        .publish_did_document_update(did_id_2.clone(), TEST_GAS_BUDGET)
        .await?;

    println!("DID Document > {did_id_2:#}");

    // Create a credential subject indicating the degree earned by Alice.
    let subject: Subject = Subject::from_json_value(json!({
      "id": did_id_str_1.id().as_str(),
      "name": "Alice",
      "degree": {
        "type": "BachelorDegree",
        "name": "Bachelor of Science and Arts",
      },
      "GPA": "4.0",
    }))?;

    // Create an unsigned `UniversityDegree` credential for Alice.
    // The issuer also chooses a unique `RevocationBitmap` index to be able to revoke it later.
    let service_url = did_id_1
        .id()
        .to_url()
        .join("#my-revocation-service")?;
    let credential_index: u32 = 5;
    let status: Status = RevocationBitmapStatus::new(service_url, credential_index).into();

    // Build credential using subject above and issuer.
    let credential: Credential = CredentialBuilder::default()
        .id(Url::parse("https://example.edu/credentials/3732")?)
        .issuer(Url::parse(did_id_2.id().as_str())?)
        .type_("UniversityDegreeCredential")
        .status(status)
        .subject(subject)
        .build()?;

    println!("Credential JSON > {credential:#}");

    let credential_jwt: Jwt = did_id_2
        .create_credential_jwt(
            &credential,
            &issuer_storage,
            &issuer_vm_fragment,
            &JwsSignatureOptions::default(),
            None,
        )
        .await?;

    let validator: JwtCredentialValidator<EdDSAJwsVerifier> =
        JwtCredentialValidator::with_signature_verifier(EdDSAJwsVerifier::default());
    // Validate the credential's signature using the issuer's DID Document.
    validator.validate::<_, Object>(
        &credential_jwt,
        &issuer_document,
        &JwtCredentialValidationOptions::default(),
        FailFast::FirstError,
    )?;

    Ok(())
}
