use std::env;

use examples::create_did_document;
use examples::get_client_and_create_account;
use examples::get_memstorage;
use identity_eddsa_verifier::EdDSAJwsVerifier;
use identity_iota::core::Object;

use identity_iota::credential::DecodedJwtCredential;
use identity_iota::credential::Jwt;
use identity_iota::credential::JwtCredentialValidationOptions;
use identity_iota::credential::JwtCredentialValidator;
use identity_iota::iota::IotaDID;
use identity_iota::storage::JwkDocumentExt;
use identity_iota::storage::JwsSignatureOptions;

use identity_iota::core::json;
use identity_iota::core::FromJson;
use identity_iota::core::Url;
use identity_iota::credential::Credential;
use identity_iota::credential::CredentialBuilder;
use identity_iota::credential::FailFast;
use identity_iota::credential::Subject;
use identity_iota::did::DID;

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

    // Print the parsed DID IDs to verify
    println!("DID ID 1: {:?}", did_id_1);
    println!("DID ID 2: {:?}", did_id_2);

    // Create a credential subject indicating the degree earned by Alice.
    let subject: Subject = Subject::from_json_value(json!({
      "id": did_id_1.id().as_str(),
      //"id": holder_document.id().as_str(),
      "name": "Alice",
      "degree": {
        "type": "BachelorDegree",
        "name": "Bachelor of Science and Arts",
      },
      "GPA": "4.0",
    }))?;

    // Build credential using subject above and issuer.
    let credential: Credential = CredentialBuilder::default()
        .id(Url::parse("https://example.edu/credentials/3732")?)
        .issuer(Url::parse(did_id_2.id().as_str())?)
        .type_("UniversityDegreeCredential")
        .subject(subject)
        .build()?;

    let credential_jwt: Jwt = did_id_2
        .create_credential_jwt(
            &credential,
            &issuer_storage,
            &issuer_vm_fragment,
            &JwsSignatureOptions::default(),
            None,
        )
        .await?;

    // Before sending this credential to the holder the issuer wants to validate that some properties
    // of the credential satisfy their expectations.

    // Validate the credential's signature using the issuer's DID Document, the credential's semantic structure,
    // that the issuance date is not in the future and that the expiration date is not in the past:
    let decoded_credential: DecodedJwtCredential<Object> =
        JwtCredentialValidator::with_signature_verifier(EdDSAJwsVerifier::default())
            .validate::<_, Object>(
                &credential_jwt,
                &did_id_2,
                &JwtCredentialValidationOptions::default(),
                FailFast::FirstError,
            )
            .unwrap();

    println!("VC successfully validated");

    println!("Credential JSON > {:#}", decoded_credential.credential);

    Ok(())
}
