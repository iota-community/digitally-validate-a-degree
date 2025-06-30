// use shared_utils::{create_did_document, get_funded_client, get_memstorage};
use shared_utils::create_did_document;
use shared_utils::get_memstorage;
use shared_utils::get_funded_client;

use identity_eddsa_verifier::EdDSAJwsVerifier;
use identity_iota::core::Object;
use identity_iota::credential::Jwt;
use identity_iota::storage::JwkDocumentExt;
use identity_iota::storage::JwsSignatureOptions;

use identity_iota::core::json;
use identity_iota::core::FromJson;
use identity_iota::core::Url;
use identity_iota::credential::Credential;
use identity_iota::credential::CredentialBuilder;
use identity_iota::credential::FailFast;
use identity_iota::credential::JwtCredentialValidationOptions;
use identity_iota::credential::JwtCredentialValidator;
use identity_iota::credential::Subject;
use identity_iota::did::DID;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // ===========================================================================
    // Step 1: Create identity for the issuer and holder.
    // ===========================================================================

    // create new issuer account with did document
    let issuer_storage = get_memstorage().await?;
    let issuer_identity_client = get_funded_client(&issuer_storage).await?;
    let (issuer_document, issuer_vm_fragment) =
        create_did_document(&issuer_identity_client, &issuer_storage).await?;

    // create new holder account with did document
    let holder_storage = get_memstorage().await?;
    let holder_identity_client = get_funded_client(&holder_storage).await?;
    let (holder_document, _) =
        create_did_document(&holder_identity_client, &holder_storage).await?;

    // ===========================================================================
    // Step 2: Issuer creates and signs a Verifiable Credential.
    // ===========================================================================

    // Create a credential subject indicating the degree earned by Alice.
    let subject: Subject = Subject::from_json_value(json!({
        "id": holder_document.id().as_str(),
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
        .issuer(Url::parse(issuer_document.id().as_str())?)
        .type_("UniversityDegreeCredential")
        .subject(subject)
        .build()?;

    let credential_jwt: Jwt = issuer_document
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
    JwtCredentialValidator::with_signature_verifier(EdDSAJwsVerifier::default())
        .validate::<_, Object>(
            &credential_jwt,
            &issuer_document,
            &JwtCredentialValidationOptions::default(),
            FailFast::FirstError,
        )
        .unwrap();

    println!("VC successfully validated");

    // ===========================================================================
    // Step 3: Issuer sends the Verifiable Credential to the holder.
    // ===========================================================================
    // println!("Sending credential to the holder: {credential:#}");
    println!("Sending verified credential as JWT to holder: {credential:#}");

    Ok(())
}