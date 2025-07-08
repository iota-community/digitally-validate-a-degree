use anyhow::Result;
use identity_iota::credential::{Jwt, JwtPresentationOptions, PresentationValidator, FailFast};
use identity_iota::iota::IotaDocument;
use identity_iota::resolver::Resolver;
use shared_utils::get_read_only_client;

#[tokio::main]
async fn main() -> Result<()> {
    // Get the VP JWT from CLI args
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: cargo run --bin verifier <VP_JWT>");
        return Err(anyhow::anyhow!("Missing VP JWT argument."));
    }
    let vp_jwt_str = &args[1];
    println!("✅ Received VP JWT: {}", vp_jwt_str);

    // Wrap into Jwt type
    let vp_jwt = Jwt::new(vp_jwt_str.clone());

    // Build resolver with IOTA client
    let read_only_client = get_read_only_client().await?;
    let mut resolver: Resolver<IotaDocument> = Resolver::new();
    resolver.attach_iota_handler(read_only_client);

    // Validate the presentation
    let challenge = "475a7984-1bb5-4c4c-a56f-822bccd46440"; // Should match what holder used
    let presentation_options = JwtPresentationOptions::default().challenge(challenge.to_owned());

    let validation_result = PresentationValidator::validate::<IotaDocument>(
        &vp_jwt,
        &resolver,
        &presentation_options,
        FailFast::FirstError,
    )
    .await;

    match validation_result {
        Ok(presentation) => {
            println!("✅ VP verification successful!");
            println!("✅ Holder: {}", presentation.holder());
            println!("✅ Included credentials count: {}", presentation.verifiable_credential().len());
        }
        Err(err) => {
            eprintln!("❌ VP verification failed: {:?}", err);
        }
    }

    Ok(())
}
