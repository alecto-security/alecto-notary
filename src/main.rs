#[tokio::main]
async fn main() {
    std::process::exit(alecto_notary::cli::run().await);
}
