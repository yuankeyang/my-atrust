fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Copy policy.proto to generated location
    let proto_src = "../../policy.proto";
    let proto_dst = "../../generated/policy.proto";

    // Ensure directory exists
    std::fs::create_dir_all(std::path::Path::new(proto_dst).parent().unwrap())?;

    // Copy if changed
    if std::path::Path::new(proto_src).exists() {
        std::fs::copy(proto_src, proto_dst)?;
    }

    // Compile protobuf
    let proto_files = std::path::Path::new(".").join("generated/policy.proto");
    if proto_files.exists() {
        prost_build::compile_protos(&[proto_files.to_str().unwrap()], &["generated/"])?;
        println!("cargo:rerun-if-changed=generated/policy.proto");
    }

    Ok(())
}
