use anyhow::{
    Context as _,
    anyhow,
};

use aya_build::Toolchain;

fn main() -> anyhow::Result<()> {
    let cargo_metadata::Metadata {
        packages,
        ..
    } =
        cargo_metadata::MetadataCommand::new()
            .no_deps()
            .exec()
            .context(
                "MetadataCommand::exec"
            )?;

    let ebpf_package =
        packages
            .into_iter()
            .find(|package| {
                package.name.as_str()
                    == "omasnitch-ebpf"
            })
            .ok_or_else(|| {
                anyhow!(
                    "omasnitch-ebpf package not found"
                )
            })?;

    let manifest_dir =
        ebpf_package
            .manifest_path
            .parent()
            .ok_or_else(|| {
                anyhow!(
                    "omasnitch-ebpf manifest has no parent"
                )
            })?;

    let package =
        aya_build::Package {
            name: "omasnitch-ebpf",
            root_dir:
                manifest_dir.as_str(),
            ..Default::default()
        };

    aya_build::build_ebpf(
        [package],
        Toolchain::default(),
    )
}