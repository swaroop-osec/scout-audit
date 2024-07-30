use anyhow::{anyhow, bail, Context, Ok, Result};
use cargo::GlobalContext;
use cargo_metadata::{Metadata, MetadataCommand};
use clap::{Parser, Subcommand, ValueEnum};
use dylint::opts::{Check, Dylint, LibrarySelection, Operation};
use std::{collections::HashMap, fs, io::Write, path::PathBuf};
use tempfile::NamedTempFile;

use crate::{
    detectors::{
        builder::DetectorBuilder,
        configuration::{get_local_detectors_configuration, get_remote_detectors_configuration},
    },
    output::raw_report::RawReport,
    scout::{
        blockchain::BlockChain, nightly_runner::run_scout_in_nightly, project_info::ProjectInfo,
        version_checker::VersionChecker,
    },
    utils::{
        config::{open_config_or_default, profile_enabled_detectors},
        detectors::{get_excluded_detectors, get_filtered_detectors, list_detectors},
        detectors_info::{get_detectors_info, LintInfo},
        print::{print_error, print_warning},
    },
};

#[derive(Debug, Parser)]
#[clap(display_name = "cargo")]
pub struct Cli {
    #[clap(subcommand)]
    pub subcmd: CargoSubCommand,
}

#[derive(Debug, Subcommand)]
pub enum CargoSubCommand {
    ScoutAudit(Scout),
}

#[derive(Debug, Default, Clone, ValueEnum, PartialEq)]
pub enum OutputFormat {
    #[default]
    Html,
    Json,
    RawJson,
    #[clap(name = "md")]
    Markdown,
    #[clap(name = "md-gh")]
    MarkdownGithub,
    Sarif,
    Pdf,
}

#[derive(Clone, Debug, Default, Parser)]
#[command(author, version, about, long_about = None)]
pub struct Scout {
    #[clap(short, long, value_name = "path", help = "Path to Cargo.toml.")]
    pub manifest_path: Option<PathBuf>,

    // Exlude detectors
    #[clap(
        short,
        long,
        value_name = "detector/s",
        help = "Exclude the given detectors, separated by commas."
    )]
    pub exclude: Option<String>,

    // Filter by detectors
    #[clap(
        short,
        long,
        value_name = "detector/s",
        help = "Filter by the given detectors, separated by commas."
    )]
    pub filter: Option<String>,

    // Select profiles in configuration
    #[clap(
        short,
        long,
        value_name = "profile",
        help = "Filter detectors using profiles."
    )]
    pub profile: Option<String>,

    // List all the available detectors
    #[clap(short, long, help = "List all the available detectors")]
    pub list_detectors: bool,

    #[clap(last = true, help = "Arguments for `cargo check`.")]
    pub args: Vec<String>,

    #[clap(short, long, value_name = "type", help = "Sets the output type")]
    pub output_format: Option<OutputFormat>,

    #[clap(long, value_name = "path", help = "Path to the output file.")]
    pub output_path: Option<PathBuf>,

    #[clap(long, value_name = "path", help = "Path to detectors workspace.")]
    pub local_detectors: Option<PathBuf>,

    #[clap(
        long,
        help = "Force fallback to secondary detectors branch.",
        default_value_t = false
    )]
    pub force_fallback: bool,

    #[clap(
        short,
        long,
        help = "Prints detectors metadata.",
        default_value_t = false
    )]
    pub verbose: bool,

    #[clap(
        name = "toolchain",
        long,
        help = "Prints the detectors current toolchain.",
        default_value_t = false
    )]
    pub toolchain: bool,

    #[clap(
        name = "metadata",
        long,
        help = "Prints metadata information.",
        default_value_t = false
    )]
    pub detectors_metadata: bool,
}

impl Scout {
    fn prepare_args(&mut self) {
        if !self.args.iter().any(|x| x.contains("--target=")) {
            self.args.extend([
                "--target=wasm32-unknown-unknown".to_string(),
                "--no-default-features".to_string(),
                "-Zbuild-std=std,core,alloc".to_string(),
            ]);
        }

        if self.output_format.is_some() {
            self.args.push("--message-format=json".to_string());
        }
    }

    fn validate(&self) -> Result<()> {
        if self.filter.is_some() && self.exclude.is_some() {
            bail!("The flags `--filter` and `--exclude` can't be used together");
        }
        if self.filter.is_some() && self.profile.is_some() {
            bail!("The flags `--filter` and `--profile` can't be used together");
        }
        if let Some(path) = &self.output_path {
            if path.is_dir() {
                bail!("The output path can't be a directory");
            }
        }
        Ok(())
    }
}

fn get_project_metadata(manifest_path: &Option<PathBuf>) -> Result<Metadata> {
    let mut metadata_command = MetadataCommand::new();

    if let Some(manifest_path) = manifest_path {
        if !manifest_path.ends_with("Cargo.toml") {
            bail!(
                "Invalid manifest path, ensure scout is being run in a Rust project, and the path is set to the Cargo.toml file.\n     → Manifest path: {:?}",
                manifest_path
            );
        }

        fs::metadata(manifest_path).context(format!(
            "Cargo.toml file not found, ensure the path is a valid file path.\n     → Manifest path: {:?}",
            manifest_path
        ))?;

        metadata_command.manifest_path(manifest_path);
    }

    metadata_command
        .exec()
        .map_err(|e| {
            anyhow!("Failed to execute metadata command on this path, ensure this is a valid rust project or workspace directory.\n\n     → Caused by: {}", e.to_string())})
}

#[tracing::instrument(name = "RUN SCOUT", skip_all)]
pub fn run_scout(mut opts: Scout) -> Result<()> {
    opts.validate()?;
    opts.prepare_args();

    let metadata = get_project_metadata(&opts.manifest_path)?;
    let blockchain = BlockChain::get_blockchain_dependency(&metadata)?;
    let toolchain = blockchain.get_toolchain();

    if opts.toolchain {
        println!("{}", toolchain);
        return Ok(());
    }

    if let Some(mut child) = run_scout_in_nightly(toolchain)? {
        child
            .wait()
            .with_context(|| "Failed to wait for nightly child process")?;
        return Ok(());
    }

    if let Err(e) = VersionChecker::new().check_for_updates() {
        print_error(&format!(
            "Failed to check for updates.\n\n     → Caused by: {}",
            e
        ));
    }

    let cargo_config =
        GlobalContext::default().with_context(|| "Failed to create default cargo configuration")?;
    cargo_config.shell().set_verbosity(if opts.verbose {
        cargo::core::Verbosity::Verbose
    } else {
        cargo::core::Verbosity::Quiet
    });

    let detectors_config = match &opts.local_detectors {
        Some(path) => get_local_detectors_configuration(&PathBuf::from(path)).map_err(|e| {
            anyhow!(
                "Failed to get local detectors configuration.\n\n     → Caused by: {}",
                e
            )
        })?,
        None => {
            get_remote_detectors_configuration(blockchain, opts.force_fallback).map_err(|e| {
                anyhow!(
                    "Failed to get remote detectors configuration.\n\n     → Caused by: {}",
                    e
                )
            })?
        }
    };

    // Instantiate detectors
    let detector_builder = DetectorBuilder::new(
        &cargo_config,
        &detectors_config,
        &metadata,
        opts.verbose,
        toolchain,
    );

    let mut detectors_names = detector_builder
        .get_detector_names()
        .map_err(|e| anyhow!("Failed to get detector names.\n\n     → Caused by: {}", e))?;

    if opts.list_detectors {
        list_detectors(&detectors_names);
        return Ok(());
    }

    detectors_names = if let Some(profile) = &opts.profile {
        let config = open_config_or_default(blockchain, detectors_names.clone()).map_err(|e| {
            anyhow!(
                "Failed to load or generate profile.\n\n     → Caused by: {}",
                e
            )
        })?;

        profile_enabled_detectors(config, profile.clone())?
    } else {
        detectors_names
    };

    let used_detectors = if let Some(filter) = &opts.filter {
        get_filtered_detectors(filter, &detectors_names)?
    } else if let Some(excluded) = &opts.exclude {
        get_excluded_detectors(excluded, &detectors_names)
    } else {
        detectors_names
    };

    let detectors_paths = detector_builder
        .build(&blockchain, &used_detectors)
        .map_err(|e| {
            anyhow!(
                "Failed to build detectors.\n\n     → Caused by: {}",
                e.to_string()
            )
        })?;

    let detectors_info = get_detectors_info(&detectors_paths)?;

    if opts.detectors_metadata {
        let json = serde_json::to_string_pretty(&detectors_info);
        println!("{}", json.unwrap());
        return Ok(());
    }

    let project_info = ProjectInfo::get_project_info(&metadata)
        .map_err(|err| anyhow!("Failed to get project info.\n\n     → Caused by: {}", err))?;

    // Run dylint
    let stdout_temp_file = run_dylint(detectors_paths, &opts, blockchain)
        .map_err(|err| anyhow!("Failed to run dylint.\n\n     → Caused by: {}", err))?;

    // Generate report
    if let Some(output_format) = opts.output_format {
        generate_report(
            &stdout_temp_file,
            project_info,
            detectors_info,
            opts.output_path,
            output_format,
        )?;
    }

    stdout_temp_file.close()?;

    Ok(())
}

#[tracing::instrument(name = "RUN DYLINT", skip(detectors_paths, opts, _bc_dependency))]
fn run_dylint(
    detectors_paths: Vec<PathBuf>,
    opts: &Scout,
    _bc_dependency: BlockChain,
) -> Result<NamedTempFile> {
    // Convert detectors paths to string
    let detectors_paths: Vec<String> = detectors_paths
        .iter()
        .map(|path| path.to_string_lossy().into_owned())
        .collect();

    // Initialize temporary file for stdout
    let stdout_temp_file =
        NamedTempFile::new().with_context(|| ("Failed to create stdout temporary file"))?;
    let pipe_stdout = Some(stdout_temp_file.path().to_string_lossy().into_owned());

    // Get the manifest path
    let manifest_path = opts
        .manifest_path
        .as_ref()
        .map(|p| p.to_string_lossy().into_owned());

    let check_opts = Check {
        lib_sel: LibrarySelection {
            manifest_path,
            lib_paths: detectors_paths,
            ..Default::default()
        },
        args: opts.args.to_owned(),
        ..Default::default()
    };

    let options = Dylint {
        pipe_stdout,
        quiet: opts.verbose,
        operation: Operation::Check(check_opts.clone()),
        ..Default::default()
    };

    if dylint::run(&options).is_err() {
        print_error("Failed to run dylint, most likely due to an issue in the code.");
        if opts.output_format.is_some() {
            print_warning("This report is incomplete as some files could not be fully analyzed due to compilation errors. We strongly recommend to address all issues and executing Scout again.");
        }
    }

    if check_opts
        .args
        .contains(&"--message-format=json".to_string())
        && opts.output_format.is_none()
    {
        let stdout_content = fs::read(stdout_temp_file.path())
            .with_context(|| ("Failed to read stdout temporary file"))?;
        std::io::stdout()
            .lock()
            .write_all(&stdout_content)
            .with_context(|| ("Failed to write stdout content"))?;
    }

    Ok(stdout_temp_file)
}

#[tracing::instrument(name = "GENERATE REPORT", skip_all)]
fn generate_report(
    stdout_temp_file: &NamedTempFile,
    project_info: ProjectInfo,
    detectors_info: HashMap<String, LintInfo>,
    output_path: Option<PathBuf>,
    output_format: OutputFormat,
) -> Result<()> {
    // Read the stdout temporary file
    let mut stdout_file = fs::File::open(stdout_temp_file.path())?;

    // Generate report
    let mut content = String::new();
    std::io::Read::read_to_string(&mut stdout_file, &mut content)?;
    let report = RawReport::generate_report(&content, &project_info, &detectors_info)?;

    tracing::trace!(?output_format, "Output format");
    tracing::trace!(?report, "Report");

    // Save the report
    match output_format {
        OutputFormat::Html => {
            // Generate HTML report
            let html = report.generate_html()?;

            // Save to file
            let html_path = output_path.unwrap_or_else(|| PathBuf::from("report.html"));
            report.save_to_file(&html_path, html)?;

            // Open the HTML report in the default web browser
            webbrowser::open(
                html_path
                    .to_str()
                    .with_context(|| "Path conversion to string failed")?,
            )
            .with_context(|| "Failed to open HTML report")?;
        }

        OutputFormat::Json => {
            // Generate JSON report
            let json = report.generate_json()?;

            // Save to file
            let json_path = output_path.unwrap_or_else(|| PathBuf::from("report.json"));
            report.save_to_file(&json_path, json)?;
        }
        OutputFormat::RawJson => {
            let mut json_file = match &output_path {
                Some(path) => fs::File::create(path)?,
                None => fs::File::create("raw-report.json")?,
            };

            std::io::Write::write(&mut json_file, content.as_bytes())?;
        }
        OutputFormat::Markdown => {
            // Generate Markdown
            let markdown = report.generate_markdown(true)?;

            // Save to file
            let md_path = output_path.unwrap_or_else(|| PathBuf::from("report.md"));
            report.save_to_file(&md_path, markdown)?;
        }
        OutputFormat::MarkdownGithub => {
            // Generate Markdown
            let markdown = report.generate_markdown(false)?;

            // Save to file
            let md_path = output_path.unwrap_or_else(|| PathBuf::from("report.md"));
            report.save_to_file(&md_path, markdown)?;
        }
        OutputFormat::Sarif => {
            let path = if let Some(path) = output_path {
                path
            } else {
                PathBuf::from("report.sarif")
            };

            let mut sarif_file = fs::File::create(path)?;

            let mut content = String::new();
            std::io::Read::read_to_string(&mut stdout_file, &mut content)?;

            let child = std::process::Command::new("clippy-sarif")
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .spawn()?;

            std::io::Write::write_all(&mut child.stdin.as_ref().unwrap(), content.as_bytes())?;

            std::io::Write::write_all(&mut sarif_file, &child.wait_with_output()?.stdout)?;
        }
        OutputFormat::Pdf => {
            let path = if let Some(path) = output_path {
                path
            } else {
                PathBuf::from("report.pdf")
            };
            report.generate_pdf(&path)?;
        }
    }

    Ok(())
}
