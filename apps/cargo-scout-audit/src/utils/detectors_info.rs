use anyhow::{anyhow, Result};
use libloading::{Library, Symbol};
use serde::Serialize;
use std::sync::Arc;
use std::{collections::HashMap, ffi::CString, path::PathBuf};

#[derive(Default, Debug, Clone)]
pub struct RawLintInfo {
    pub id: CString,
    pub name: CString,
    pub short_message: CString,
    pub long_message: CString,
    pub severity: CString,
    pub help: CString,
    pub vulnerability_class: CString,
}

#[derive(Default, Debug, Clone, Serialize)]
pub struct LintInfo {
    pub id: String,
    pub name: String,
    pub short_message: String,
    pub long_message: String,
    pub severity: String,
    pub help: String,
    pub vulnerability_class: String,
}

pub struct CustomLint<'lib> {
    pub lib: Arc<Library>,
    pub custom_detector: Symbol<'lib, CustomLintFunc>,
}

impl TryFrom<&RawLintInfo> for LintInfo {
    type Error = anyhow::Error;

    fn try_from(info: &RawLintInfo) -> Result<Self, Self::Error> {
        Ok(LintInfo {
            id: info.id.to_str()?.to_string(),
            name: info.name.to_str()?.to_string(),
            short_message: info.short_message.to_str()?.to_string(),
            long_message: info.long_message.to_str()?.to_string(),
            severity: info.severity.to_str()?.to_string(),
            help: info.help.to_str()?.to_string(),
            vulnerability_class: info.vulnerability_class.to_str()?.to_string(),
        })
    }
}

impl<'lib> CustomLint<'lib> {
    pub fn new(lib: Arc<Library>, custom_detector: Symbol<'lib, CustomLintFunc>) -> Self {
        CustomLint {
            lib,
            custom_detector,
        }
    }

    pub fn call(&self) {
        unsafe {
            (self.custom_detector)();
        }
    }
}

type LintInfoFunc = unsafe fn(info: &mut RawLintInfo);
type CustomLintFunc = unsafe fn();

#[tracing::instrument(level = "debug", skip_all)]
pub fn get_detectors_info(
    detectors_paths: &[PathBuf],
) -> Result<(HashMap<String, LintInfo>, HashMap<String, CustomLint<'_>>)> {
    let mut lint_store = HashMap::new();
    let mut custom_dectectors = HashMap::new();

    for detector_path in detectors_paths {
        let lib = unsafe {
            Library::new(detector_path)
                .map_err(|e| anyhow!("Failed to load library {}: {}", detector_path.display(), e))?
        };
        let lib = Arc::new(lib);

        let lint_info_func: Symbol<LintInfoFunc> = unsafe {
            lib.get(b"lint_info").map_err(|e| {
                anyhow!(
                    "Failed to get lint_info function from {}: {}",
                    detector_path.display(),
                    e
                )
            })?
        };
        let custom_detector_func: Option<Symbol<CustomLintFunc>> =
            unsafe { (*Arc::as_ptr(&lib)).get(b"custom_detector").ok() };

        let mut raw_info = RawLintInfo::default();
        unsafe { lint_info_func(&mut raw_info) };

        let lint_info = LintInfo::try_from(&raw_info).map_err(|e| {
            anyhow!(
                "Failed to convert RawLintInfo from {}: {}",
                detector_path.display(),
                e
            )
        })?;

        let id = lint_info.id.clone();

        lint_store.insert(id.clone(), lint_info);

        if let Some(custom_detector_func) = custom_detector_func {
            custom_dectectors.insert(id, CustomLint::new(lib, custom_detector_func));
        }
    }

    Ok((lint_store, custom_dectectors))
}
