use crate::build_config::{INK_TOOLCHAIN, SOROBAN_TOOLCHAIN, APTOS_TOOLCHAIN};
use anyhow::Result;
use cargo_metadata::Metadata;
use std::collections::HashSet;
use strum::IntoEnumIterator;
use strum_macros::{Display, EnumIter, EnumString};

#[derive(Debug, Copy, Clone, EnumIter, Display, EnumString, PartialEq)]
pub enum BlockChain {
    Ink,
    Soroban,
    SubstratePallet,
    Aptos,
}

impl BlockChain {
    pub fn variants() -> Vec<String> {
        Self::iter().map(|e| e.to_string()).collect()
    }

    pub fn get_detectors_url(&self) -> &str {
        match self {
            BlockChain::Ink => "https://github.com/CoinFabrik/scout",
            BlockChain::Soroban => "https://github.com/CoinFabrik/scout-soroban",
            BlockChain::SubstratePallet => "https://github.com/CoinFabrik/scout-substrate",
            BlockChain::Aptos => "https://github.com/swaroop-osec/scout-soroban",
        }
    }

    pub fn get_toolchain(&self) -> &str {
        match self {
            BlockChain::Ink => INK_TOOLCHAIN,
            BlockChain::Soroban => SOROBAN_TOOLCHAIN,
            BlockChain::SubstratePallet => INK_TOOLCHAIN,
            BlockChain::Aptos => APTOS_TOOLCHAIN,
        }
    }

    fn get_immediate_dependencies(metadata: &Metadata) -> HashSet<String> {
        let mut ret = HashSet::<String>::new();
        let root_packages = metadata
            .workspace_members
            .iter()
            .filter_map(|x| metadata.packages.iter().find(|p| p.id == *x));
        for package in root_packages {
            for dep in package.dependencies.iter() {
                ret.insert(dep.name.clone());
            }
        }
        ret
    }

    #[tracing::instrument(name = "GET BLOCKCHAIN DEPENDENCY", level = "debug", skip_all)]
    pub fn get_blockchain_dependency(metadata: &Metadata) -> Result<Self> {
        let immediate_dependencies = Self::get_immediate_dependencies(metadata);
        if immediate_dependencies.contains("soroban-sdk") {
            Ok(BlockChain::Soroban)
        } else if immediate_dependencies.contains("ink") {
            Ok(BlockChain::Ink)
        } else if immediate_dependencies.contains("frame-system") {
            Ok(BlockChain::SubstratePallet)
        } else {
            Ok(BlockChain::Aptos)
        }
    }
}
