#![no_std]

use soroban_sdk::{contract, contractimpl};

#[contract]
pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn test() -> u64 {
        (1 * 100) / 2
    }
}
