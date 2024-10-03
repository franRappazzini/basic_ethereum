mod ecdsa;
mod ethereum_wallet;
mod state;
mod utils;

use crate::ethereum_wallet::EthereumWallet;
use crate::state::{init_state, read_state};
use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope, TxLegacy};
use alloy_eips::eip6110::DepositRequest;
use alloy_primitives::hex::FromHex;
use alloy_primitives::{hex, keccak256, Bytes, Signature, TxKind, U256};
use candid::{CandidType, Deserialize, Nat, Principal};
use ethers_core::abi::Contract;
use ethers_core::abi::{Abi, Token};
use ethers_core::types::Address;
use evm_rpc_canister_types::{
    BlockTag, EthMainnetService, EthSepoliaService, EvmRpcCanister, FeeHistory, FeeHistoryArgs,
    FeeHistoryResult, GetTransactionCountArgs, GetTransactionCountResult, MultiFeeHistoryResult,
    MultiGetTransactionCountResult, MultiSendRawTransactionResult, RequestResult, RpcService,
    RpcServices,
};
use ic_cdk::api::management_canister::ecdsa::{EcdsaCurve, EcdsaKeyId};
use ic_cdk::api::management_canister::http_request::{HttpResponse, TransformArgs};
use ic_cdk::{init, query, update};
use num::{BigUint, Num};
use serde::Serialize;
use std::rc::Rc;
use std::str::FromStr;
use utils::{call_contract, create_hex_data, to_0x};
pub const EVM_RPC_CANISTER_ID: Principal =
    Principal::from_slice(b"\x00\x00\x00\x00\x02\x30\x00\xCC\x01\x01"); // 7hfb6-caaaa-aaaar-qadga-cai
pub const EVM_RPC: EvmRpcCanister = EvmRpcCanister(EVM_RPC_CANISTER_ID);

thread_local! {
    static TEST: Rc<Contract> = Rc::new(include_abi!("./abi/Test.json"))
}

#[init]
pub fn init(maybe_init: Option<InitArg>) {
    if let Some(init_arg) = maybe_init {
        init_state(init_arg)
    }
}

#[update]
pub async fn ethereum_address(owner: Option<Principal>) -> String {
    let caller = validate_caller_not_anonymous();
    let owner = owner.unwrap_or(caller);
    let wallet = EthereumWallet::new(owner).await;
    wallet.ethereum_address().to_string()
}

#[update]
pub async fn get_balance(address: Option<String>) -> Nat {
    let address = address.unwrap_or(ethereum_address(None).await);

    let json = format!(
        r#"{{ "jsonrpc": "2.0", "method": "eth_getBalance", "params": ["{}", "latest"], "id": 1 }}"#,
        address
    );

    let max_response_size_bytes = 500_u64;
    let num_cycles = 1_000_000_000u128;

    let ethereum_network = read_state(|s| s.ethereum_network());

    let rpc_service = match ethereum_network {
        EthereumNetwork::Mainnet => RpcService::EthMainnet(EthMainnetService::PublicNode),
        EthereumNetwork::Sepolia => RpcService::EthSepolia(EthSepoliaService::PublicNode),
    };

    let (response,) = EVM_RPC
        .request(rpc_service, json, max_response_size_bytes, num_cycles)
        .await
        .expect("RPC call failed");

    let hex_balance = match response {
        RequestResult::Ok(balance_result) => {
            // The response to a successful `eth_getBalance` call has the following format:
            // { "id": "[ID]", "jsonrpc": "2.0", "result": "[BALANCE IN HEX]" }
            let response: serde_json::Value = serde_json::from_str(&balance_result).unwrap();
            response
                .get("result")
                .and_then(|v| v.as_str())
                .unwrap()
                .to_string()
        }
        RequestResult::Err(e) => panic!("Received an error response: {:?}", e),
    };

    // Remove the "0x" prefix before converting to a decimal number.
    Nat(BigUint::from_str_radix(&hex_balance[2..], 16).unwrap())
}

#[update]
pub async fn transaction_count(owner: Option<Principal>, block: Option<BlockTag>) -> Nat {
    let caller = validate_caller_not_anonymous();
    let owner = owner.unwrap_or(caller);
    let wallet = EthereumWallet::new(owner).await;
    let rpc_services = read_state(|s| s.single_evm_rpc_service());
    let args = GetTransactionCountArgs {
        address: wallet.ethereum_address().to_string(),
        block: block.unwrap_or(BlockTag::Finalized),
    };
    let (result,) = EVM_RPC
        .eth_get_transaction_count(rpc_services, None, args.clone(), 2_000_000_000_u128)
        .await
        .unwrap_or_else(|e| {
            panic!(
                "failed to get transaction count for {:?}, error: {:?}",
                args, e
            )
        });
    match result {
        MultiGetTransactionCountResult::Consistent(consistent_result) => match consistent_result {
            GetTransactionCountResult::Ok(count) => count,
            GetTransactionCountResult::Err(error) => {
                ic_cdk::trap(&format!("failed to get transaction count for {:?}, error: {:?}",args, error))
            }
        },
        MultiGetTransactionCountResult::Inconsistent(inconsistent_results) => {
            ic_cdk::trap(&format!("inconsistent results when retrieving transaction count for {:?}. Received results: {:?}", args, inconsistent_results))
        }
    }
}

#[update]
pub async fn send_eth(to: String, amount: Nat) -> (String, u64, MultiSendRawTransactionResult) {
    use alloy_eips::eip2718::Encodable2718;

    let caller = validate_caller_not_anonymous();
    let _to_address = Address::from_str(&to).unwrap_or_else(|e| {
        ic_cdk::trap(&format!("failed to parse the recipient address: {:?}", e))
    });
    let chain_id = read_state(|s| s.ethereum_network().chain_id());
    let nonce = nat_to_u64(transaction_count(Some(caller), Some(BlockTag::Pending)).await);
    let (gas_limit, max_fee_per_gas, max_priority_fee_per_gas) = estimate_transaction_fees();

    // (
    //     chain_id,
    //     nonce,
    //     gas_limit,
    //     max_fee_per_gas,
    //     max_priority_fee_per_gas,
    // )

    let transaction = TxEip1559 {
        chain_id,
        nonce,
        gas_limit,
        max_fee_per_gas,
        max_priority_fee_per_gas,
        to: TxKind::Call(to.parse().expect("failed to parse recipient address")),
        value: nat_to_u256(amount),
        access_list: Default::default(),
        input: Default::default(),
    };

    let wallet = EthereumWallet::new(caller).await;
    let tx_hash = transaction.signature_hash().0;
    let (raw_signature, recovery_id) = wallet.sign_with_ecdsa(tx_hash).await;
    let signature = Signature::from_bytes_and_parity(&raw_signature, recovery_id.is_y_odd())
        .expect("BUG: failed to create a signature");
    let signed_tx = transaction.into_signed(signature);

    let raw_transaction_hash = *signed_tx.hash();
    let mut tx_bytes: Vec<u8> = vec![];
    TxEnvelope::from(signed_tx).encode_2718(&mut tx_bytes);
    let raw_transaction_hex = format!("0x{}", hex::encode(&tx_bytes));
    ic_cdk::println!(
        "Sending raw transaction hex {} with transaction hash {}",
        raw_transaction_hex,
        raw_transaction_hash
    );
    // The canister is sending a signed statement, meaning a malicious provider could only affect availability.
    // For demonstration purposes, the canister uses a single provider to send the signed transaction,
    // but in production multiple providers (e.g., using a round-robin strategy) should be used to avoid a single point of failure.
    let single_rpc_service = read_state(|s| s.single_evm_rpc_service());
    let (result,) = EVM_RPC
        .eth_send_raw_transaction(
            single_rpc_service,
            None,
            raw_transaction_hex.clone(),
            2_000_000_000_u128,
        )
        .await
        .unwrap_or_else(|e| {
            panic!(
                "failed to send raw transaction {}, error: {:?}",
                raw_transaction_hex, e
            )
        });
    ic_cdk::println!(
        "Result of sending raw transaction {}: {:?}. \
    Due to the replicated nature of HTTPs outcalls, an error such as transaction already known or nonce too low could be reported, \
    even though the transaction was successfully sent. \
    Check whether the transaction appears on Etherscan or check that the transaction count on \
    that address at latest block height did increase.",
        raw_transaction_hex,
        result
    );

    (raw_transaction_hash.to_string(), nonce, result)
}

fn estimate_transaction_fees() -> (u128, u128, u128) {
    /// Standard gas limit for an Ethereum transfer to an EOA.
    /// Other transactions, in particular ones interacting with a smart contract (e.g., ERC-20), would require a higher gas limit.
    const GAS_LIMIT: u128 = 21_000;

    /// Very crude estimates of max_fee_per_gas and max_priority_fee_per_gas.
    /// A real world application would need to estimate this more accurately by for example fetching the fee history from the last 5 blocks.
    const MAX_FEE_PER_GAS: u128 = 350_188_139_150;
    const MAX_PRIORITY_FEE_PER_GAS: u128 = 1_500_000_000;
    // const MAX_PRIORITY_FEE_PER_GAS: u128 = 2_500_000_000;
    (GAS_LIMIT, MAX_FEE_PER_GAS, MAX_PRIORITY_FEE_PER_GAS)
}

#[update]
async fn avg_fees(block_count: u8) -> (u128, u128) {
    // TODO (fran): estimar cycles automaticamente
    let num_cycles = 1_000_000_000u128;
    let ethereum_network = read_state(|s| s.ethereum_network());

    let rpc_services = match ethereum_network {
        EthereumNetwork::Mainnet => {
            RpcServices::EthMainnet(Some(vec![EthMainnetService::PublicNode]))
        }
        EthereumNetwork::Sepolia => {
            RpcServices::EthSepolia(Some(vec![EthSepoliaService::PublicNode]))
        }
    };

    let fee_history_args: FeeHistoryArgs = FeeHistoryArgs {
        blockCount: Nat::from(block_count),
        newestBlock: BlockTag::Latest,
        rewardPercentiles: None,
    };

    let (response,) = EVM_RPC
        .eth_fee_history(rpc_services, None, fee_history_args, num_cycles)
        .await
        .expect("RPC call failed");

    let (max_fee_per_gas, max_priority_fee_per_gas) = match response {
        MultiFeeHistoryResult::Consistent(fee_history_result) => match fee_history_result {
            FeeHistoryResult::Ok(val) => {
                // parse the last 5 blocks

                let val = val.unwrap();
                let base_fees = &val.baseFeePerGas;
                // let rewards = &val.reward;

                let last_x_fees = &base_fees[base_fees.len() - 5..];
                // let last_x_rewards = &rewards[rewards.len() - 5..]; // FIXME (fran): rewards is empty => creo que porque es sepolia

                let total_fee: u128 = last_x_fees.iter().map(|n| nat_to_u128(n.clone())).sum();
                // let total_reward: u128 = last_x_rewards
                //     .iter()
                //     .map(|v| nat_to_u128(v[0].clone()))
                //     .sum();

                let avg_max_fee_per_gas = total_fee / last_x_fees.len() as u128;
                // let avg_max_priority_fee_per_gas = total_reward / last_x_rewards.len() as u128;

                (
                    avg_max_fee_per_gas,
                    /*  avg_max_priority_fee_per_gas */ 1_500_000_000_u128,
                )
            }
            FeeHistoryResult::Err(e) => {
                panic!("Received an error response on `eth_fee_history`: {:?}", e);
            }
        },
        MultiFeeHistoryResult::Inconsistent(inc) => {
            panic!(
                "Received an inconsistent response on `eth_fee_history`: {:?}",
                inc
            );
        }
    };

    (max_fee_per_gas, max_priority_fee_per_gas)
}

#[update]
async fn calculate_gas_limit(from: String, to: String, value: String, data: String) -> u128 {
    let json = format!(
        r#"{{
            "jsonrpc": "2.0",
            "method": "eth_estimateGas",
            "params": [
                {{
                "from": "{}",
                "to": "{}",
                "value": "{}",
                "data": "{}"
                }}
            ],
            "id": 1
        }}"#,
        from, to, value, data
    );

    // TODO (fran): automatizar cycles
    let max_response_size_bytes = 1000_u64;
    let num_cycles = 1_000_000_000u128;

    let ethereum_network = read_state(|s| s.ethereum_network());

    let rpc_service = match ethereum_network {
        EthereumNetwork::Mainnet => RpcService::EthMainnet(EthMainnetService::PublicNode),
        EthereumNetwork::Sepolia => RpcService::EthSepolia(EthSepoliaService::PublicNode),
    };

    let (response,) = EVM_RPC
        .request(
            rpc_service,
            json.to_string(),
            max_response_size_bytes,
            num_cycles,
        )
        .await
        .expect("RPC call failed");

    match response {
        RequestResult::Ok(estimate_gas) => {
            let eth_estimate_gas: EthEstimateGasResponse =
                serde_json::from_str(&estimate_gas).unwrap();

            let hex_gas = eth_estimate_gas.result;
            let gas_used = u128::from_str_radix(&hex_gas[2..], 16).unwrap();
            gas_used
        }
        RequestResult::Err(e) => panic!("Received an error response: {:?}", e),
    }
}

// TODO (fran): setear bien cantidad de cycles para llamados
// https://internetcomputer.org/docs/current/developer-docs/multi-chain/ethereum/evm-rpc/costs#attaching-the-correct-amount-of-cycles
#[update]
async fn update_call_custom_contract(
    function_name: String,
    value: u128,
) -> (String, u64, MultiSendRawTransactionResult) {
    use alloy_eips::eip2718::Encodable2718;

    let caller = validate_caller_not_anonymous();
    // let _to_address = Address::from_str(&to).unwrap_or_else(|e| {
    //     ic_cdk::trap(&format!("failed to parse the recipient address: {:?}", e))
    // });
    let chain_id = read_state(|s| s.ethereum_network().chain_id());
    let nonce = nat_to_u64(transaction_count(Some(caller), Some(BlockTag::Pending)).await);
    let (_gas_limit, max_fee_per_gas, max_priority_fee_per_gas) = estimate_transaction_fees();

    // let value = 0u8;
    let value_hex = format!("0x{:x}", value);
    let abi = &TEST.with(Rc::clone);

    let data_hex = create_hex_data(abi, &function_name, &[Token::Uint(20_000_000_u64.into())]);

    let wallet = EthereumWallet::new(caller).await;
    let to = "0x46D1239bB2b9E0b1e14E475FD86ed4a3C3C1e31E";

    let tx: TxEip1559 = TxEip1559 {
        chain_id,
        nonce,
        gas_limit: calculate_gas_limit(
            wallet.ethereum_address().to_string(),
            to.to_string(),
            value_hex,
            to_0x(data_hex.clone()),
        )
        .await,
        max_fee_per_gas,
        max_priority_fee_per_gas,
        to: TxKind::Call(to.parse().expect("failed to parse recipient address")),
        value: nat_to_u256(Nat::from(value)),
        input: Bytes::from_hex(data_hex).expect("failed to parse input"),
        access_list: Default::default(),
    };

    let tx_hash = tx.signature_hash().0;
    let (raw_signature, recovery_id) = wallet.sign_with_ecdsa(tx_hash).await;
    let signature = Signature::from_bytes_and_parity(&raw_signature, recovery_id.is_y_odd())
        .expect("BUG: failed to create a signature");
    let signed_tx = tx.into_signed(signature);

    let raw_transaction_hash = *signed_tx.hash();
    let mut tx_bytes: Vec<u8> = vec![];
    TxEnvelope::from(signed_tx).encode_2718(&mut tx_bytes);
    let raw_transaction_hex = format!("0x{}", hex::encode(&tx_bytes));
    ic_cdk::println!(
        "Sending raw transaction hex {} with transaction hash {}",
        raw_transaction_hex,
        raw_transaction_hash
    );
    // The canister is sending a signed statement, meaning a malicious provider could only affect availability.
    // TODO (fran): For demonstration purposes, the canister uses a single provider to send the signed transaction,
    // but in production multiple providers (e.g., using a round-robin strategy) should be used to avoid a single point of failure.
    let single_rpc_service = read_state(|s| s.single_evm_rpc_service());
    let (result,) = EVM_RPC
        .eth_send_raw_transaction(
            single_rpc_service,
            None,
            raw_transaction_hex.clone(),
            2_000_000_000_u128,
        )
        .await
        .unwrap_or_else(|e| {
            panic!(
                "failed to send raw transaction {}, error: {:?}",
                raw_transaction_hex, e
            )
        });
    ic_cdk::println!(
        "Result of sending raw transaction {}: {:?}. \
    Due to the replicated nature of HTTPs outcalls, an error such as transaction already known or nonce too low could be reported, \
    even though the transaction was successfully sent. \
    Check whether the transaction appears on Etherscan or check that the transaction count on \
    that address at latest block height did increase.",
        raw_transaction_hex,
        result
    );

    (raw_transaction_hash.to_string(), nonce, result)
}

#[update]
async fn query_call_custom_contact(function_name: String) -> u128 {
    let abi = &TEST.with(Rc::clone);

    let result = call_contract(
        "sepolia",
        "0x46D1239bB2b9E0b1e14E475FD86ed4a3C3C1e31E".to_string(),
        abi,
        &function_name,
        &[Token::Address(
            Address::from_str("0x22Ff826A4af6408bdC07a63435744B61c0e71A1F").unwrap(),
        )],
    )
    .await;

    match result.get(0) {
        Some(Token::Uint(n)) => n.as_u128(),
        _ => panic!("Unexpected result"),
    }
}

#[derive(CandidType, Deserialize, Debug, Default, PartialEq, Eq)]
pub struct InitArg {
    pub ethereum_network: Option<EthereumNetwork>,
    pub ecdsa_key_name: Option<EcdsaKeyName>,
}

#[derive(CandidType, Deserialize, Debug, Default, PartialEq, Eq, Clone, Copy)]
pub enum EthereumNetwork {
    Mainnet,
    #[default]
    Sepolia,
}

impl EthereumNetwork {
    pub fn chain_id(&self) -> u64 {
        match self {
            EthereumNetwork::Mainnet => 1,
            EthereumNetwork::Sepolia => 11155111,
        }
    }
}

#[derive(CandidType, Deserialize, Debug, Default, PartialEq, Eq, Clone)]
pub enum EcdsaKeyName {
    #[default]
    TestKeyLocalDevelopment,
    TestKey1,
    ProductionKey1,
}

impl From<&EcdsaKeyName> for EcdsaKeyId {
    fn from(value: &EcdsaKeyName) -> Self {
        EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name: match value {
                EcdsaKeyName::TestKeyLocalDevelopment => "dfx_test_key",
                EcdsaKeyName::TestKey1 => "test_key_1",
                EcdsaKeyName::ProductionKey1 => "key_1",
            }
            .to_string(),
        }
    }
}

pub fn validate_caller_not_anonymous() -> Principal {
    let principal = ic_cdk::caller();
    if principal == Principal::anonymous() {
        panic!("anonymous principal is not allowed");
    }
    principal
}

fn nat_to_u64(nat: Nat) -> u64 {
    use num_traits::cast::ToPrimitive;
    nat.0
        .to_u64()
        .unwrap_or_else(|| ic_cdk::trap(&format!("Nat {} doesn't fit into a u64", nat)))
}

fn nat_to_u128(nat: Nat) -> u128 {
    use num_traits::cast::ToPrimitive;
    nat.0
        .to_u128()
        .unwrap_or_else(|| ic_cdk::trap(&format!("Nat {} doesn't fit into a u128", nat)))
}

fn nat_to_u256(value: Nat) -> U256 {
    let value_bytes = value.0.to_bytes_be();
    assert!(
        value_bytes.len() <= 32,
        "Nat does not fit in a U256: {}",
        value
    );
    let mut value_u256 = [0u8; 32];
    value_u256[32 - value_bytes.len()..].copy_from_slice(&value_bytes);
    U256::from_be_bytes(value_u256)
}

#[derive(Serialize, Deserialize, Debug)]
#[allow(non_snake_case)]
struct ResultData {
    baseFeePerBlobGas: Vec<String>,
    baseFeePerGas: Vec<String>,
    blobGasUsedRatio: Vec<f64>,
    gasUsedRatio: Vec<f64>,
    oldestBlock: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct EthFeeHistoryResponse {
    id: u32,
    jsonrpc: String,
    result: ResultData,
}

#[derive(Serialize, Deserialize, Debug)]
struct EthEstimateGasResponse {
    id: u32,
    jsonrpc: String,
    result: String,
}

#[query]
fn transform(args: TransformArgs) -> HttpResponse {
    HttpResponse {
        status: args.response.status.clone(),
        body: args.response.body,
        // Strip headers as they contain the Date which is not necessarily the same
        // and will prevent consensus on the result.
        headers: Vec::new(),
    }
}

// Enable Candid export
ic_cdk::export_candid!();

// 2_048_000_000_000_000_000_000_000
// 70_509_978_562_327_059
