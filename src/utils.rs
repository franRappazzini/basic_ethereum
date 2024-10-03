use ethers_core::abi::{Contract, FunctionExt, Token};
use hex::FromHexError;
use ic_cdk::api::management_canister::http_request::{
    self, http_request, CanisterHttpRequestArgument, HttpHeader, HttpMethod, TransformContext,
};
use serde::{Deserialize, Serialize};

pub fn from_hex(data: &str) -> Result<Vec<u8>, FromHexError> {
    hex::decode(&data[2..])
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct JsonRpcRequest {
    id: u64,
    jsonrpc: String,
    method: String,
    params: (EthCallParams, String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct EthCallParams {
    to: String,
    data: String,
}

pub fn to_0x(data: String) -> String {
    format!("0x{}", data)
}

pub fn create_hex_data(abi: &Contract, function_name: &str, args: &[Token]) -> String {
    let f = match abi.functions_by_name(function_name).map(|v| &v[..]) {
        Ok([f]) => f,
        Ok(fs) => panic!(
            "Found {} function overloads. Please pass one of the following: {}",
            fs.len(),
            fs.iter()
                .map(|f| format!("{:?}", f.abi_signature()))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Err(_) => abi
            .functions()
            .find(|f| function_name == f.abi_signature())
            .expect("Function not found"),
    };
    let data = f
        .encode_input(args)
        .expect("Error while encoding input args");

    hex::encode(data)
}

fn get_rpc_endpoint(network: &str) -> &'static str {
    match network {
        "mainnet" | "ethereum" => "https://cloudflare-eth.com/v1/mainnet",
        "goerli" => "https://ethereum-goerli.publicnode.com",
        "sepolia" => "https://rpc.sepolia.org",
        _ => panic!("Unsupported network: {}", network),
    }
}

/// Call an Ethereum smart contract.
pub async fn call_contract(
    network: &str,
    contract_address: String,
    abi: &Contract,
    function_name: &str,
    args: &[Token],
) -> Vec<Token> {
    let f = match abi.functions_by_name(function_name).map(|v| &v[..]) {
        Ok([f]) => f,
        Ok(fs) => panic!(
            "Found {} function overloads. Please pass one of the following: {}",
            fs.len(),
            fs.iter()
                .map(|f| format!("{:?}", f.abi_signature()))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Err(_) => abi
            .functions()
            .find(|f| function_name == f.abi_signature())
            .expect("Function not found"),
    };
    let data = f
        .encode_input(args)
        .expect("Error while encoding input args");

    // let data_hex = create_hex_data(abi, function_name, args);
    let data_hex = hex::encode(data);

    let service_url = get_rpc_endpoint(network).to_string();
    let json_rpc_payload = serde_json::to_string(&JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        method: "eth_call".to_string(),
        params: (
            EthCallParams {
                to: contract_address,
                data: to_0x(data_hex),
            },
            "latest".to_string(),
        ),
        id: 1,
    })
    .expect("Error while encoding JSON-RPC request");

    let parsed_url = url::Url::parse(&service_url).expect("Service URL parse error");
    let host = parsed_url
        .host_str()
        .expect("Invalid service URL host")
        .to_string();

    let request_headers = vec![
        HttpHeader {
            name: "Content-Type".to_string(),
            value: "application/json".to_string(),
        },
        HttpHeader {
            name: "Host".to_string(),
            value: host.to_string(),
        },
    ];
    let request = CanisterHttpRequestArgument {
        url: service_url,
        max_response_bytes: Some(/* MAX_RESPONSE_BYTES */ 2048),
        method: HttpMethod::POST,
        headers: request_headers,
        body: Some(json_rpc_payload.as_bytes().to_vec()),
        transform: Some(TransformContext::from_name("transform".to_string(), vec![])),
    };
    let result: http_request::HttpResponse =
        match http_request(request, /* HTTP_CYCLES */ 100_000_000).await {
            Ok((r,)) => r,
            Err((r, m)) => panic!("{:?} {:?}", r, m),
        };

    let json: JsonRpcResult =
        serde_json::from_str(std::str::from_utf8(&result.body).expect("utf8"))
            .expect("JSON was not well-formatted");
    if let Some(err) = json.error {
        panic!("JSON-RPC error code {}: {}", err.code, err.message);
    }
    let result = from_hex(&json.result.expect("Unexpected JSON response")).unwrap();
    f.decode_output(&result).expect("Error decoding output")
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct JsonRpcResult {
    result: Option<String>,
    error: Option<JsonRpcError>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct JsonRpcError {
    code: isize,
    message: String,
}
