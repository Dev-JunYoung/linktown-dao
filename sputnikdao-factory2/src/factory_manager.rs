//! Module for standard generic contract factory manager.
//! 표준 일반 계약 공장 관리자를 위한 모듈.
//! TODO: move to near-sdk standards library.

use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::json_types::Base58CryptoHash;
use near_sdk::serde_json;
use near_sdk::{env, AccountId, Balance, CryptoHash, Gas};

/// Gas spent on the call & account creation.
const CREATE_CALL_GAS: Gas = Gas(40_000_000_000_000);

/// Gas allocated on the callback.
const ON_CREATE_CALL_GAS: Gas = Gas(10_000_000_000_000);

/// Leftover gas after creating promise and calling update.
/// 약속을 만들고 업데이트를 호출한 후 남은 가스.
const GAS_UPDATE_LEFTOVER: Gas = Gas(10_000_000_000_000);

const NO_DEPOSIT: Balance = 0;

/// Factory manager that allows to store/load contracts by hash directly in the storage.
/// Uses directly underlying host functions to not load any of the data into WASM memory.
/// /// 스토리지에 직접 해시 방식으로 계약을 저장/로드할 수 있는 공장 관리자.
/// 데이터를 WASM 메모리에 로드하지 않기 위해 직접적으로 기본 호스트 기능을 사용합니다
#[derive(BorshSerialize, BorshDeserialize)]
pub struct FactoryManager {}

impl FactoryManager {
    /// Store contract from input.
    pub fn store_contract(&self) {
         // 현재 환경에서 입력을 가져옵니다.
        let input = env::input().expect("ERR_NO_INPUT");
        // 입력에 대한 SHA256 해시를 계산합니다.
        let sha256_hash = env::sha256(&input);
        // 해당 해시 키가 이미 저장소에 있는지 확인합니다.
        assert!(!env::storage_has_key(&sha256_hash), "ERR_ALREADY_EXISTS");
        // 입력을 저장소에 해시를 키로 사용하여 저장합니다.
        env::storage_write(&sha256_hash, &input);
        // 반환할 바이너리 해시 배열을 준비합니다.  
        let mut blob_hash = [0u8; 32];
        // 바이너리 해시를 문자열 형식으로 변환합니다.
        blob_hash.copy_from_slice(&sha256_hash);
        let blob_hash_str = serde_json::to_string(&Base58CryptoHash::from(blob_hash))
            .unwrap()
            .into_bytes();
        // 변환된 해시 문자열을 반환합니다.
        env::value_return(&blob_hash_str);
    }

    /// Delete code from the contract.
    pub fn delete_contract(&self, code_hash: Base58CryptoHash) {
         // 코드 해시를 내부 유형으로 변환합니다.
        let code_hash: CryptoHash = code_hash.into();
        // 저장소에서 해당 해시를 사용하여 데이터를 삭제합니다.
        env::storage_remove(&code_hash);
    }

    /// Get code for given hash.
    pub fn get_code(&self, code_hash: Base58CryptoHash) {
        // 코드 해시를 내부 유형으로 변환합니다.
        let code_hash: CryptoHash = code_hash.into();
        // Check that such contract exists.
        // 해당 해시로 저장된 계약이 있는지 확인합니다.
        assert!(env::storage_has_key(&code_hash), "Contract doesn't exist");
        // Load the hash from storage.
        // 저장소에서 해당 해시의 데이터를 읽습니다.
        let code = env::storage_read(&code_hash).unwrap();
        // Return as value.
        // 읽은 데이터를 반환합니다.
        env::value_return(&code);
    }

    /// Forces update on the given contract.
    /// Contract must support update by factory for this via permission check.
    pub fn update_contract(
        &self,
        account_id: AccountId,
        code_hash: Base58CryptoHash,
        method_name: &str,
    ) {
        let code_hash: CryptoHash = code_hash.into();
        // Check that such contract exists.
        // 해당 해시로 저장된 계약이 있는지 확인합니다.
        assert!(env::storage_has_key(&code_hash), "Contract doesn't exist");
        // Load the hash from storage.
        // 저장소에서 해당 해시의 데이터를 읽습니다.
        let code = env::storage_read(&code_hash).expect("ERR_NO_HASH");
        // Create a promise toward given account.
        // 주어진 계정 ID에 프로미스 배치를 생성합니다.   
        let promise_id = env::promise_batch_create(&account_id);
        // Call `update` method, which should also handle migrations.
        // 생성된 프로미스에 함수 호출을 추가합니다. 이를 통해 계약을 업데이트합니다.
        env::promise_batch_action_function_call(
            promise_id,
            method_name,
            &code,
            NO_DEPOSIT,
            env::prepaid_gas() - env::used_gas() - GAS_UPDATE_LEFTOVER,
        );
        env::promise_return(promise_id);
    }

    /// Create given contract with args and callback factory.
    /// args 및 callback factory와 주어진 계약을 만듭니다
    pub fn create_contract(
        &self,
        code_hash: Base58CryptoHash,
        account_id: AccountId,
        new_method: &str,
        args: &[u8],
        callback_method: &str,
        callback_args: &[u8],
    ) {
        let code_hash: CryptoHash = code_hash.into();
        let attached_deposit = env::attached_deposit();
        let factory_account_id = env::current_account_id();
        // Check that such contract exists.
        assert!(env::storage_has_key(&code_hash), "Contract doesn't exist");
        // Load input (wasm code).
        let code = env::storage_read(&code_hash).expect("ERR_NO_HASH");
        // Compute storage cost.
        // 저장 비용을 계산합니다.
        let code_len = code.len();
        let storage_cost = ((code_len + 32) as Balance) * env::storage_byte_cost();
        // 첨부된 예금이 저장 비용을 충족하는지 확인합니다.
        assert!(
            attached_deposit >= storage_cost,
            "ERR_NOT_ENOUGH_DEPOSIT:{}",
            storage_cost
        );
        // Schedule a Promise tx to account_id.
        // 주어진 계정 ID에 프로미스 배치를 생성합니다.
        let promise_id = env::promise_batch_create(&account_id);
        // Create account first.
        // 새 계정을 생성합니다.
        env::promise_batch_action_create_account(promise_id);
        // Transfer attached deposit.
        // 첨부된 예금을 전송합니다.
        env::promise_batch_action_transfer(promise_id, attached_deposit);
        // Deploy contract.
        // 계약을 배포합니다.
        env::promise_batch_action_deploy_contract(promise_id, &code);
        // call `new` with given arguments.
        // 주어진 인수로 `new` 함수를 호출합니다.
        env::promise_batch_action_function_call(
            promise_id,
            new_method,
            args,
            NO_DEPOSIT,
            CREATE_CALL_GAS,
        );
        // attach callback to the factory.
        // 팩토리에 콜백을 연결합니다.
        let _ = env::promise_then(
            promise_id,
            factory_account_id,
            callback_method,
            callback_args,
            NO_DEPOSIT,
            ON_CREATE_CALL_GAS,
        );
        env::promise_return(promise_id);
    }
}
