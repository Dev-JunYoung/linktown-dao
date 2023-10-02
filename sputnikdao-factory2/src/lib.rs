// Factory manager 모듈을 가져옵니다.
mod factory_manager;

use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::collections::{UnorderedMap, UnorderedSet};
use near_sdk::json_types::{Base58CryptoHash, Base64VecU8, U128};
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::serde_json::{self, json};
use near_sdk::{env, near_bindgen, AccountId, Balance, CryptoHash, Gas, PanicOnDefault, Promise};

use factory_manager::FactoryManager;

// 스마트 컨트랙트의 버전을 나타내는 타입입니다.
type Version = [u8; 2];

// The keys used for writing data to storage via `env::storage_write`.
// 'env::storage_write'를 통해 스토리지에 데이터를 쓰는 데 사용되는 키입니다.
const DEFAULT_CODE_HASH_KEY: &[u8; 4] = b"CODE";
const FACTORY_OWNER_KEY: &[u8; 5] = b"OWNER";
const CODE_METADATA_KEY: &[u8; 8] = b"METADATA";

// The values used when writing initial data to the storage.
// 저장소에 초기 데이터를 쓸 때 사용되는 값입니다.
//const DAO_CONTRACT_INITIAL_CODE: &[u8] = include_bytes!("../../sputnikdao2/res/sputnikdao2.wasm");
const DAO_CONTRACT_INITIAL_CODE: &[u8] = include_bytes!("../../target/wasm32-unknown-unknown/release/sputnikdao2.wasm");
const DAO_CONTRACT_INITIAL_VERSION: Version = [3, 0];
const DAO_CONTRACT_NO_DATA: &str = "no data";

// Gas & Costs for blob storage
const GAS_STORE_CONTRACT_LEFTOVER: Gas = Gas(20_000_000_000_000);
const ON_REMOVE_CONTRACT_GAS: Gas = Gas(10_000_000_000_000);
const NO_DEPOSIT: Balance = 0;
// DAO 컨트랙트 메타데이터 구조체입니다.
// 이 구조체는 DAO 컨트랙트의 버전, GitHub의 commit ID, 변경 사항의 URL 등의 정보를 담습니다.
#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
#[cfg_attr(not(target_arch = "wasm32"), derive(Clone, Debug))]
#[serde(crate = "near_sdk::serde")]
pub struct DaoContractMetadata {
    // version of the DAO contract code (e.g. [2, 0] -> 2.0, [3, 1] -> 3.1, [4, 0] -> 4.0)
    pub version: Version,
    // commit id of https://github.com/near-daos/sputnik-dao-contract
    // representing a snapshot of the code that generated the wasm
    //wasm을 생성한 코드의 스냅샷을 나타냅니다
    pub commit_id: String,
    // if available, url to the changelog to see the changes introduced in this version
    // 사용 가능한 경우, 이 버전에 도입된 변경 사항을 보려면 changelog에 url을 입력합니다
    pub changelog_url: Option<String>,
}
// SputnikDAOFactory 스마트 컨트랙트의 주 구조체입니다.
// 이 구조체는 팩토리 매니저와 DAO 계정의 목록을 포함합니다.
#[near_bindgen]
#[derive(BorshSerialize, BorshDeserialize, PanicOnDefault)]
pub struct SputnikDAOFactory {
    factory_manager: FactoryManager,
    daos: UnorderedSet<AccountId>,
}

#[near_bindgen]
impl SputnikDAOFactory {
    #[init]
    pub fn new() -> Self {
        let this = Self {
            factory_manager: FactoryManager {},
            daos: UnorderedSet::new(b"d".to_vec()),
        };
        this.internal_store_initial_contract();
        this
    }
    //초기 DAO 계약을 저장하는 내부 기능.
    fn internal_store_initial_contract(&self) {
        //발신자가 소유자인지 확인합니다.
        self.assert_owner();
        // 초기 DAO 계약 코드를 가져와 해시를 계산합니다.
        let code = DAO_CONTRACT_INITIAL_CODE.to_vec();
        let sha256_hash = env::sha256(&code);
        // 계약 코드를 해시 단위로 저장합니다.
        env::storage_write(&sha256_hash, &code);
        // 코드 해시와 연관된 계약 메타데이터를 저장합니다.
        self.store_contract_metadata(
            slice_to_hash(&sha256_hash),
            DaoContractMetadata {
                version: DAO_CONTRACT_INITIAL_VERSION,
                commit_id: String::from(DAO_CONTRACT_NO_DATA),
                changelog_url: None,
            },
            true,
        );
    }
    // sputnikdao2 wasm 파일 임포트 
    pub fn store_additional_contract(&mut self) {
        // 발신자가 소유자인지 확인합니다.
        self.assert_owner();
        // 추가 DAO 계약 코드를 가져와 해시를 계산합니다.
        let code = DAO_CONTRACT_INITIAL_CODE.to_vec();
        let sha256_hash = env::sha256(&code);
        // 계약 코드를 해시 단위로 저장합니다.
        env::storage_write(&sha256_hash, &code);
        // 코드 해시와 연관된 계약 메타데이터를 저장합니다.
        self.store_contract_metadata(
            slice_to_hash(&sha256_hash),
            DaoContractMetadata {
                version: DAO_CONTRACT_INITIAL_VERSION,
                commit_id: String::from(DAO_CONTRACT_NO_DATA),
                changelog_url: None,
            },
            true,
        );
    }
    


    // Function to change the owner of the factory.
    // factory의 주인을 바꾸는 기능.
    pub fn set_owner(&self, owner_id: AccountId) {
        self.assert_owner();
        // 새 소유자의 계정 ID를 저장합니다.
        env::storage_write(FACTORY_OWNER_KEY, owner_id.as_bytes());
    }

    pub fn set_default_code_hash(&self, code_hash: Base58CryptoHash) {
        self.assert_owner();
        let code_hash: CryptoHash = code_hash.into();
        assert!(
            env::storage_has_key(&code_hash),
            "Code not found for the given code hash. Please store the code first."
        );
        // 기본 코드 해시를 저장합니다
        env::storage_write(DEFAULT_CODE_HASH_KEY, &code_hash);
    }
    //코드 해시로 계약을 삭제하는 함수입니다.
    pub fn delete_contract(&self, code_hash: Base58CryptoHash) {
        self.assert_owner();
        //공장 관리자를 사용하여 계약서를 삭제한 후 메타데이터를 제거합니다.
        self.factory_manager.delete_contract(code_hash);
        self.delete_contract_metadata(code_hash);
    }
     /// Function to create a new DAO.
    #[payable]
    pub fn create(&mut self, name: AccountId, args: Base64VecU8) {
        env::log_str("Function: create");
        //// 새 DAO의 전체 계정 ID를 구성합니다.
        let account_id: AccountId = format!("{}.{}", name, env::current_account_id())
            .parse()
            .unwrap();
        // Set up callback arguments for the creation.   
        let callback_args = serde_json::to_vec(&json!({
            "account_id": account_id,
            "attached_deposit": U128(env::attached_deposit()),
            "predecessor_account_id": env::predecessor_account_id()
        }))
        .expect("Failed to serialize");
        //factory_manager를 사용하여 계약서를 작성합니다.
        self.factory_manager.create_contract( // 기본 코드 해시를 나타내는 `Base58CryptoHash`를 반환합니다.
            self.get_default_code_hash(),
            account_id,
            "new",
            &args.0,
            "on_create",
            &callback_args,
        );
    }

    //DAO 생성 후 호출되는 비공개 함수
    #[private]
    pub fn on_create(
        &mut self,
        account_id: AccountId,
        attached_deposit: U128,
        predecessor_account_id: AccountId,
    ) -> bool {
        // Check if the promise was successful.
        if near_sdk::is_promise_success() {
            // Add the DAO to the list.
            self.daos.insert(&account_id);
            true
        } else {
            // 만약 실패하면 첨부된 보증금을 환불해줍니다.
            Promise::new(predecessor_account_id).transfer(attached_deposit.0);
            false
        }
    }

    /// Tries to update given account created by this factory to the specified code.
    /// 이 공장에서 만든 지정된 계정을 지정된 코드로 업데이트하려고 합니다.
    pub fn update(&self, account_id: AccountId, code_hash: Base58CryptoHash) {
        let caller_id = env::predecessor_account_id();
        // 소유자 또는 DAO 자체만 업데이트를 수행할 수 있습니다.
        assert!(
            caller_id == self.get_owner() || caller_id == account_id,
            "Must be updated by the factory owner or the DAO itself"
        );
        // DAO가 이 팩토리에서 생성되었는지 확인합니다.
        assert!(
            self.daos.contains(&account_id),
            "Must be contract created by factory"
        );
        // 팩토리 관리자를 사용하여 계약을 업데이트합니다.
        self.factory_manager
            .update_contract(account_id, code_hash, "update");
    }

    /// Allows a DAO to store the official factory version as a blob, funded by the DAO wanting to upgrade
    /// Required to successfully upgrade a DAO via proposals (proposal to store blob, proposal to upgrade from local blob)
    /// Only intended for sputnik v2 DAO's created by sputnik factory
    /// Payment is needed to cover storage costs for code blob size, paid by the DAO and returned upon blob removal
    /// DAO는 공식 버전을 공장에 저장할 수 있습니다.
    /// 이는 제안을 통한 업그레이드에 필요합니다.
    /// 저장 비용을 충당하려면 DAO가 지불하고 제거 시 반환되는 지불이 필요합니다.
    #[payable]
    pub fn store_contract_self(&mut self, code_hash: Base58CryptoHash) {
        // 현재 호출자의 계정 ID를 가져옵니다.
        let account_id = env::predecessor_account_id();
        let method_name = "store_blob";
         // 제공된 Base58CryptoHash 값을 실제 CryptoHash로 변환합니다.
        let hash: CryptoHash = code_hash.into();
        // 주어진 해시 값에 해당하는 코드가 저장되어 있는지 확인합니다.
        assert!(
            env::storage_has_key(&hash),
            "Code not found for the given code hash. Please store the code first."
        );

        // Lock down contract upgrades to this factory:
        // 이 공장에 대한 계약 업그레이드 잠금:
        let dao_id = env::predecessor_account_id().to_string();
        let idx = dao_id.find('.').expect("INTERNAL_FAIL");
        // ex: sputnik-dao.near
        // 팩토리의 계정 ID를 추출합니다.   
        let factory_id = &dao_id[idx + 1..];

        assert_eq!(
            factory_id,
            env::current_account_id().as_str(),
            "Wrong factory"
        );
        // 저장된 DAO 계약 코드를 읽어옵니다. 
        let dao_contract_code = env::storage_read(&hash).expect("CODE_HASH_NONEXIST");

        // Compute and use the correct amount needed for storage
        // 저장에 필요한 정확한 비용을 계산합니다.
        let blob_len = dao_contract_code.len();
        let storage_cost = ((blob_len + 32) as u128) * env::storage_byte_cost();

        // Confirm payment before proceeding
        // 첨부된 결제가 저장 비용을 충족하는지 확인합니다.
        assert!(
            storage_cost <= env::attached_deposit(),
            "Must at least deposit {} to store",
            storage_cost
        );

        // refund the extra cost
        let extra_attached_deposit = env::attached_deposit() - storage_cost;
        Promise::new(account_id.clone()).transfer(extra_attached_deposit);

        // Create a promise toward given account.
        let promise_id = env::promise_batch_create(&account_id);
        env::promise_batch_action_function_call(
            promise_id,
            method_name,
            &dao_contract_code,
            storage_cost,
            env::prepaid_gas() - env::used_gas() - GAS_STORE_CONTRACT_LEFTOVER,
        );
        env::promise_return(promise_id);
    }

    /// Allows a DAO to remove the blob stored in its DAO storage, and reclaim the storage cost
    pub fn remove_contract_self(&mut self, code_hash: Base58CryptoHash) {
        let account_id = env::predecessor_account_id();
        let factory_id = env::current_account_id();
        let method_name = "remove_blob";

        // NOTE: Not verifing the hash, in case factory removes a hash before DAO does
        // 주의: 팩토리가 DAO가 해시를 제거하기 전에 해시를 제거하는 경우를 대비하여 해시를 검증하지 않습니다.
        let method_args = &json!({ "hash": &code_hash }).to_string().into_bytes();
        let callback_method = "on_remove_contract_self";
        let callback_args = &json!({ "account_id": &account_id, "code_hash": &code_hash })
            .to_string()
            .into_bytes();

        // Create a promise toward given account.
        let promise_id = env::promise_batch_create(&account_id);
        env::promise_batch_action_function_call(
            promise_id,
            method_name,
            method_args,
            NO_DEPOSIT,
            GAS_STORE_CONTRACT_LEFTOVER,
        );
        // attach callback to the factory.
        // 팩토리에 콜백을 연결합니다.
        let _ = env::promise_then(
            promise_id,
            factory_id,
            callback_method,
            callback_args,
            NO_DEPOSIT,
            ON_REMOVE_CONTRACT_GAS,
        );
        // promise를 반환하여 실행을 예약합니다.
        env::promise_return(promise_id);
    }

    /// Upon blob remove, compute the balance (if any) that got paid to the factory,
    /// since it was the "owner" of the blob stored on the DAO.
    /// Send this balance back to the DAO, since it was the original funder
    /// blob이 제거된 후, 팩토리에 지불된 잔액(있는 경우)을 계산합니다.
    /// 팩토리는 DAO에 저장된 blob의 "소유자"였기 때문입니다.
    /// 이 잔액을 원래의 자금 제공자인 DAO에 돌려보냅니다.
    /**
     * 이 함수는 DAO 스토리지에서 blob (일반적으로 계약 코드나 데이터)을 제거한 후 발생하는 후처리 작업을 담당합니다. 
     * blob을 제거하면 해당 스토리지의 비용이 팩토리에 지불됩니다. 
     * 이 함수는 그 지불된 비용을 계산하여 원래의 자금 제공자인 DAO에게 반환합니다.
     */
    #[private]
    pub fn on_remove_contract_self(
        &mut self,
        account_id: AccountId,
        code_hash: Base58CryptoHash,
    ) -> bool {
         // Promise의 성공 여부를 확인합니다.
        if near_sdk::is_promise_success() {
            // Compute the actual storage cost for an accurate refund
            // 정확한 환불을 위한 실제 스토리지 비용을 계산합니다.
            let hash: CryptoHash = code_hash.into();
            // 해당 해시로 스토리지에서 계약 코드를 읽어옵니다.
            let dao_contract_code = env::storage_read(&hash).expect("CODE_HASH_NONEXIST");
            // blob의 길이를 계산합니다.
            let blob_len = dao_contract_code.len();
            // 스토리지 비용을 계산합니다.
            let storage_cost = ((blob_len + 32) as u128) * env::storage_byte_cost();
            // 계산된 스토리지 비용을 DAO에게 전송합니다.
            Promise::new(account_id).transfer(storage_cost);
            // 성공적으로 처리되었음을 나타내는 true 값을 반환합니다.
            true
        } else {
            false
        }
    }
    /// Returns a list of all registered DAOs.
    /// 모든 등록된 DAOs의 리스트를 반환합니다.
    pub fn get_dao_list(&self) -> Vec<AccountId> {
        self.daos.to_vec()
    }

    /// Get number of created DAOs.
    /// 생성된 총 DAO 수를 검색합니다.
    pub fn get_number_daos(&self) -> u64 {
        self.daos.len()
    }

    /// Get daos in paginated view.
    /// 페이지네이션 방식으로 DAOs를 가져옵니다.
    ///
    /// 총 DAOs의 수가 많을 경우 더 효율적인 쿼리를 위해 사용됩니다.
    /// #param
    /// * `from_index` - 페이지네이션을 위한 시작 인덱스.
    /// * `limit` - 반환할 DAOs의 최대 수.
    /// #return
    /// 지정된 범위 내의 DAOs를 나타내는 `AccountId`의 벡터입니다.
    pub fn get_daos(&self, from_index: u64, limit: u64) -> Vec<AccountId> {
        let elements = self.daos.as_vector();
        (from_index..std::cmp::min(from_index + limit, elements.len()))
            .filter_map(|index| elements.get(index))
            .collect()
    }


    /// 소유자의 계정 ID를 가져옵니다.
    ///
    /// 저장소에서 소유자 키를 찾을 수 없는 경우 현재 계정 ID를 기본값으로 사용합니다.
    /// 
    /// # 반환값
    /// 
    /// 팩토리 소유자의 `AccountId`입니다.
    pub fn get_owner(&self) -> AccountId {
        AccountId::new_unchecked(
            String::from_utf8(
                env::storage_read(FACTORY_OWNER_KEY)
                    .unwrap_or(env::current_account_id().as_bytes().to_vec()),
            )
            .expect("INTERNAL_FAIL"),
        )
    }
    /// 저장소에서 기본 코드 해시를 검색합니다.
    /// 
    /// # 반환값
    /// 
    /// 기본 코드 해시를 나타내는 `Base58CryptoHash`를 반환합니다.
    pub fn get_default_code_hash(&self) -> Base58CryptoHash {
        slice_to_hash(&env::storage_read(DEFAULT_CODE_HASH_KEY).expect("Must have code hash"))
    }
    /// 저장소에서 DAO 계약의 기본 버전을 가져옵니다.
    ///
    /// 기본 버전은 저장된 메타데이터에서 추출됩니다.
    ///
    /// # 반환값
    ///
    /// DAO 계약의 기본 버전을 나타내는 `Version` 객체입니다.
    pub fn get_default_version(&self) -> Version {
        let storage_metadata = env::storage_read(CODE_METADATA_KEY).expect("INTERNAL_FAIL");
        let deserialized_metadata: UnorderedMap<Base58CryptoHash, DaoContractMetadata> =
            BorshDeserialize::try_from_slice(&storage_metadata).expect("INTERNAL_FAIL");
        let default_metadata = deserialized_metadata
            .get(&self.get_default_code_hash())
            .expect("INTERNAL_FAIL");
        default_metadata.version
    }

    /// Returns non serialized code by given code hash.
    /// 주어진 코드 해시에 의해 직렬화되지 않은 코드를 반환합니다.
    pub fn get_code(&self, code_hash: Base58CryptoHash) {
        self.factory_manager.get_code(code_hash);
    }
    /// Store metadata for a specific DAO contract.
    /// 특정 DAO 컨트랙트에 대한 메타데이터를 저장합니다.
    pub fn store_contract_metadata(
        &self,
        code_hash: Base58CryptoHash,
        metadata: DaoContractMetadata,
        set_default: bool,
    ) {
        // Ensure only the owner can execute this function.
        // 이 함수를 실행할 수 있는 것은 오너만이어야 합니다.
        self.assert_owner();
        let hash: CryptoHash = code_hash.into();
        // Ensure that the code exists before storing metadata.
        // 메타데이터를 저장하기 전에 코드가 존재하는지 확인합니다. 
        assert!(
            env::storage_has_key(&hash),
            "Code not found for the given code hash. Please store the code first."
        );
        // Read the stored metadata, if it exists.
        // 저장된 메타데이터를 읽습니다(존재하는 경우).
        let storage_metadata = env::storage_read(CODE_METADATA_KEY);
        if storage_metadata.is_none() {
            // If not, initialize a new metadata map and insert the new data.
            // 없다면 새 메타데이터 맵을 초기화하고 새 데이터를 삽입합니다
            let mut storage_metadata: UnorderedMap<Base58CryptoHash, DaoContractMetadata> =
                UnorderedMap::new(b"m".to_vec());
            storage_metadata.insert(&code_hash, &metadata);
            let serialized_metadata =
                BorshSerialize::try_to_vec(&storage_metadata).expect("INTERNAL_FAIL");
            env::storage_write(CODE_METADATA_KEY, &serialized_metadata);
        } else {
            // If existing metadata is found, deserialize, update and re-serialize.
            // 기존 메타데이터가 발견되면 역직렬화, 업데이트 및 재직렬화를 수행합니다.
            let storage_metadata = storage_metadata.expect("INTERNAL_FAIL");
            let mut deserialized_metadata: UnorderedMap<Base58CryptoHash, DaoContractMetadata> =
                BorshDeserialize::try_from_slice(&storage_metadata).expect("INTERNAL_FAIL");
            deserialized_metadata.insert(&code_hash, &metadata);
            let serialized_metadata =
                BorshSerialize::try_to_vec(&deserialized_metadata).expect("INTERNAL_FAIL");
            env::storage_write(CODE_METADATA_KEY, &serialized_metadata);
        }

        if set_default {
            env::storage_write(DEFAULT_CODE_HASH_KEY, &hash);
        }
    }

    /// Delete metadata for a specific DAO contract.
    /// 특정 DAO 컨트랙트의 메타데이터를 삭제합니다.
    pub fn delete_contract_metadata(&self, code_hash: Base58CryptoHash) {
        // Ensure only the owner can execute this function.
        // 이 함수를 실행할 수 있는 것은 오너만이어야 합니다.
        self.assert_owner();

        let storage_metadata = env::storage_read(CODE_METADATA_KEY).expect("INTERNAL_FAIL");
        let mut deserialized_metadata: UnorderedMap<Base58CryptoHash, DaoContractMetadata> =
            BorshDeserialize::try_from_slice(&storage_metadata).expect("INTERNAL_FAIL");
        // Remove the specified metadata.
        // 지정된 메타데이터를 제거합니다.
        deserialized_metadata.remove(&code_hash);
        let serialized_metadata =
            BorshSerialize::try_to_vec(&deserialized_metadata).expect("INTERNAL_FAIL");
        env::storage_write(CODE_METADATA_KEY, &serialized_metadata);
    }

    /// Get all contract metadata.
    /// 모든 컨트랙트 메타데이터를 가져옵니다.
    pub fn get_contracts_metadata(&self) -> Vec<(Base58CryptoHash, DaoContractMetadata)> {
        let storage_metadata = env::storage_read(CODE_METADATA_KEY).expect("INTERNAL_FAIL");
        let deserialized_metadata: UnorderedMap<Base58CryptoHash, DaoContractMetadata> =
            BorshDeserialize::try_from_slice(&storage_metadata).expect("INTERNAL_FAIL");
        return deserialized_metadata.to_vec();
    }
    /// Ensure that the function is executed by the owner.
    /// 함수가 오너에 의해 실행되는지 확인합니다.
    fn assert_owner(&self) {
        assert_eq!(
            self.get_owner(),
            env::predecessor_account_id(),
            "Must be owner"
        );
    }
}

pub fn slice_to_hash(hash: &[u8]) -> Base58CryptoHash {
    let mut result: CryptoHash = [0; 32];
    result.copy_from_slice(&hash);
    Base58CryptoHash::from(result)
}

/// Store new contract. Non serialized argument is the contract.
/// Returns base58 of the hash of the contract.
#[no_mangle]
pub extern "C" fn store() {
    env::setup_panic_hook();
    let contract: SputnikDAOFactory = env::state_read().expect("Contract is not initialized");
    contract.assert_owner();
    let prev_storage = env::storage_usage();
    contract.factory_manager.store_contract();
    let storage_cost = (env::storage_usage() - prev_storage) as u128 * env::storage_byte_cost();
    assert!(
        storage_cost <= env::attached_deposit(),
        "Must at least deposit {} to store",
        storage_cost
    );
}

#[cfg(test)]
mod tests {
    use near_sdk::test_utils::test_env::{alice, bob, carol};
    use near_sdk::test_utils::{accounts, VMContextBuilder};
    use near_sdk::{testing_env, PromiseResult};

    use near_sdk_sim::to_yocto;

    use super::*;

    #[test]
    #[should_panic(expected = "ERR_NOT_ENOUGH_DEPOSIT")]
    fn test_create_error() {
        let mut context = VMContextBuilder::new();
        testing_env!(context
            .current_account_id(accounts(0))
            .predecessor_account_id(accounts(0))
            .build());
        let mut factory = SputnikDAOFactory::new();

        testing_env!(context.attached_deposit(to_yocto("5")).build());
        factory.create("test".parse().unwrap(), "{}".as_bytes().to_vec().into());
    }

    #[test]
    fn test_basics() {
        let mut context = VMContextBuilder::new();
        testing_env!(context
            .current_account_id(accounts(0))
            .predecessor_account_id(accounts(0))
            .build());
        let mut factory = SputnikDAOFactory::new();

        testing_env!(context.attached_deposit(to_yocto("6")).build());
        factory.create("test".parse().unwrap(), "{}".as_bytes().to_vec().into());

        testing_env!(
            context.predecessor_account_id(accounts(0)).build(),
            near_sdk::VMConfig::test(),
            near_sdk::RuntimeFeesConfig::test(),
            Default::default(),
            vec![PromiseResult::Successful(vec![])],
        );
        factory.on_create(
            format!("test.{}", accounts(0)).parse().unwrap(),
            U128(to_yocto("6")),
            accounts(0),
        );
        assert_eq!(
            factory.get_dao_list(),
            vec![format!("test.{}", accounts(0)).parse().unwrap()]
        );
        assert_eq!(
            factory.get_daos(0, 100),
            vec![format!("test.{}", accounts(0)).parse().unwrap()]
        );
    }

    //              #################################              //
    //              #    Factory ownership tests    #              //
    //              #################################              //

    #[test]
    fn test_factory_can_get_current_owner() {
        let mut context = VMContextBuilder::new();
        testing_env!(context
            .current_account_id(alice())
            .predecessor_account_id(alice())
            .attached_deposit(to_yocto("5"))
            .build());
        let factory = SputnikDAOFactory::new();

        assert_eq!(factory.get_owner(), alice());
    }

    #[test]
    #[should_panic]
    fn test_factory_fails_setting_owner_from_not_owner_account() {
        let mut context = VMContextBuilder::new();
        testing_env!(context
            .current_account_id(alice())
            .predecessor_account_id(carol())
            .attached_deposit(to_yocto("5"))
            .build());
        let factory = SputnikDAOFactory::new();

        factory.set_owner(bob());
    }

    #[test]
    fn test_owner_can_be_a_dao_account() {
        let mut context = VMContextBuilder::new();
        testing_env!(context
            .current_account_id(bob())
            .predecessor_account_id(bob())
            .attached_deposit(to_yocto("6"))
            .build());
        let mut factory = SputnikDAOFactory::new();

        factory.create(bob(), "{}".as_bytes().to_vec().into());

        factory.set_owner(AccountId::new_unchecked("bob.sputnik-dao.near".to_string()));

        assert_eq!(
            factory.get_owner(),
            AccountId::new_unchecked("bob.sputnik-dao.near".to_string())
        )
    }

    #[test]
    fn test_owner_gets_succesfully_updated() {
        let mut context = VMContextBuilder::new();
        testing_env!(context
            .current_account_id(accounts(0))
            .predecessor_account_id(accounts(0))
            .attached_deposit(to_yocto("5"))
            .build());
        let factory = SputnikDAOFactory::new();

        assert_ne!(factory.get_owner(), bob());

        factory.set_owner(bob());

        assert_eq!(factory.get_owner(), bob())
    }
}
