use crate::*;

impl Contract {
    /// 주어진 account_id에 대한 사용자의 위임 가중치를 반환합니다.
    pub fn get_user_weight(&self, account_id: &AccountId) -> Balance {
        self.delegations.get(account_id).unwrap_or_default()
    }
}

#[near_bindgen]
impl Contract {
    #[payable] /// 주어진 account_id로 위임을 등록합니다.
    pub fn register_delegation(&mut self, account_id: &AccountId) {
        let staking_id = self.staking_id.clone().expect("ERR_NO_STAKING");
        // 호출자가 스테이킹 계정과 일치하는지 확인합니다.
        assert_eq!(
            env::predecessor_account_id(),
            staking_id,
            "ERR_INVALID_CALLER"
        );
        // 첨부된 예금이 저장 비용과 일치하는지 확인합니다.
        assert_eq!(env::attached_deposit(), 16 * env::storage_byte_cost());
        self.delegations.insert(account_id, &0);
    }

    /// Adds given amount to given account as delegated weight.
    /// Returns previous amount, new amount and total delegated amount.
    /// 주어진 계정에 주어진 양을 위임 가중치로 추가합니다.
    /// 이전 양, 새 양, 총 위임된 양을 반환합니다.
    pub fn delegate(&mut self, account_id: &AccountId, amount: U128) -> (U128, U128, U128) {
        let staking_id = self.staking_id.clone().expect("ERR_NO_STAKING");
        // 호출자가 스테이킹 계정과 일치하는지 확인합니다
        assert_eq!(
            env::predecessor_account_id(),
            staking_id,
            "ERR_INVALID_CALLER"
        );
        let prev_amount = self
            .delegations
            .get(account_id)
            .expect("ERR_NOT_REGISTERED");
        let new_amount = prev_amount + amount.0;
        self.delegations.insert(account_id, &new_amount);
        self.total_delegation_amount += amount.0;
        (
            U128(prev_amount),
            U128(new_amount),
            self.delegation_total_supply(),
        )
    }

    /// Removes given amount from given account's delegations.
    /// Returns previous, new amount of this account and total delegated amount.
    /// 주어진 계정의 위임에서 주어진 양을 제거합니다.
    /// 이 계정의 이전, 새로운 양 및 총 위임된 양을 반환합니다.
    pub fn undelegate(&mut self, account_id: &AccountId, amount: U128) -> (U128, U128, U128) {
        let staking_id = self.staking_id.clone().expect("ERR_NO_STAKING");
        assert_eq!(
            env::predecessor_account_id(),
            staking_id,
            "ERR_INVALID_CALLER"
        );
        let prev_amount = self.delegations.get(account_id).unwrap_or_default();
        assert!(prev_amount >= amount.0, "ERR_INVALID_STAKING_CONTRACT");
        let new_amount = prev_amount - amount.0;
        self.delegations.insert(account_id, &new_amount);
        self.total_delegation_amount -= amount.0;
        (
            U128(prev_amount),
            U128(new_amount),
            self.delegation_total_supply(),
        )
    }
}
