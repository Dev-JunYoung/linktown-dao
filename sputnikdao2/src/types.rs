use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::json_types::Base64VecU8;
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::{AccountId, Balance, Gas};

/// Account ID used for $NEAR in near-sdk v3.
/// Need to keep it around for backward compatibility.
pub const OLD_BASE_TOKEN: &str = "";

/// Account ID that represents a token in near-sdk v3.
/// Need to keep it around for backward compatibility.
pub type OldAccountId = String;

/// 1 yN to prevent access key fraud.
pub const ONE_YOCTO_NEAR: Balance = 1;

/// Gas for single ft_transfer call.
pub const GAS_FOR_FT_TRANSFER: Gas = Gas(10_000_000_000_000);

/// Configuration of the DAO.
#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "near_sdk::serde")]
pub struct Config {
    /// Name of the DAO.
    pub name: String,
    /// Purpose of this DAO.
    pub purpose: String,
    /// Generic metadata. Can be used by specific UI to store additional data.
    /// This is not used by anything in the contract.
    /// 일반 메타데이터. 특정 UI에서 추가 데이터를 저장하는 데 사용할 수 있습니다.
    /// 이것은 계약서상의 어떤 것에도 사용되지 않습니다.
    pub metadata: Base64VecU8,
    /// Logo image URL for the DAO.
    /// DAO의 로고 이미지 URL.
    pub logo_url: String,
}

/// Set of possible action to take.
#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Debug)]
#[serde(crate = "near_sdk::serde")]
pub enum Action {
    /// Action to add proposal. Used internally.
    /// 제안을 추가하는 작업. 내부적으로 사용합니다.
    AddProposal,
    /// Action to remove given proposal. Used for immediate deletion in special cases.
    /// 지정된 제안을 제거하는 작업입니다. 특수한 경우 즉시 삭제하는 데 사용됩니다.
    RemoveProposal,
    /// Vote to approve given proposal or bounty.
    /// 주어진 제안이나 현상금을 승인하는 투표를 합니다.
    VoteApprove,
    /// Vote to reject given proposal or bounty.
    /// 주어진 제안이나 현상금을 거부하는 투표를 합니다.
    VoteReject,
    /// Vote to remove given proposal or bounty (because it's spam).
    /// (스팸이기 때문에) 주어진 제안이나 현상금을 삭제하기 위해 투표합니다.
    VoteRemove,
    /// Finalize proposal, called when it's expired to return the funds
    /// (or in the future can be used for early proposal closure).
    /// 제안서 마무리, 자금 반환 만료 시 호출
    /// (또는 향후 조기 제안 마감을 위해 사용될 수 있음).
    Finalize,
    /// Move a proposal to the hub to shift into another DAO.
    /// 제안을 허브로 이동하여 다른 DAO로 전환합니다.
    MoveToHub,
}

impl Action {
    pub fn to_policy_label(&self) -> String {
        format!("{:?}", self)
    }
}

/// In near-sdk v3, the token was represented by a String, with no other restrictions.
/// That being said, Sputnik used "" (empty String) as a convention to represent the $NEAR token.
/// In near-sdk v4, the token representation was replaced by AccountId (which is in fact a wrapper
/// over a String), with the restriction that the token must be between 2 and 64 chars.
/// Sputnik had to adapt since "" was not allowed anymore and we chose to represent the token as a
/// Option<AccountId> with the convention that None represents the $NEAR token.
/// This function is required to help with the transition and keep the backward compatibility.
pub fn convert_old_to_new_token(old_account_id: &OldAccountId) -> Option<AccountId> {
    if old_account_id == OLD_BASE_TOKEN {
        return None;
    }
    Some(AccountId::new_unchecked(old_account_id.clone()))
}

#[cfg(test)]
impl Config {
    pub fn test_config() -> Self {
        Self {
            name: "Test".to_string(),
            purpose: "to test".to_string(),
            metadata: Base64VecU8(vec![]),
            logo_url:"url".to_string(),
        }
    }
}
