use std::collections::HashMap;

use near_contract_standards::fungible_token::core_impl::ext_fungible_token;
use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::json_types::{Base64VecU8, U128, U64};
use near_sdk::{log, AccountId, Balance, Gas, PromiseOrValue};

use crate::policy::UserInfo;
use crate::types::{
    convert_old_to_new_token, Action, Config, OldAccountId, GAS_FOR_FT_TRANSFER, OLD_BASE_TOKEN,
    ONE_YOCTO_NEAR,
};
use crate::upgrade::{upgrade_remote, upgrade_using_factory};
use crate::*;

/// Status of a proposal.₩
#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone, PartialEq, Debug)]
#[serde(crate = "near_sdk::serde")]
pub enum ProposalStatus {
    //진행 중,
    InProgress,
    /// If quorum voted yes, this proposal is successfully approved.
    /// 만약 의사정족수가 찬성표를 던졌을 경우, 이 제안은 성공적으로 승인된 것입니다.
    Approved,
    /// If quorum voted no, this proposal is rejected. Bond is returned.
    /// 의결정족수가 부결되면 이 안은 부결됩니다. 채권은 반환됩니다.
    Rejected,
    /// If quorum voted to remove (e.g. spam), this proposal is rejected and bond is not returned.
    /// 정족수가 투표로 제거(예: 스팸)된 경우, 이 제안은 거부되고 채권은 반환되지 않습니다.
    /// Interfaces shouldn't show removed proposals.
    /// 인터페이스에 제거된 제안이 표시되면 안 됩니다.
    Removed,
    /// Expired after period of time.
    /// 기간이 지난 후 만료되었습니다.
    Expired,
    /// If proposal was moved to Hub or somewhere else.
    /// 제안이 허브나 다른 곳으로 옮겨진 경우.
    Moved,
    /// If proposal has failed when finalizing. Allowed to re-finalize again to either expire or approved.
    /// 제안을 완료할 때 실패한 경우. 다시 완료하여 만료되거나 승인된 경우.
    Failed,
}

/// Function call arguments.
#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
#[cfg_attr(not(target_arch = "wasm32"), derive(Clone, Debug))]
#[serde(crate = "near_sdk::serde")]
pub struct ActionCall {
    method_name: String,
    args: Base64VecU8,
    deposit: U128,
    gas: U64,
}

/// Function call arguments.
/// /// `PolicyParameters`는 DAO 내에서 제안 정책의 구성 옵션을 나타냅니다.
/// 이 매개변수들은 제안과 현상금이 어떻게 처리되어야 하는지에 대한 세부 사항을 정의하는 데 도움을 줍니다.
/// 이것은 필요한 담보와 이와 관련된 시간 기간을 포함합니다.
///
/// 속성:
/// - `proposal_bond`: 제안을 제출할 때 필요한 토큰의 담보량입니다.
///     이 담보는 담보로 작용하며 제안이 처리되면 반환되거나 제안이 악의적이면 처벌될 수 있습니다.
///     `None`으로 설정된 경우 담보가 필요하지 않습니다.
///
/// - `proposal_period`: 제안이 활성 상태로 유지되고 투표할 수 있는 기간입니다. 블록 단위로 측정됩니다.
///     `None`으로 설정된 경우 제안의 투표 기간에 명시적인 시간 제한이 없을 수 있습니다.
///
/// - `bounty_bond`: 현상금 제안을 제출할 때 필요한 토큰의 담보량입니다.
///     `proposal_bond`와 마찬가지로 이 담보는 결과에 따라 반환되거나 처벌될 수 있습니다.
///     `None`으로 설정된 경우 현상금 제안에는 담보가 필요하지 않습니다.
///
/// - `bounty_forgiveness_period`: 승인된 현상금을 청구해야 하는 기간입니다.
///     이 기간이 지나면 현상금은 면제되었을 수 있으며 청구할 수 없을 수 있습니다. 블록 단위로 측정됩니다.
///     `None`으로 설정된 경우 승인된 현상금을 청구하기 위한 명시적인 시간 제한이 없을 수 있습니다.
#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
#[cfg_attr(not(target_arch = "wasm32"), derive(Clone, Debug))]
#[serde(crate = "near_sdk::serde")]
pub struct PolicyParameters {
    pub proposal_bond: Option<U128>,
    pub proposal_period: Option<U64>,
    pub bounty_bond: Option<U128>,
    pub bounty_forgiveness_period: Option<U64>,
}

/// Kinds of proposals, doing different action.
/// 다양한 제안을 하고 다른 Action 을 합니다.
#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
#[cfg_attr(not(target_arch = "wasm32"), derive(Clone, Debug))]
#[serde(crate = "near_sdk::serde")]
    pub enum ProposalKind {
    /// DAO 설정 변경.
    /// Change the DAO config.
    ChangeConfig { config: Config },

    /// 전체 정책 변경.
    /// Change the full policy.
    ChangePolicy { policy: VersionedPolicy },

    /// 정책의 특정 역할에 회원 추가. 전체 정책 업데이트의 단축 경로.
    /// Add member to given role in the policy. This is short cut to updating the whole policy.
    AddMemberToRole { member_id: AccountId, role: String },

    /// 정책의 특정 역할에서 회원 제거. 전체 정책 업데이트의 단축 경로.
    /// Remove member from given role in the policy. This is short cut to updating the whole policy.
    RemoveMemberFromRole { member_id: AccountId, role: String },

    /// `receiver_id`에게 메서드 이름 목록과 함께 단일 프로미스 호출.
    /// 다른 컨트랙트에서 임의의 동작 집합을 실행하도록 이 컨트랙트에 허용.
    /// Calls `receiver_id` with list of method names in a single promise.
    /// Allows this contract to execute any arbitrary set of actions in other contracts.
    FunctionCall {
        receiver_id: AccountId,
        actions: Vec<ActionCall>,
    },

    /// 블롭 스토어의 주어진 해시로 이 컨트랙트 업그레이드.
    /// Upgrade this contract with given hash from blob store.
    UpgradeSelf { hash: Base58CryptoHash },

    /// 주어진 블롭 스토어의 해시로 다른 컨트랙트를 업그레이드하려면 메서드 호출.
    /// Upgrade another contract, by calling method with the code from given hash from blob store.
    UpgradeRemote {
        receiver_id: AccountId,
        method_name: String,
        hash: Base58CryptoHash,
    },

    /// 주어진 `token_id`의 금액을 이 DAO에서 `receiver_id`로 전송.
    /// `msg`가 None이 아니면 주어진 `msg`로 `ft_transfer_call` 호출. 기본 토큰이 실패한 경우.
    /// `ft_transfer`와 `ft_transfer_call`의 `memo`는 제안의 `description`입니다.
    /// Transfers given amount of `token_id` from this DAO to `receiver_id`.
    /// If `msg` is not None, calls `ft_transfer_call` with given `msg`. Fails if this base token.
    /// For `ft_transfer` and `ft_transfer_call` `memo` is the `description` of the proposal.
    Transfer {
        /// $NEAR을 위한 ""일 수 있거나 유효한 계정 ID일 수 있습니다.
        /// Transfer 구조체를 보면, 다음의 필드들이 있습니다:
        /// token_id: $NEAR로 전송하려면 빈 문자열 ("")을 사용하거나, 다른 토큰을 전송하려면 유효한 계정 ID를 사용해야 합니다.
        /// Can be "" for $NEAR or a valid account id.
        token_id: OldAccountId,
        receiver_id: AccountId,
        amount: U128,
        msg: Option<String>,
    },

    /// 스테이킹 컨트랙트 설정. 스테이킹 컨트랙트가 아직 설정되지 않았다면 제안될 수 있습니다.
    /// Sets staking contract. Can only be proposed if staking contract is not set yet.
    SetStakingContract { staking_id: AccountId },

    /// 새로운 바운티 추가.
    /// Add new bounty.
    AddBounty { bounty: Bounty },

    /// 주어진 바운티가 주어진 사용자에 의해 완료되었음을 나타냅니다.
    /// Indicates that given bounty is done by given user.
    BountyDone {
        bounty_id: u64,
        receiver_id: AccountId,
    },

    /// 실행 없이 단순한 신호 투표.
    /// Just a signaling vote, with no execution.
    Vote,
    /// 팩토리 및 자동 업데이트에 대한 정보 변경.
    /// Change information about factory and auto update.
    FactoryInfoUpdate { factory_info: FactoryInfo },

    /// 정책에 새로운 역할 추가. 역할이 이미 존재하면 업데이트합니다. 전체 정책 업데이트의 단축 경로.
    /// Add new role to the policy. If the role already exists, update it. This is short cut to updating the whole policy.
    ChangePolicyAddOrUpdateRole { role: RolePermission },

    /// 정책에서 역할 제거. 전체 정책 업데이트의 단축 경로.
    /// Remove role from the policy. This is short cut to updating the whole policy.
    ChangePolicyRemoveRole { role: String },

    /// 정책에서 기본 투표 정책 업데이트. 전체 정책 업데이트의 단축 경로.
    /// Update the default vote policy from the policy. This is short cut to updating the whole policy.
    ChangePolicyUpdateDefaultVotePolicy { vote_policy: VotePolicy },

    /// 정책에서 매개변수 업데이트. 전체 정책 업데이트의 단축 경로.
    /// Update the parameters from the policy. This is short cut to updating the whole policy.
    ChangePolicyUpdateParameters { parameters: PolicyParameters },
}


impl ProposalKind {
    /// Returns label of policy for given type of proposal.
    /// 지정된 제안 유형에 대한 정책 레이블을 반환합니다.
    pub fn to_policy_label(&self) -> &str {
        match self {
            ProposalKind::ChangeConfig { .. } => "config",
            ProposalKind::ChangePolicy { .. } => "policy",
            ProposalKind::AddMemberToRole { .. } => "add_member_to_role",
            ProposalKind::RemoveMemberFromRole { .. } => "remove_member_from_role",
            ProposalKind::FunctionCall { .. } => "call",
            ProposalKind::UpgradeSelf { .. } => "upgrade_self",
            ProposalKind::UpgradeRemote { .. } => "upgrade_remote",
            ProposalKind::Transfer { .. } => "transfer",
            ProposalKind::SetStakingContract { .. } => "set_vote_token",
            ProposalKind::AddBounty { .. } => "add_bounty",
            ProposalKind::BountyDone { .. } => "bounty_done",
            ProposalKind::Vote => "vote",
            ProposalKind::FactoryInfoUpdate { .. } => "factory_info_update",
            ProposalKind::ChangePolicyAddOrUpdateRole { .. } => "policy_add_or_update_role",
            ProposalKind::ChangePolicyRemoveRole { .. } => "policy_remove_role",
            ProposalKind::ChangePolicyUpdateDefaultVotePolicy { .. } => {
                "policy_update_default_vote_policy"
            }
            ProposalKind::ChangePolicyUpdateParameters { .. } => "policy_update_parameters",
        }
    }
}

/// Votes recorded in the proposal.
/// 제안서에 기록된 투표.
#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "near_sdk::serde")]
pub enum Vote {
    Approve = 0x0,
    Reject = 0x1,
    Remove = 0x2,
}

impl From<Action> for Vote {
    fn from(action: Action) -> Self {
        match action {
            Action::VoteApprove => Vote::Approve,
            Action::VoteReject => Vote::Reject,
            Action::VoteRemove => Vote::Remove,
            _ => unreachable!(),
        }
    }
}

/// Proposal that are sent to this DAO.
#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
#[cfg_attr(not(target_arch = "wasm32"), derive(Debug))]
#[serde(crate = "near_sdk::serde")]
pub struct Proposal {
    /// Original proposer.    
    ///원래 제안자.
    pub proposer: AccountId,
    /// Description of this proposal.
    pub description: String,
    /// Kind of proposal with relevant information.
    /// 제안의 현재 상태입니다.
    pub kind: ProposalKind,
    /// Current status of the proposal.
    pub status: ProposalStatus,
    /// Count of votes per role per decision: yes / no / spam.
    /// 의사 결정당 역할당 투표 수: 예 / 아니오 / 스팸입니다.
    pub vote_counts: HashMap<String, [Balance; 3]>,
    /// Map of who voted and how.
    /// 누가 어떻게 투표했는지 
    pub votes: HashMap<AccountId, Vote>,
    /// Time of the vote for each account.
    /// 각 계정에 대한 투표 시간입니다.
    pub vote_times: HashMap<AccountId, U64>,
    /// Submission time (for voting period).
    pub submission_time: U64,    
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
#[cfg_attr(not(target_arch = "wasm32"), derive(Debug))]
#[serde(crate = "near_sdk::serde")]
pub enum VersionedProposal {
    Default(Proposal),
}

impl From<VersionedProposal> for Proposal {
    fn from(v: VersionedProposal) -> Self {
        match v {
            VersionedProposal::Default(p) => p,
        }
    }
}

impl Proposal {
   /// 주어진 `account_id`와 연결된 투표를 추가하거나 업데이트합니다.
/// Adds or updates the votes associated with the given `account_id`.
pub fn update_votes(
    &mut self,
    account_id: &AccountId,      // 투표하는 계정의 ID입니다.
                                 // The ID of the account that is voting.
    roles: &[String],            // 사용자(투표자)와 연결된 역할들입니다.
                                 // The roles associated with the user (voter).
    vote: Vote,                  // 사용자의 투표 (예: 승인, 거부 등).
                                 // The user's vote (e.g., Approve, Reject, etc.).
    policy: &Policy,             // 현재 정책의 세부사항입니다.
                                 // Current policy details.
    user_weight: Balance,        // 사용자 투표의 가중치입니다.
                                 // Weight of the user's vote.
) {
    env::log_str("Function: update_votes");
    // 사용자의 각 역할을 반복하여 검사합니다.
    // Iterate through each role of the user.
    for role in roles {
        // 정책을 기반으로 투표 가중치를 결정합니다.
        // 만약 정책이 이 제안 유형에 대한 역할의 투표가 토큰 가중치라고 말한다면,
        // 사용자의 가중치(잔액)를 사용합니다. 그렇지 않으면 투표 가중치는 1입니다.
        // Determine the voting weight based on the policy. 
        // If the policy says the role's vote is token weighted for this kind of proposal,
        // use the user's weight (balance). Otherwise, vote weight is just 1.
        let amount = if policy.is_token_weighted(role, &self.kind.to_policy_label().to_string()) {
            user_weight
        } else {
            1
        };

        // 역할에 대한 투표 수를 업데이트합니다. 이는 역할별 및 투표 유형별 투표 수를 유지합니다.
        // Update the vote count for the role. This maintains a tally of votes by role and type of vote.
        self.vote_counts.entry(role.clone()).or_insert([0u128; 3])[vote.clone() as usize] += amount;
    }

    // 사용자가 이미 투표하지 않았는지 확인합니다. 그렇다면 오류를 발생시킵니다.
    // Ensure that the user hasn't already voted. If they have, throw an error.
    assert!(
        self.votes.insert(account_id.clone(), vote).is_none(),
        "ERR_ALREADY_VOTED"
    );
}

}

#[derive(Serialize, Deserialize)]
#[serde(crate = "near_sdk::serde")]
pub struct ProposalInput {
    /// Description of this proposal.
    pub description: String,
    /// Kind of proposal with relevant information.
    /// 관련된 정보를 가진 일종의 제안.
    pub kind: ProposalKind,
}

impl From<ProposalInput> for Proposal {
    fn from(input: ProposalInput) -> Self {
        Self {
            proposer: env::predecessor_account_id(),
            description: input.description,
            kind: input.kind,
            status: ProposalStatus::InProgress,
            vote_counts: HashMap::default(),
            votes: HashMap::default(),
            vote_times:HashMap::default(),
            submission_time: U64::from(env::block_timestamp()),
        }
    }
}

impl Contract {
    /// Execute payout of given token to given user.
    /// 지정된 사용자에게 주어진 토큰을 지급합니다.
    pub(crate) fn internal_payout(
        &mut self,
        token_id: &Option<AccountId>,
        receiver_id: &AccountId,
        amount: Balance,
        memo: String,
        msg: Option<String>,
    ) -> PromiseOrValue<()> {
        env::log_str("Function: internal_payout sputnikdao2 prososals.rs ");
        if token_id.is_none() {
            Promise::new(receiver_id.clone()).transfer(amount).into()
        } else {
            if let Some(msg) = msg {
                ext_fungible_token::ft_transfer_call(
                    receiver_id.clone(),
                    U128(amount),
                    Some(memo),
                    msg,
                    token_id.as_ref().unwrap().clone(),
                    ONE_YOCTO_NEAR,
                    GAS_FOR_FT_TRANSFER,
                )
            } else {
                ext_fungible_token::ft_transfer(
                    receiver_id.clone(),
                    U128(amount),
                    Some(memo),
                    token_id.as_ref().unwrap().clone(),
                    ONE_YOCTO_NEAR,
                    GAS_FOR_FT_TRANSFER,
                )
            }
            .into()
        }
    }

    fn internal_return_bonds(&mut self, policy: &Policy, proposal: &Proposal) -> Promise {
        env::log_str("Function: internal_return_bonds sputnikdao2 prososals.rs ");
        match &proposal.kind {
            ProposalKind::BountyDone { .. } => {
                self.locked_amount -= policy.bounty_bond.0;
                Promise::new(proposal.proposer.clone()).transfer(policy.bounty_bond.0);
            }
            _ => {}
        }

        self.locked_amount -= policy.proposal_bond.0;
        Promise::new(proposal.proposer.clone()).transfer(policy.proposal_bond.0)
    }

    /// Executes given proposal and updates the contract's state.
    /// 지정된 제안을 실행하고 계약 상태를 업데이트합니다.
    fn internal_execute_proposal(
        &mut self,
        policy: &Policy,
        proposal: &Proposal,
        proposal_id: u64,
    ) -> PromiseOrValue<()> {
        env::log_str("Function: internal_execute_proposal sputnikdao2 prososals.rs ");
        let result = match &proposal.kind {
            ProposalKind::ChangeConfig { config } => {
                self.config.set(config);
                PromiseOrValue::Value(())
            }
            ProposalKind::ChangePolicy { policy } => {
                self.policy.set(policy);
                PromiseOrValue::Value(())
            }
            ProposalKind::AddMemberToRole { member_id, role } => {
                let mut new_policy = policy.clone();
                new_policy.add_member_to_role(role, &member_id.clone().into());
                self.policy.set(&VersionedPolicy::Current(new_policy));
                PromiseOrValue::Value(())
            }
            ProposalKind::RemoveMemberFromRole { member_id, role } => {
                let mut new_policy = policy.clone();
                new_policy.remove_member_from_role(role, &member_id.clone().into());
                self.policy.set(&VersionedPolicy::Current(new_policy));
                PromiseOrValue::Value(())
            }
            ProposalKind::FunctionCall {
                receiver_id,
                actions,
            } => {
                let mut promise = Promise::new(receiver_id.clone().into());
                for action in actions {
                    promise = promise.function_call(
                        action.method_name.clone().into(),
                        action.args.clone().into(),
                        action.deposit.0,
                        Gas(action.gas.0),
                    )
                }
                promise.into()
            }
            ProposalKind::UpgradeSelf { hash } => {
                upgrade_using_factory(hash.clone());
                PromiseOrValue::Value(())
            }
            ProposalKind::UpgradeRemote {
                receiver_id,
                method_name,
                hash,
            } => {
                upgrade_remote(&receiver_id, method_name, &CryptoHash::from(hash.clone()));
                PromiseOrValue::Value(())
            }
            ProposalKind::Transfer {
                token_id,
                receiver_id,
                amount,
                msg,
            } => self.internal_payout(
                &convert_old_to_new_token(token_id),
                &receiver_id,
                amount.0,
                proposal.description.clone(),
                msg.clone(),
            ),
            ProposalKind::SetStakingContract { staking_id } => {
                assert!(self.staking_id.is_none(), "ERR_INVALID_STAKING_CHANGE");
                self.staking_id = Some(staking_id.clone().into());
                PromiseOrValue::Value(())
            }
            ProposalKind::AddBounty { bounty } => {
                self.internal_add_bounty(bounty);
                PromiseOrValue::Value(())
            }
            ProposalKind::BountyDone {
                bounty_id,
                receiver_id,
            } => self.internal_execute_bounty_payout(*bounty_id, &receiver_id.clone().into(), true),
            ProposalKind::Vote => PromiseOrValue::Value(()),
            ProposalKind::FactoryInfoUpdate { factory_info } => {
                internal_set_factory_info(factory_info);
                PromiseOrValue::Value(())
            }
            ProposalKind::ChangePolicyAddOrUpdateRole { role } => {
                let mut new_policy = policy.clone();
                new_policy.add_or_update_role(role);
                self.policy.set(&VersionedPolicy::Current(new_policy));
                PromiseOrValue::Value(())
            }
            ProposalKind::ChangePolicyRemoveRole { role } => {
                let mut new_policy = policy.clone();
                new_policy.remove_role(role);
                self.policy.set(&VersionedPolicy::Current(new_policy));
                PromiseOrValue::Value(())
            }
            ProposalKind::ChangePolicyUpdateDefaultVotePolicy { vote_policy } => {
                let mut new_policy = policy.clone();
                new_policy.update_default_vote_policy(vote_policy);
                self.policy.set(&VersionedPolicy::Current(new_policy));
                PromiseOrValue::Value(())
            }
            ProposalKind::ChangePolicyUpdateParameters { parameters } => {
                let mut new_policy = policy.clone();
                new_policy.update_parameters(parameters);
                self.policy.set(&VersionedPolicy::Current(new_policy));
                PromiseOrValue::Value(())
            }
        };
        match result {
            PromiseOrValue::Promise(promise) => promise
                .then(ext_self::on_proposal_callback(
                    proposal_id,
                    env::current_account_id(),
                    0,
                    GAS_FOR_FT_TRANSFER,
                ))
                .into(),
            PromiseOrValue::Value(()) => self.internal_return_bonds(&policy, &proposal).into(),
        }
    }

    pub(crate) fn internal_callback_proposal_success(
        &mut self,
        proposal: &mut Proposal,
    ) -> PromiseOrValue<()> {
        env::log_str("Function: internal_callback_proposal_success sputnikdao2 prososals.rs ");
        let policy = self.policy.get().unwrap().to_policy();
        if let ProposalKind::BountyDone { bounty_id, .. } = proposal.kind {
            let mut bounty: Bounty = self.bounties.get(&bounty_id).expect("ERR_NO_BOUNTY").into();
            if bounty.times == 0 {
                self.bounties.remove(&bounty_id);
            } else {
                bounty.times -= 1;
                self.bounties
                    .insert(&bounty_id, &VersionedBounty::Default(bounty));
            }
        }
        proposal.status = ProposalStatus::Approved;
        self.internal_return_bonds(&policy, &proposal).into()
    }

    pub(crate) fn internal_callback_proposal_fail(
        &mut self,
        proposal: &mut Proposal,
    ) -> PromiseOrValue<()> {
        env::log_str("Function: internal_callback_proposal_fail sputnikdao2 prososals.rs ");
        proposal.status = ProposalStatus::Failed;
        PromiseOrValue::Value(())
    }

    /// Process rejecting proposal.
    fn internal_reject_proposal(
        &mut self,
        policy: &Policy,
        proposal: &Proposal,
        return_bonds: bool,
    ) -> PromiseOrValue<()> {
        env::log_str("Function: internal_reject_proposal sputnikdao2 prososals.rs ");
        if return_bonds {
            // Return bond to the proposer.
            self.internal_return_bonds(policy, proposal);
        }
        match &proposal.kind {
            ProposalKind::BountyDone {
                bounty_id,
                receiver_id,
            } => {
                self.internal_execute_bounty_payout(*bounty_id, &receiver_id.clone().into(), false)
            }
            _ => PromiseOrValue::Value(()),
        }
    }

    pub(crate) fn internal_user_info(&self) -> UserInfo {
        env::log_str("Function: internal_user_info sputnikdao2 prososals.rs ");
        let account_id = env::predecessor_account_id();
        UserInfo {
            amount: self.get_user_weight(&account_id),
            account_id,
        }
    }
}

#[near_bindgen]
impl Contract {
    /// Add proposal to this DAO.
    #[payable]
   /// 이 DAO에 제안을 추가합니다.
/// Add proposal to this DAO.
    pub fn add_proposal(&mut self, proposal: ProposalInput) -> u64 {
        // 0. 첨부된 보증금을 검증합니다.
        // 0. validate bond attached.
        // TODO: 이 DAO의 토큰에서 보증금을 고려합니다.
        // TODO: consider bond in the token of this DAO.
        env::log_str("Function: add_proposal sputnikdao2 prososals.rs ");
        log!("add_proposal called");
        let policy = self.policy.get().unwrap().to_policy();

        // 첨부된 보증금이 정책의 제안 보증금과 동일한지 확인합니다.
        assert_eq!(
            env::attached_deposit(),
            policy.proposal_bond.0,
            "ERR_MIN_BOND"
        );

        // 1. 제안을 검증합니다.
        // 1. Validate proposal.
        match &proposal.kind {
            ProposalKind::ChangePolicy { policy } => match policy {
                VersionedPolicy::Current(_) => {}
                _ => panic!("ERR_INVALID_POLICY"),
            },
            ProposalKind::Transfer { token_id, msg, .. } => {
                // OLD_BASE_TOKEN인 경우 메시지가 없어야 합니다.
                assert!(
                    !(token_id == OLD_BASE_TOKEN) || msg.is_none(),
                    "ERR_BASE_TOKEN_NO_MSG"
                );
            }
            ProposalKind::SetStakingContract { .. } => 
                // 스테이킹 계약은 변경할 수 없습니다.
                assert!(
                    self.staking_id.is_none(),
                    "ERR_STAKING_CONTRACT_CANT_CHANGE"
                ),
            // TODO: 추가적인 검증을 여기에 넣습니다.
            // TODO: add more verifications.
            _ => {}
        };


        let user_info = self.internal_user_info();
        env::log_str(&format!("user_info:{:?}",user_info));
        // 2. 호출자가 이 유형의 제안을 추가할 권한이 있는지 확인합니다.
        // 2. Check permission of caller to add this type of proposal.
        assert!(
            policy
                .can_execute_action(
                    self.internal_user_info(),
                    &proposal.kind,
                    &Action::AddProposal
                )
                .1,
            "ERR_PERMISSION_DENIED"
        );

        // 3. 실제로 제안을 현재의 제안 목록에 추가합니다.
        // 3. Actually add proposal to the current list of proposals.
        let id = self.last_proposal_id;
        self.proposals
            .insert(&id, &VersionedProposal::Default(proposal.into()));
        self.last_proposal_id += 1;
        // 첨부된 보증금을 잠급니다.
        self.locked_amount += env::attached_deposit();
        id
    }

    /// Act on given proposal by id, if permissions allow.
    /// Memo is logged but not stored in the state. Can be used to leave notes or explain the action.
    /// 권한이 허용되는 경우 ID별로 주어진 제안에 대해 작업을 수행합니다.
    /// 메모는 기록되지만 상태에 저장되지 않습니다. 메모를 남기거나 작업을 설명하는 데 사용할 수 있습니다.
    pub fn act_proposal(&mut self, id: u64, action: Action, memo: Option<String>) {
        env::log_str("Function: act_proposal sputnikdao2 prososals.rs ");
        // Retrieve the proposal with the given ID.
        // 주어진 ID를 가진 제안을 검색합니다.
        let mut proposal: Proposal = self.proposals.get(&id).expect("ERR_NO_PROPOSAL").into();
        // Retrieve the current policy.
        // 현재 정책을 검색합니다.
        let policy = self.policy.get().unwrap().to_policy();
        // Check permissions for the given action.
        // 주어진 행동에 대한 권한을 확인합니다.
        let (roles, allowed) =
            policy.can_execute_action(self.internal_user_info(), &proposal.kind, &action);
        assert!(allowed, "ERR_PERMISSION_DENIED");
        // Get the account ID of the action initiator.
        // 행동을 시작한 계정 ID를 가져옵니다.
        let sender_id = env::predecessor_account_id();
        // Update proposal given action. Returns true if should be updated in storage.
        // Determine how to update the proposal based on the action.
        // 행동에 기반하여 제안을 어떻게 업데이트할지 결정합니다.
        let update = match action {
            Action::AddProposal => env::panic_str("ERR_WRONG_ACTION"),
            Action::RemoveProposal => {
                // Remove the proposal.
                // 제안을 삭제합니다.
                self.proposals.remove(&id);
                false
            }
            Action::VoteApprove | Action::VoteReject | Action::VoteRemove => {
                // Check if the proposal is ready for voting.
                // 제안이 투표를 위해 준비되었는지 확인합니다.
                assert!(
                    matches!(proposal.status, ProposalStatus::InProgress),
                    "ERR_PROPOSAL_NOT_READY_FOR_VOTE"
                );
                // Update the votes on the proposal.
                // 제안에 대한 투표를 업데이트합니다.
                proposal.update_votes(
                    &sender_id,
                    &roles,
                    Vote::from(action),
                    &policy,
                    self.get_user_weight(&sender_id),
                );
                // Updates proposal status with new votes using the policy.
                // 제안에 대한 투표를 업데이트합니다.
                proposal.status =
                    policy.proposal_status(&proposal, roles, self.total_delegation_amount);
                      // Update the vote time for the account.
                    proposal.vote_times.insert(sender_id.clone(), near_sdk::json_types::U64(env::block_timestamp()));

                // Determine the proposal's new status.
                // 제안의 새로운 상태를 결정합니다.
                if proposal.status == ProposalStatus::Approved {
                    self.internal_execute_proposal(&policy, &proposal, id);
                    true
                } else if proposal.status == ProposalStatus::Removed {
                    self.internal_reject_proposal(&policy, &proposal, false);
                    self.proposals.remove(&id);
                    false
                } else if proposal.status == ProposalStatus::Rejected {
                    self.internal_reject_proposal(&policy, &proposal, true);
                    true
                } else {
                    // Still in progress or expired.
                    // 여전히 진행 중 또는 만료됨.
                    true
                }          
            }
            // There are two cases when proposal must be finalized manually: expired or failed.
            // In case of failed, we just recompute the status and if it still approved, we re-execute the proposal.
            // In case of expired, we reject the proposal and return the bond.
            // Corner cases:
            //  - if proposal expired during the failed state - it will be marked as expired.
            //  - if the number of votes in the group has changed (new members has been added) -
            //      the proposal can loose it's approved state. In this case new proposal needs to be made, this one can only expire.
            // 제안서를 수동으로 확정해야 하는 경우는 만료된 경우와 실패한 경우 두 가지가 있습니다.
            // 실패할 경우 상태만 다시 계산하고 승인이 나면 제안서를 다시 실행합니다.
            // 만기가 되면 제안서를 거절하고 채권을 반환합니다.
            // 코너 케이스:
            // - 실패한 상태에서 제안이 만료된 경우 - 만료된 것으로 표시됩니다.
            // - 그룹내 투표수가 변경된 경우(신규회원 추가) -
            // 그 제안은 승인된 상태를 잃을 수 있습니다. 이 경우에는 새로운 제안을 해야 하며, 이 제안은 만료될 수 있습니다.
            Action::Finalize => {
                proposal.status = policy.proposal_status(
                    &proposal,
                    policy.roles.iter().map(|r| r.name.clone()).collect(),
                    self.total_delegation_amount,
                );
                match proposal.status {
                    ProposalStatus::Approved => {
                        self.internal_execute_proposal(&policy, &proposal, id);
                    }
                    ProposalStatus::Expired => {
                        self.internal_reject_proposal(&policy, &proposal, true);
                    }
                    _ => {
                        env::panic_str("ERR_PROPOSAL_NOT_EXPIRED_OR_FAILED");
                    }
                }
                true
            }
            Action::MoveToHub => false,
        };
        // Save the updated proposal.
        // 업데이트 된 제안을 저장합니다.
        if update {
            self.proposals
                .insert(&id, &VersionedProposal::Default(proposal));
        }
        if let Some(memo) = memo {
            // Log the memo, if provided.
            // 제공된 경우 메모를 로그에 남깁니다.
            log!("Memo: {}", memo);
        }
    }

    /// Receiving callback after the proposal has been finalized.
    /// If successful, returns bond money to the proposal originator.
    /// If the proposal execution failed (funds didn't transfer or function call failure),
    /// move proposal to "Failed" state.
    #[private]
    pub fn on_proposal_callback(&mut self, proposal_id: u64) -> PromiseOrValue<()> {
        let mut proposal: Proposal = self
            .proposals
            .get(&proposal_id)
            .expect("ERR_NO_PROPOSAL")
            .into();
        assert_eq!(
            env::promise_results_count(),
            1,
            "ERR_UNEXPECTED_CALLBACK_PROMISES"
        );
        let result = match env::promise_result(0) {
            PromiseResult::NotReady => unreachable!(),
            PromiseResult::Successful(_) => self.internal_callback_proposal_success(&mut proposal),
            PromiseResult::Failed => self.internal_callback_proposal_fail(&mut proposal),
        };
        self.proposals
            .insert(&proposal_id, &VersionedProposal::Default(proposal.into()));
        result
    }
}
