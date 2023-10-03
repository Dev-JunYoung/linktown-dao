use std::cmp::min;
use std::collections::{HashMap, HashSet};

use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::json_types::{U128, U64};
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::{env, AccountId, Balance};

use crate::proposals::{PolicyParameters, Proposal, ProposalKind, ProposalStatus, Vote};
use crate::types::Action;

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone)]
#[cfg_attr(not(target_arch = "wasm32"), derive(Debug, PartialEq))]
#[serde(crate = "near_sdk::serde")]
pub enum RoleKind {
    /// Matches everyone, who is not matched by other roles.
    Everyone,
    /// Member greater or equal than given balance. Can use `1` as non-zero balance.
    Member(U128),
    /// Set of accounts.
    Group(HashSet<AccountId>),
}

impl RoleKind {
    /// Checks if user matches given role.
    /// 주어진 사용자가 해당 역할과 일치하는지 확인합니다.
    pub fn match_user(&self, user: &UserInfo) -> bool {
        match self {
            RoleKind::Everyone => true,
            RoleKind::Member(amount) => user.amount >= amount.0,
            RoleKind::Group(accounts) => accounts.contains(&user.account_id),
        }
    }
    /// Returns the number of people in the this role or None if not supported role kind.
    /// 이 역할의 사람 수를 반환하거나 지원되지 않는 역할 유형인 경우 None을 반환합니다.
    pub fn get_role_size(&self) -> Option<usize> {
        match self {
            RoleKind::Group(accounts) => Some(accounts.len()),
            _ => None,
        }
    }
    /// 그룹에 멤버를 추가합니다. 그룹이 아닌 경우 오류를 반환합니다.
    pub fn add_member_to_group(&mut self, member_id: &AccountId) -> Result<(), ()> {
        match self {
            RoleKind::Group(accounts) => {
                accounts.insert(member_id.clone());
                Ok(())
            }
            _ => Err(()),
        }
    }
    /// 그룹에서 멤버를 제거합니다. 그룹이 아닌 경우 오류를 반환합니다.
    pub fn remove_member_from_group(&mut self, member_id: &AccountId) -> Result<(), ()> {
        match self {
            RoleKind::Group(accounts) => {
                accounts.remove(member_id); // 그룹에서 멤버를 제거합니다.
                Ok(())
            }
            _ => Err(()),
        }
    }
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone)]
#[cfg_attr(not(target_arch = "wasm32"), derive(Debug, PartialEq))]
#[serde(crate = "near_sdk::serde")]
pub struct RolePermission {
    /// Name of the role to display to the user.
    /// 사용자에게 표시할 역할의 이름입니다.
    pub name: String,
    /// Kind of the role: defines which users this permissions apply.
    /// 역할 종류: 이 권한을 적용할 사용자를 정의합니다.
    pub kind: RoleKind,//Everyone, Member(U128), Group(HashSet<AccountId>),
    /// Set of actions on which proposals that this role is allowed to execute.
    /// <proposal_kind>:<action>
    /// 이 역할이 실행할 수 있는 제안에 대한 작업 집합입니다.
    pub permissions: HashSet<String>, 
    
    /// For each proposal kind, defines voting policy.
    /// 각 제안 유형에 대해 투표 정책을 정의합니다.
    pub vote_policy: HashMap<String, VotePolicy>,
}

pub struct UserInfo {
    pub account_id: AccountId,
    pub amount: Balance,
}

/// Direct weight or ratio to total weight, used for the voting policy.
#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone)]
#[cfg_attr(not(target_arch = "wasm32"), derive(Debug, PartialEq))]
#[serde(crate = "near_sdk::serde")]
#[serde(untagged)]
pub enum WeightOrRatio {
    Weight(U128),
    Ratio(u64, u64),
}

impl WeightOrRatio {
    /// Convert weight or ratio to specific weight given total weight.
    pub fn to_weight(&self, total_weight: Balance) -> Balance {
        match self {
            WeightOrRatio::Weight(weight) => min(weight.0, total_weight),
            WeightOrRatio::Ratio(num, denom) => min(
                (*num as u128 * total_weight) / *denom as u128 + 1,
                total_weight,
            ),
        }
    }
}

/// How the voting policy votes get weigthed.
#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone, PartialEq)]
#[cfg_attr(not(target_arch = "wasm32"), derive(Debug))]
#[serde(crate = "near_sdk::serde")]
pub enum WeightKind {
    /// Using token amounts and total delegated at the moment.
    /// 토큰 금액 및 현재 위임된 합계 사용.
    TokenWeight,
    /// Weight of the group role. Roles that don't have scoped group are not supported.
    /// 그룹 역할의 가중치. 범위 그룹이 없는 역할은 지원되지 않습니다.
    RoleWeight,
}

/// Defines configuration of the vote.
#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone)]
#[cfg_attr(not(target_arch = "wasm32"), derive(Debug, PartialEq))]
#[serde(crate = "near_sdk::serde")]
pub struct VotePolicy {
    /// Kind of weight to use for votes.
    pub weight_kind: WeightKind,
    /// Minimum number required for vote to finalize.
    /// If weight kind is TokenWeight - this is minimum number of tokens required.
    ///     This allows to avoid situation where the number of staked tokens from total supply is too small.
    /// If RoleWeight - this is minimum number of votes.
    ///     This allows to avoid situation where the role is got too small but policy kept at 1/2, for example.
    /// 투표를 완료하는 데 필요한 최소 개수입니다.
    /// weight 종류가 TokenWeight인 경우 - 필요한 토큰의 최소 개수입니다.
    ///     이를 통해 총 공급에서 스테이킹된 토큰의 수가 너무 적은 상황을 방지할 수 있습니다.
    /// RoleWeight인 경우 - 최소 득표수입니다.
    ///     이를 통해 역할이 너무 작지만 정책이 1/2 수준으로 유지되는 상황을 방지할 수 있습니다.
    pub quorum: U128,
    /// How many votes to pass this vote.
    /// 이 투표를 몇 표를 통과해야 합니까.
    pub threshold: WeightOrRatio,
}

impl Default for VotePolicy {
    fn default() -> Self {
        VotePolicy {
            weight_kind: WeightKind::RoleWeight,
            // quorum 필드의 기본값으로 0을 설정합니다. 
            // 쿼럼(quorum)은 투표에 유효하게 간주되기 위해 필요한 최소 투표 참여량을 나타냅니다.
            quorum: U128(0), 
            threshold: WeightOrRatio::Ratio(1, 2),
        }
    }
}

/// Defines voting / decision making policy of this DAO.
#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone)]
#[cfg_attr(not(target_arch = "wasm32"), derive(Debug, PartialEq))]
#[serde(crate = "near_sdk::serde")]
pub struct Policy {
    /// List of roles and permissions for them in the current policy.
    /// 현재 정책의 역할 및 권한 목록입니다
    pub roles: Vec<RolePermission>,
    /// Default vote policy. Used when given proposal kind doesn't have special policy.
    /// 기본 투표 정책. 주어진 제안 종류에 특별한 정책이 없을 때 사용됩니다.
    pub default_vote_policy: VotePolicy,
    /// Proposal bond.
    pub proposal_bond: U128,
    /// Expiration period for proposals.
    /// 제안에 대한 만료 기간.
    pub proposal_period: U64,
    /// Bond for claiming a bounty.
    /// 현상금을 요구하는 채권.
    pub bounty_bond: U128,
    /// Period in which giving up on bounty is not punished.
    /// 현상금을 포기하는 것은 처벌되지 않는 기간.
    pub bounty_forgiveness_period: U64,
}

/// Versioned policy.
#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone)]
#[cfg_attr(not(target_arch = "wasm32"), derive(Debug, PartialEq))]
#[serde(crate = "near_sdk::serde", untagged)]
pub enum VersionedPolicy {
    /// Default policy with given accounts as council.
    Default(Vec<AccountId>),
    Current(Policy),
}

/// Defines default policy:
///     - everyone can add proposals
///     - group consisting of the call can do all actions, consists of caller.
///     - non token weighted voting, requires 1/2 of the group to vote
///     - proposal & bounty bond is 1N
///     - proposal & bounty forgiveness period is 1 day
/// 기본 정책을 정의합니다:
///     - 누구나 제안을 추가할 수 있습니다.
///     - 호출로 구성된 그룹은 모든 작업을 수행할 수 있으며 호출자로 구성됩니다.
///     - 토큰 가중치가 없는 투표, 그룹의 1/2이 투표해야 함
///     - 제안 및 바운티 본드는 1N입니다.
///     - 제안 및 바운티 forgiveness 기간은 1일입니다.
pub fn default_policy(council: Vec<AccountId>) -> Policy {
    Policy {
        roles: vec![
            RolePermission {
                name: "all".to_string(),
                kind: RoleKind::Everyone,
                permissions: vec!["*:AddProposal".to_string()].into_iter().collect(),
                vote_policy: HashMap::default(),
            },
            RolePermission {
                name: "council".to_string(),
                kind: RoleKind::Group(council.into_iter().collect()),
                // All actions except RemoveProposal are allowed by council.
                permissions: vec![
                    "*:AddProposal".to_string(),
                    "*:VoteApprove".to_string(),
                    "*:VoteReject".to_string(),
                    "*:VoteRemove".to_string(),
                    "*:Finalize".to_string(),
                ]
                .into_iter()
                .collect(),
                vote_policy: HashMap::default(),
            },
        ],
        default_vote_policy: VotePolicy::default(),
        proposal_bond: U128(10u128.pow(24)),
        proposal_period: U64::from(1_000_000_000 * 60 * 60 * 24 * 7),
        bounty_bond: U128(10u128.pow(24)),
        bounty_forgiveness_period: U64::from(1_000_000_000 * 60 * 60 * 24),
    }
}

impl VersionedPolicy {
    /// Upgrades either version of policy into the latest.
    /// 정책 버전을 최신 버전으로 업그레이드합니다.
    pub fn upgrade(self) -> Self {
        match self {
            VersionedPolicy::Default(accounts) => {
                VersionedPolicy::Current(default_policy(accounts))
            }
            VersionedPolicy::Current(policy) => VersionedPolicy::Current(policy),
        }
    }

    /// Return recent version of policy.
    /// 정책의 최신 버전을 반환합니다.
    pub fn to_policy(self) -> Policy {
        match self {
            VersionedPolicy::Current(policy) => policy,
            _ => unimplemented!(),
        }
    }

    pub fn to_policy_mut(&mut self) -> &mut Policy {
        match self {
            VersionedPolicy::Current(policy) => policy,
            _ => unimplemented!(),
        }
    }
}

impl Policy {
    /// 주어진 역할(`role`)에 따라 해당 역할을 추가하거나 업데이트합니다.
    pub fn add_or_update_role(&mut self, role: &RolePermission) {
        for i in 0..self.roles.len() {
            if &self.roles[i].name == &role.name {
                env::log_str(&format!(
                    "Updating existing role in the policy:{}",
                    &role.name
                ));
                let _ = std::mem::replace(&mut self.roles[i], role.clone());
                return;
            }
        }
        env::log_str(&format!("Adding new role to the policy:{}", &role.name));
        self.roles.push(role.clone());
    }
    /// 주어진 역할 이름을 사용하여 역할을 제거합니다.
    pub fn remove_role(&mut self, role: &String) {
        for i in 0..self.roles.len() {
            if &self.roles[i].name == role {
                self.roles.remove(i);
                return;
            }
        }
        env::log_str(&format!("ERR_ROLE_NOT_FOUND:{}", role));
    }
    /// 기본 투표 정책을 업데이트합니다.
    pub fn update_default_vote_policy(&mut self, vote_policy: &VotePolicy) {
        self.default_vote_policy = vote_policy.clone();
        env::log_str("Successfully updated the default vote policy.");
    }
    /// 정책 매개변수를 업데이트합니다
    pub fn update_parameters(&mut self, parameters: &PolicyParameters) {
        if parameters.proposal_bond.is_some() {
            self.proposal_bond = parameters.proposal_bond.unwrap();
        }
        if parameters.proposal_period.is_some() {
            self.proposal_period = parameters.proposal_period.unwrap();
        }
        if parameters.bounty_bond.is_some() {
            self.bounty_bond = parameters.bounty_bond.unwrap();
        }
        if parameters.bounty_forgiveness_period.is_some() {
            self.bounty_forgiveness_period = parameters.bounty_forgiveness_period.unwrap();
        }
        env::log_str("Successfully updated the policy parameters.");
    }
    /// 주어진 역할에 멤버를 추가합니다.
    pub fn add_member_to_role(&mut self, role: &String, member_id: &AccountId) {
        for i in 0..self.roles.len() {
            if &self.roles[i].name == role {
                self.roles[i]
                    .kind
                    .add_member_to_group(member_id)
                    .unwrap_or_else(|()| {
                        env::log_str(&format!("ERR_ROLE_WRONG_KIND:{}", role));
                    });
                return;
            }
        }
        env::log_str(&format!("ERR_ROLE_NOT_FOUND:{}", role));
    }
    /// 주어진 역할에서 멤버를 제거합니다.
    pub fn remove_member_from_role(&mut self, role: &String, member_id: &AccountId) {
        for i in 0..self.roles.len() {
            if &self.roles[i].name == role {
                self.roles[i]
                    .kind
                    .remove_member_from_group(member_id)
                    .unwrap_or_else(|()| {
                        env::log_str(&format!("ERR_ROLE_WRONG_KIND:{}", role));
                    });
                return;
            }
        }
        env::log_str(&format!("ERR_ROLE_NOT_FOUND:{}", role));
    }
    /// 사용자가 멤버로 있는 모든 역할의 권한을 반환합니다.
    /// Returns set of roles that this user is member of permissions for given user across all the roles it's member of.
    fn get_user_roles(&self, user: UserInfo) -> HashMap<String, &HashSet<String>> {
        let mut roles = HashMap::default();
        for role in self.roles.iter() {
            if role.kind.match_user(&user) {
                roles.insert(role.name.clone(), &role.permissions);
            }
        }
        roles
    }

    /// Can given user execute given action on this proposal.
    /// Returns all roles that allow this action.
    /// 주어진 사용자가 제안 유형 및 액션에 대해 지정된 액션을 실행할 수 있는지 확인합니다.
    /// 해당 액션을 허용하는 모든 역할을 반환합니다.
    pub fn can_execute_action(
        &self,
        user: UserInfo,
        proposal_kind: &ProposalKind,
        action: &Action,
    ) -> (Vec<String>, bool) {
        let roles = self.get_user_roles(user);
        let mut allowed = false;
        let allowed_roles = roles
            .into_iter()
            .filter_map(|(role, permissions)| {
                let allowed_role = permissions.contains(&format!(
                    "{}:{}",
                    proposal_kind.to_policy_label(),
                    action.to_policy_label()
                )) || permissions
                    .contains(&format!("{}:*", proposal_kind.to_policy_label()))
                    || permissions.contains(&format!("*:{}", action.to_policy_label()))
                    || permissions.contains("*:*");
                allowed = allowed || allowed_role;
                if allowed_role {
                    Some(role)
                } else {
                    None
                }
            })
            .collect();
        (allowed_roles, allowed)
    }
    
    /// Returns if given proposal kind is token weighted.
    /// 주어진 제안 유형이 토큰 가중치를 가지는지 확인합니다.
    pub fn is_token_weighted(&self, role: &String, proposal_kind_label: &String) -> bool {
        let role_info = self.internal_get_role(role).expect("ERR_ROLE_NOT_FOUND");
        match role_info
            .vote_policy
            .get(proposal_kind_label)
            .unwrap_or(&self.default_vote_policy)
            .weight_kind
        {
            WeightKind::TokenWeight => true,
            _ => false,
        }
    }
    /// 주어진 이름을 사용하여 역할 정보를 가져옵니다.
    fn internal_get_role(&self, name: &String) -> Option<&RolePermission> {
        for role in self.roles.iter() {
            if role.name == *name {
                return Some(role);
            }
        }
        None
    }

    /// Get proposal status for given proposal.
    /// Usually is called after changing it's state.
    /// 주어진 제안에 대한 제안 상태를 가져옵니다.    
    /// 주로 제안 상태가 변경된 후 호출됩니다.
    pub fn proposal_status(
        &self,
        proposal: &Proposal,
        roles: Vec<String>,
        total_supply: Balance,
    ) -> ProposalStatus {
        assert!(
            matches!(
                proposal.status,
                ProposalStatus::InProgress | ProposalStatus::Failed
            ),
            "ERR_PROPOSAL_NOT_IN_PROGRESS"
        );
        if proposal.submission_time.0 + self.proposal_period.0 < env::block_timestamp() {
            // Proposal expired.
            return ProposalStatus::Expired;
        };
        for role in roles {
            let role_info = self.internal_get_role(&role).expect("ERR_MISSING_ROLE");
            let vote_policy = role_info
                .vote_policy
                .get(&proposal.kind.to_policy_label().to_string())
                .unwrap_or(&self.default_vote_policy);
            let total_weight = match &role_info.kind {
                // Skip role that covers everyone as it doesn't provide a total size.
                RoleKind::Everyone => continue,
                RoleKind::Group(group) => {
                    if vote_policy.weight_kind == WeightKind::RoleWeight {
                        group.len() as Balance
                    } else {
                        total_supply
                    }
                }
                RoleKind::Member(_) => total_supply,
            };
            let threshold = std::cmp::max(
                vote_policy.quorum.0,
                vote_policy.threshold.to_weight(total_weight),
            );
            // Check if there is anything voted above the threshold specified by policy for given role.
            let vote_counts = proposal.vote_counts.get(&role).unwrap_or(&[0u128; 3]);
            if vote_counts[Vote::Approve as usize] >= threshold {
                return ProposalStatus::Approved;
            } else if vote_counts[Vote::Reject as usize] >= threshold {
                return ProposalStatus::Rejected;
            } else if vote_counts[Vote::Remove as usize] >= threshold {
                return ProposalStatus::Removed;
            } else {
                // continue to next role.
            }
        }
        proposal.status.clone()
    }
}

#[cfg(test)]
mod tests {
    use near_sdk::test_utils::accounts;

    use super::*;

    #[test]
    fn test_vote_policy() {
        let r1 = WeightOrRatio::Weight(U128(100));
        assert_eq!(r1.to_weight(1_000_000), 100);
        let r2 = WeightOrRatio::Ratio(1, 2);
        assert_eq!(r2.to_weight(2), 2);
        let r2 = WeightOrRatio::Ratio(1, 2);
        assert_eq!(r2.to_weight(5), 3);
        let r2 = WeightOrRatio::Ratio(1, 1);
        assert_eq!(r2.to_weight(5), 5);
    }

    #[test]
    fn test_add_role() {
        let council = vec![accounts(0), accounts(1)];
        let mut policy = default_policy(council);

        let community_role = policy.internal_get_role(&String::from("community"));
        assert!(community_role.is_none());

        let name: String = "community".to_string();
        let kind: RoleKind = RoleKind::Group(vec![accounts(2), accounts(3)].into_iter().collect());
        let permissions: HashSet<String> = vec!["*:*".to_string()].into_iter().collect();
        let vote_policy: HashMap<String, VotePolicy> = HashMap::default();
        let new_role = RolePermission {
            name: name.clone(),
            kind: kind.clone(),
            permissions: permissions.clone(),
            vote_policy: vote_policy.clone(),
        };
        assert_eq!(2, policy.roles.len());
        policy.add_or_update_role(&new_role);
        assert_eq!(3, policy.roles.len());

        let community_role = policy.internal_get_role(&String::from("community"));
        assert!(community_role.is_some());

        let community_role = community_role.unwrap();
        assert_eq!(name, community_role.name);
        assert_eq!(kind, community_role.kind);
        assert_eq!(permissions, community_role.permissions);
        assert_eq!(vote_policy, community_role.vote_policy);
    }

    #[test]
    fn test_update_role() {
        let council = vec![accounts(0), accounts(1)];
        let mut policy = default_policy(council);

        let name: String = "council".to_string();
        let kind: RoleKind = RoleKind::Group(vec![accounts(0), accounts(1)].into_iter().collect());
        let permissions: HashSet<String> = vec![
            "*:AddProposal".to_string(),
            "*:VoteApprove".to_string(),
            "*:VoteReject".to_string(),
            "*:VoteRemove".to_string(),
            "*:Finalize".to_string(),
        ]
        .into_iter()
        .collect();
        let vote_policy: HashMap<String, VotePolicy> = HashMap::default();

        let council_role = policy.internal_get_role(&String::from("council"));
        assert!(council_role.is_some());

        let council_role = council_role.unwrap();
        assert_eq!(name, council_role.name);
        assert_eq!(kind, council_role.kind);
        assert_eq!(permissions, council_role.permissions);
        assert_eq!(vote_policy, council_role.vote_policy);

        let kind: RoleKind = RoleKind::Group(vec![accounts(2), accounts(3)].into_iter().collect());
        let permissions: HashSet<String> = vec!["*:*".to_string()].into_iter().collect();
        let updated_role = RolePermission {
            name: name.clone(),
            kind: kind.clone(),
            permissions: permissions.clone(),
            vote_policy: vote_policy.clone(),
        };
        assert_eq!(2, policy.roles.len());
        policy.add_or_update_role(&updated_role);
        assert_eq!(2, policy.roles.len());

        let council_role = policy.internal_get_role(&String::from("council"));
        assert!(council_role.is_some());

        let council_role = council_role.unwrap();
        assert_eq!(name, council_role.name);
        assert_eq!(kind, council_role.kind);
        assert_eq!(permissions, council_role.permissions);
        assert_eq!(vote_policy, council_role.vote_policy);
    }

    #[test]
    fn test_remove_role() {
        let council = vec![accounts(0), accounts(1)];
        let mut policy = default_policy(council);

        let council_role = policy.internal_get_role(&String::from("council"));
        assert!(council_role.is_some());
        assert_eq!(2, policy.roles.len());

        policy.remove_role(&String::from("council"));

        let council_role = policy.internal_get_role(&String::from("council"));
        assert!(council_role.is_none());
        assert_eq!(1, policy.roles.len());
    }

    #[test]
    fn test_update_default_vote_policy() {
        let council = vec![accounts(0), accounts(1)];
        let mut policy = default_policy(council);

        assert_eq!(
            WeightKind::RoleWeight,
            policy.default_vote_policy.weight_kind
        );
        assert_eq!(U128(0), policy.default_vote_policy.quorum);
        assert_eq!(
            WeightOrRatio::Ratio(1, 2),
            policy.default_vote_policy.threshold
        );

        let new_default_vote_policy = VotePolicy {
            weight_kind: WeightKind::TokenWeight,
            quorum: U128(100),
            threshold: WeightOrRatio::Ratio(1, 4),
        };
        policy.update_default_vote_policy(&new_default_vote_policy);
        assert_eq!(
            new_default_vote_policy.weight_kind,
            policy.default_vote_policy.weight_kind
        );
        assert_eq!(
            new_default_vote_policy.quorum,
            policy.default_vote_policy.quorum
        );
        assert_eq!(
            new_default_vote_policy.threshold,
            policy.default_vote_policy.threshold
        );
    }

    #[test]
    fn test_update_parameters() {
        let council = vec![accounts(0), accounts(1)];
        let mut policy = default_policy(council);

        assert_eq!(U128(10u128.pow(24)), policy.proposal_bond);
        assert_eq!(
            U64::from(1_000_000_000 * 60 * 60 * 24 * 7),
            policy.proposal_period
        );
        assert_eq!(U128(10u128.pow(24)), policy.bounty_bond);
        assert_eq!(
            U64::from(1_000_000_000 * 60 * 60 * 24),
            policy.bounty_forgiveness_period
        );

        let new_parameters = PolicyParameters {
            proposal_bond: Some(U128(10u128.pow(26))),
            proposal_period: None,
            bounty_bond: None,
            bounty_forgiveness_period: Some(U64::from(1_000_000_000 * 60 * 60 * 24 * 5)),
        };
        policy.update_parameters(&new_parameters);
        assert_eq!(U128(10u128.pow(26)), policy.proposal_bond);
        assert_eq!(
            U64::from(1_000_000_000 * 60 * 60 * 24 * 7),
            policy.proposal_period
        );
        assert_eq!(U128(10u128.pow(24)), policy.bounty_bond);
        assert_eq!(
            U64::from(1_000_000_000 * 60 * 60 * 24 * 5),
            policy.bounty_forgiveness_period
        );
    }
}
