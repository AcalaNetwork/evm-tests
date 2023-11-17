use codec::{Decode, Encode};
use evm_utility::evm::backend::MemoryAccount;
use frame_support::{
	assert_ok, construct_runtime, ord_parameter_types, parameter_types,
	traits::{Everything, FindAuthor, Nothing},
	weights::Weight,
	BoundedVec, ConsensusEngineId,
};
use frame_system::{AccountInfo, EnsureSignedBy};
use module_evm::{
	convert_decimals_to_evm, runner::state::StackState, ContractInfo, EvmChainId, EvmTask,
	MaxCodeSize, SubstrateStackState,
};
use module_support::{AddressMapping, DispatchableTask};
use orml_traits::{parameter_type_with_key, BasicCurrencyExtended};
use primitives::{
	define_combined_task, task::TaskResult, Amount, BlockNumber, CurrencyId, ReserveIdentifier,
	TokenSymbol,
};
use scale_info::TypeInfo;
use sp_core::{H160, H256, U256};
use sp_runtime::traits::UniqueSaturatedInto;
use sp_runtime::{
	traits::{BlakeTwo256, BlockNumberProvider, Convert, IdentityLookup, Zero},
	AccountId32, BuildStorage, RuntimeDebug, SaturatedConversion,
};
use std::convert::TryInto;
use std::{collections::BTreeMap, str::FromStr};

pub type AccountId = AccountId32;
pub type Nonce = u64;
pub type Balance = u128;
pub type AccountData = pallet_balances::AccountData<Balance>;

parameter_types! {
	pub const BlockHashCount: u64 = 250;
}

impl frame_system::Config for Runtime {
	type BaseCallFilter = Everything;
	type BlockWeights = ();
	type BlockLength = ();
	type RuntimeOrigin = RuntimeOrigin;
	type RuntimeCall = RuntimeCall;
	type Nonce = Nonce;
	type Hash = H256;
	type Hashing = BlakeTwo256;
	type AccountId = AccountId;
	type Lookup = IdentityLookup<Self::AccountId>;
	type Block = Block;
	type RuntimeEvent = RuntimeEvent;
	type BlockHashCount = BlockHashCount;
	type DbWeight = ();
	type Version = ();
	type PalletInfo = PalletInfo;
	type AccountData = AccountData;
	type OnNewAccount = ();
	type OnKilledAccount = module_evm::CallKillAccount<Runtime>;
	type SystemWeightInfo = ();
	type SS58Prefix = ();
	type OnSetCode = ();
	type MaxConsumers = frame_support::traits::ConstU32<16>;
}

parameter_types! {
	pub const ExistentialDeposit: Balance = 0;
	pub const MaxReserves: u32 = 50;
}
impl pallet_balances::Config for Runtime {
	type Balance = Balance;
	type DustRemoval = ();
	type RuntimeEvent = RuntimeEvent;
	type ExistentialDeposit = ExistentialDeposit;
	type AccountStore = module_support::SystemAccountStore<Runtime>;
	type MaxLocks = ();
	type MaxReserves = MaxReserves;
	type ReserveIdentifier = ReserveIdentifier;
	type WeightInfo = ();
	type RuntimeHoldReason = RuntimeHoldReason;
	type RuntimeFreezeReason = RuntimeFreezeReason;
	type FreezeIdentifier = ();
	type MaxHolds = MaxReserves;
	type MaxFreezes = ();
}

parameter_types! {
	pub const MinimumPeriod: u64 = 1000;
}
impl pallet_timestamp::Config for Runtime {
	type Moment = u64;
	type OnTimestampSet = ();
	type MinimumPeriod = MinimumPeriod;
	type WeightInfo = ();
}

parameter_type_with_key! {
	pub ExistentialDeposits: |_currency_id: CurrencyId| -> Balance {
		Default::default()
	};
}

impl orml_tokens::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type Balance = Balance;
	type Amount = Amount;
	type CurrencyId = CurrencyId;
	type WeightInfo = ();
	type ExistentialDeposits = ExistentialDeposits;
	type CurrencyHooks = ();
	type MaxLocks = ();
	type MaxReserves = ();
	type ReserveIdentifier = ReserveIdentifier;
	type DustRemovalWhitelist = Nothing;
}

parameter_types! {
	pub const GetNativeCurrencyId: CurrencyId = CurrencyId::Token(TokenSymbol::ACA);
}

impl orml_currencies::Config for Runtime {
	type MultiCurrency = Tokens;
	type NativeCurrency = AdaptedBasicCurrency;
	type GetNativeCurrencyId = GetNativeCurrencyId;
	type WeightInfo = ();
}
pub type AdaptedBasicCurrency =
	orml_currencies::BasicCurrencyAdapter<Runtime, Balances, Amount, BlockNumber>;

define_combined_task! {
	#[derive(Clone, Encode, Decode, PartialEq, RuntimeDebug, TypeInfo)]
	pub enum ScheduledTasks {
		EvmTask(EvmTask<Runtime>),
	}
}

parameter_types!(
	pub MinimumWeightRemainInBlock: Weight = Weight::zero();
	pub DisableBlockThreshold: BlockNumber = u32::MAX;
);

pub struct MockBlockNumberProvider;

impl BlockNumberProvider for MockBlockNumberProvider {
	type BlockNumber = u32;

	fn current_block_number() -> Self::BlockNumber {
		Zero::zero()
	}
}

impl module_idle_scheduler::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type WeightInfo = ();
	type Task = ScheduledTasks;
	type MinimumWeightRemainInBlock = MinimumWeightRemainInBlock;
	type DisableBlockThreshold = DisableBlockThreshold;
	type RelayChainBlockNumberProvider = MockBlockNumberProvider;
}

impl module_evm_accounts::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type Currency = Balances;
	type ChainId = EvmChainId<Runtime>;
	type AddressMapping = module_evm_accounts::EvmAddressMapping<Runtime>;
	type TransferAll = Currencies;
	type WeightInfo = ();
}

pub struct GasToWeight;

impl Convert<u64, Weight> for GasToWeight {
	fn convert(a: u64) -> Weight {
		Weight::from_parts(a, 0)
	}
}

pub struct AuthorGiven;
impl FindAuthor<AccountId> for AuthorGiven {
	fn find_author<'a, I>(_digests: I) -> Option<AccountId>
	where
		I: 'a + IntoIterator<Item = (ConsensusEngineId, &'a [u8])>,
	{
		Some(<Runtime as module_evm::Config>::AddressMapping::get_account_id(&H160::default()))
	}
}

parameter_types! {
	pub NetworkContractSource: H160 = H160::default();
}

ord_parameter_types! {
	pub const CouncilAccount: AccountId = AccountId32::from([1u8; 32]);
	pub const TreasuryAccount: AccountId = AccountId32::from([2u8; 32]);
	pub const NetworkContractAccount: AccountId = AccountId32::from([0u8; 32]);
	pub const NewContractExtraBytes: u32 = 100;
	pub const StorageDepositPerByte: Balance = convert_decimals_to_evm(10);
	pub const TxFeePerGas: Balance = 20_000_000;
	pub const DeveloperDeposit: Balance = 1000;
	pub const PublicationFee: Balance = 200;
}

impl module_evm::Config for Runtime {
	type AddressMapping = module_evm_accounts::EvmAddressMapping<Runtime>;
	type Currency = Balances;
	type TransferAll = Currencies;
	type NewContractExtraBytes = NewContractExtraBytes;
	type StorageDepositPerByte = StorageDepositPerByte;
	type TxFeePerGas = TxFeePerGas;

	type RuntimeEvent = RuntimeEvent;
	type PrecompilesType = ();
	type PrecompilesValue = ();
	type GasToWeight = GasToWeight;
	type ChargeTransactionPayment = ();

	type NetworkContractOrigin = EnsureSignedBy<NetworkContractAccount, AccountId>;
	type NetworkContractSource = NetworkContractSource;
	type DeveloperDeposit = DeveloperDeposit;
	type PublicationFee = PublicationFee;
	type TreasuryAccount = TreasuryAccount;
	type FreePublicationOrigin = EnsureSignedBy<CouncilAccount, AccountId32>;

	type Runner = module_evm::runner::stack::Runner<Self>;
	type FindAuthor = AuthorGiven;
	type Task = ScheduledTasks;
	type IdleScheduler = IdleScheduler;
	type WeightInfo = ();
}

type Block = frame_system::mocking::MockBlock<Runtime>;

construct_runtime!(
	pub enum Runtime {
		System: frame_system,
		Timestamp: pallet_timestamp,
		EVM: module_evm,
		EVMAccounts: module_evm_accounts,
		Tokens: orml_tokens,
		Balances: pallet_balances,
		Currencies: orml_currencies,
		IdleScheduler: module_idle_scheduler,
	}
);

pub fn new_test_ext() -> sp_io::TestExternalities {
	let mut t = frame_system::GenesisConfig::<Runtime>::default()
		.build_storage()
		.unwrap();

	module_evm::GenesisConfig::<Runtime> {
		chain_id: 1,
		accounts: Default::default(),
	}
	.assimilate_storage(&mut t)
	.unwrap();

	let mut ext = sp_io::TestExternalities::new(t);
	ext.execute_with(|| System::set_block_number(1));
	ext
}

pub fn withdraw(who: H160, amount: Amount) {
	let account_id = <Runtime as module_evm::Config>::AddressMapping::get_account_id(&who);
	assert_ok!(AdaptedBasicCurrency::update_balance(&account_id, -amount));
}

pub fn deposit(who: H160, amount: Amount) {
	let account_id = <Runtime as module_evm::Config>::AddressMapping::get_account_id(&who);
	assert_ok!(AdaptedBasicCurrency::update_balance(&account_id, amount));
}

pub fn setup_state(state: BTreeMap<H160, MemoryAccount>, block_number: u64, timestamp: u64) {
	pallet_balances::TotalIssuance::<Runtime>::put(Balance::MAX);
	pallet_timestamp::Now::<Runtime>::put(timestamp * 1000);
	System::set_block_number(block_number);

	state.into_iter().for_each(|(address, value)| {
		let code_hash = module_evm::code_hash(value.code.as_slice());
		let code_size = value.code.len() as u32;
		let contract_info = if code_size > 0 {
			Some(ContractInfo {
				code_hash,
				maintainer:
					<Runtime as module_evm::Config>::AddressMapping::get_or_create_evm_address(
						&crate::mock::TreasuryAccount::get(),
					),
				published: true,
			})
		} else {
			None
		};
		module_evm::Accounts::<Runtime>::insert(
			address,
			module_evm::AccountInfo {
				nonce: value.nonce.as_u64(),
				contract_info,
			},
		);

		if code_size > 0 {
			let bounded_code: BoundedVec<u8, MaxCodeSize> = value.code.try_into().unwrap();
			module_evm::CodeInfos::<Runtime>::mutate(code_hash, |maybe_code_info| {
				if let Some(code_info) = maybe_code_info.as_mut() {
					code_info.ref_count += 1;
				} else {
					*maybe_code_info = Some(module_evm::CodeInfo {
						code_size,
						ref_count: 1,
					});
					module_evm::Codes::<Runtime>::insert(code_hash, bounded_code);
				}
			});
		}
		value.storage.into_iter().for_each(|(index, value)| {
			module_evm::AccountStorages::<Runtime>::insert(address, index, value);
		});

		let account_id = <Runtime as module_evm::Config>::AddressMapping::get_account_id(&address);
		frame_system::Account::<Runtime>::insert(
			account_id,
			frame_system::AccountInfo {
				providers: 1,
				data: pallet_balances::AccountData {
					free: value.balance.saturated_into(),
					..Default::default()
				},
				..Default::default()
			},
		);
	});
}

pub fn get_state(substate: &SubstrateStackState<Runtime>) -> BTreeMap<H160, MemoryAccount> {
	let mut state: BTreeMap<H160, MemoryAccount> = BTreeMap::new();
	module_evm::Accounts::<Runtime>::iter().for_each(|(address, account)| {
		let acc = <Runtime as module_evm::Config>::AddressMapping::get_account_id(&address);
		if substate.deleted(address) {
			return;
		}

		let account_info: AccountInfo<Nonce, pallet_balances::AccountData<Balance>> =
			frame_system::Account::<Runtime>::get(acc);
		if let Some(ContractInfo { code_hash, .. }) = account.contract_info {
			let code = module_evm::Codes::<Runtime>::get(code_hash).to_vec();
			let mut storage: BTreeMap<H256, H256> = BTreeMap::new();
			module_evm::AccountStorages::<Runtime>::iter_prefix(address).for_each(
				|(key, value)| {
					storage.insert(key, value);
				},
			);
			let mut balance = account_info.data.free.into();
			let nonce: u64 = account.nonce.unique_saturated_into();
			if balance == U256::from(u128::MAX) {
				balance = U256::from_str(
					"0x0fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
				)
				.unwrap();
			}

			state.insert(
				address,
				MemoryAccount {
					nonce: U256::from(nonce),
					balance,
					storage,
					code,
				},
			);
		} else {
			let mut balance = account_info.data.free.into();
			let nonce: u64 = account.nonce.unique_saturated_into();
			if balance == U256::from(u128::MAX) {
				balance = U256::from_str(
					"0x0fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
				)
				.unwrap();
			}

			let mut storage: BTreeMap<H256, H256> = BTreeMap::new();
			module_evm::AccountStorages::<Runtime>::iter_prefix(address).for_each(
				|(key, value)| {
					storage.insert(key, value);
				},
			);

			state.insert(
				address,
				MemoryAccount {
					nonce: U256::from(nonce),
					balance,
					storage,
					code: vec![],
				},
			);
		}
	});

	frame_system::Account::<Runtime>::iter().for_each(|(acc, data)| {
		if acc == TreasuryAccount::get() {
			return;
		} // skip treasury
		let address =
			<Runtime as module_evm::Config>::AddressMapping::get_or_create_evm_address(&acc);
		if state.contains_key(&address) {
			return;
		}
		if substate.deleted(address) {
			return;
		}

		let account_info: AccountInfo<Nonce, pallet_balances::AccountData<Balance>> = data;
		let mut storage: BTreeMap<H256, H256> = BTreeMap::new();
		module_evm::AccountStorages::<Runtime>::iter_prefix(address).for_each(|(key, value)| {
			storage.insert(key, value);
		});
		let mut balance: U256 = account_info.data.free.into();
		let nonce: u64 = account_info.nonce.unique_saturated_into();
		if balance == U256::from(u128::MAX) {
			balance = U256::from_str(
				"0x0fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			)
			.unwrap();
		}

		state.insert(
			address,
			MemoryAccount {
				nonce: U256::from(nonce),
				balance,
				storage,
				code: vec![],
			},
		);
	});

	// remove touched empty accounts
	for address in substate.empty_accounts() {
		state.remove(&address);
	}

	state
}
