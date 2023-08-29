use crate::mock::{deposit, get_state, new_test_ext, setup_state, withdraw, Runtime, EVM};
use crate::utils::*;
use ethjson::spec::ForkSpec;
use evm_utility::evm::{backend::MemoryAccount, Config};
use libsecp256k1::SecretKey;
use module_evm::{
	precompiles::{
		Blake2F, Bn128Add, Bn128Mul, Bn128Pairing, ECRecover, Identity, IstanbulModexp, Modexp,
		Precompile, Ripemd160, Sha256,
	},
	runner::state::{PrecompileFn, StackState},
	StackExecutor, StackSubstateMetadata, SubstrateStackState, Vicinity,
};
use primitives::convert_decimals_to_evm;
use serde::Deserialize;
use sha3::{Digest, Keccak256};
use sp_core::{H160, H256, U256};
use sp_runtime::SaturatedConversion;
use std::collections::BTreeMap;

#[derive(Deserialize, Debug)]
pub struct Test(ethjson::test_helpers::state::State);

impl Test {
	pub fn unwrap_to_gas_limit(&self) -> u64 {
		self.0.env.gas_limit.into()
	}
	pub fn unwrap_to_pre_state(&self) -> BTreeMap<H160, MemoryAccount> {
		unwrap_to_state(&self.0.pre_state)
	}

	pub fn unwrap_caller(&self) -> H160 {
		let hash: H256 = self.0.transaction.secret.unwrap().into();
		let mut secret_key = [0; 32];
		secret_key.copy_from_slice(hash.as_bytes());
		let secret = SecretKey::parse(&secret_key).unwrap();
		let public = libsecp256k1::PublicKey::from_secret_key(&secret);
		let mut res = [0u8; 64];
		res.copy_from_slice(&public.serialize()[1..65]);

		H160::from(H256::from_slice(Keccak256::digest(res).as_slice()))
	}

	pub fn unwrap_to_vicinity(&self, spec: &ForkSpec) -> Option<Vicinity> {
		let block_base_fee_per_gas = self.0.env.block_base_fee_per_gas.0;
		let gas_price = if self.0.transaction.gas_price.0.is_zero() {
			let max_fee_per_gas = self.0.transaction.max_fee_per_gas.0;

			// max_fee_per_gas is only defined for London and later
			if !max_fee_per_gas.is_zero() && spec < &ForkSpec::London {
				return None;
			}

			// Cannot specify a lower fee than the base fee
			if max_fee_per_gas < block_base_fee_per_gas {
				return None;
			}

			let max_priority_fee_per_gas = self.0.transaction.max_priority_fee_per_gas.0;

			// priority fee must be lower than regaular fee
			if max_fee_per_gas < max_priority_fee_per_gas {
				return None;
			}

			let priority_fee_per_gas = std::cmp::min(
				max_priority_fee_per_gas,
				max_fee_per_gas - block_base_fee_per_gas,
			);
			priority_fee_per_gas + block_base_fee_per_gas
		} else {
			self.0.transaction.gas_price.0
		};

		// gas price cannot be lower than base fee
		if gas_price < block_base_fee_per_gas {
			return None;
		}

		Some(Vicinity {
			gas_price,
			origin: self.unwrap_caller(),
			// block_hashes: Vec::new(),
			// block_number: self.0.env.number.clone().into(),
			block_coinbase: Some(self.0.env.author.into()),
			// block_timestamp: self.0.env.timestamp.clone().into(),
			block_difficulty: Some(self.0.env.difficulty.into()),
			block_gas_limit: Some(self.0.env.gas_limit.into()),
			// chain_id: U256::one(),
			block_base_fee_per_gas: Some(block_base_fee_per_gas),
		})
	}
}

pub struct JsonPrecompile;

impl JsonPrecompile {
	pub fn precompile(spec: &ForkSpec) -> Option<BTreeMap<H160, PrecompileFn>> {
		match spec {
			ForkSpec::Istanbul => {
				let mut map = BTreeMap::<H160, PrecompileFn>::new();
				map.insert(H160::from_low_u64_be(1), <ECRecover as Precompile>::execute);
				map.insert(H160::from_low_u64_be(2), <Sha256 as Precompile>::execute);
				map.insert(H160::from_low_u64_be(3), <Ripemd160 as Precompile>::execute);
				map.insert(H160::from_low_u64_be(4), <Identity as Precompile>::execute);
				map.insert(H160::from_low_u64_be(5), IstanbulModexp::execute);
				map.insert(H160::from_low_u64_be(6), Bn128Add::execute);
				map.insert(H160::from_low_u64_be(7), Bn128Mul::execute);
				map.insert(H160::from_low_u64_be(8), Bn128Pairing::execute);
				map.insert(H160::from_low_u64_be(9), Blake2F::execute);
				Some(map)
			}
			ForkSpec::Berlin => {
				let mut map = Self::precompile(&ForkSpec::Istanbul).unwrap();
				map.insert(H160::from_low_u64_be(5), Modexp::execute);
				Some(map)
			}
			// precompiles for London and Berlin are the same
			ForkSpec::London => Self::precompile(&ForkSpec::Berlin),
			_ => None,
		}
	}
}

/// Denotes the type of transaction.
#[derive(Debug, PartialEq)]
enum TxType {
	/// All transactions before EIP-2718 are legacy.
	Legacy,
	/// https://eips.ethereum.org/EIPS/eip-2718
	AccessList,
	/// https://eips.ethereum.org/EIPS/eip-1559
	DynamicFee,
}

impl TxType {
	/// Whether this is a legacy, access list, dynamic fee, etc transaction
	// Taken from geth's core/types/transaction.go/UnmarshalBinary, but we only detect the transaction
	// type rather than unmarshal the entire payload.
	fn from_txbytes(txbytes: &[u8]) -> Self {
		match txbytes[0] {
			b if b > 0x7f => Self::Legacy,
			1 => Self::AccessList,
			2 => Self::DynamicFee,
			_ => panic!(
				"Unknown tx type. \
You may need to update the TxType enum if Ethereum introduced new enveloped transaction types."
			),
		}
	}
}

pub fn test(name: &str, test: Test) {
	use std::thread;

	const STACK_SIZE: usize = 16 * 1024 * 1024;

	let name = name.to_string();
	// Spawn thread with explicit stack size
	let child = thread::Builder::new()
		.stack_size(STACK_SIZE)
		.spawn(move || test_run(&name, test))
		.unwrap();

	// Wait for thread to join
	child.join().unwrap();
}

fn test_run(name: &str, test: Test) {
	for (spec, states) in &test.0.post_states {
		new_test_ext().execute_with(|| {
			let (gasometer_config, _delete_empty) = match spec {
				ethjson::spec::ForkSpec::Istanbul => (Config::istanbul(), true),
				ethjson::spec::ForkSpec::Berlin => (Config::berlin(), true),
				ethjson::spec::ForkSpec::London => (Config::london(), true),
				_spec => {
					println!("Skip spec {:?}", spec);
					return;
				}
			};

			let original_state = test.unwrap_to_pre_state();

			let vicinity = test.unwrap_to_vicinity(spec);
			if vicinity.is_none() {
				// if vicinity could not be computed then the transaction was invalid so we simply
				// check the original state and move on
				assert_valid_hash(&states.first().unwrap().hash.0, &original_state);
				return;
			}

			let vicinity = vicinity.unwrap();
			let caller = test.unwrap_caller();
			let caller_balance = original_state.get(&caller).unwrap().balance;

			for (i, state) in states.iter().enumerate() {
				println!("Running {}:{:?}:{} ... ", name, spec, i);
				flush();

				let transaction = test.0.transaction.select(&state.indexes);

				// Test case may be expected to fail with an unsupported tx type if the current fork is
				// older than Berlin (see EIP-2718). However, this is not implemented in sputnik itself and rather
				// in the code hosting sputnik. https://github.com/rust-blockchain/evm/pull/40
				let tx_type = TxType::from_txbytes(&state.txbytes);
				if matches!(
					spec,
					ForkSpec::EIP150
						| ForkSpec::EIP158 | ForkSpec::Frontier
						| ForkSpec::Homestead | ForkSpec::Byzantium
						| ForkSpec::Constantinople
						| ForkSpec::ConstantinopleFix
						| ForkSpec::Istanbul
				) && tx_type != TxType::Legacy
					&& state.expect_exception == Some("TR_TypeNotSupported".to_string())
				{
					println!("Skip unsupported tx type {:?} for spec {:?}", tx_type, spec);
					continue;
				}

				// Only execute valid transactions
				match crate::utils::transaction::validate(
					transaction,
					test.0.env.gas_limit.0,
					caller_balance,
					&gasometer_config,
				) {
					Ok(transaction) => {
						setup_state(
							original_state.clone(),
							test.0.env.number.0.as_u64(),
							test.0.env.timestamp.0.as_u64(),
						);

						let gas_limit: u64 = transaction.gas_limit.into();
						let data: Vec<u8> = transaction.data.into();

						let metadata =
							StackSubstateMetadata::new(gas_limit, 1_000_000, &gasometer_config);

						let stack_state = SubstrateStackState::<Runtime>::new(&vicinity, metadata);

						let precompile = JsonPrecompile::precompile(spec).unwrap();
						let mut executor = StackExecutor::new_with_precompiles(
							stack_state,
							&gasometer_config,
							&precompile,
						);

						let total_fee = (vicinity.gas_price * gas_limit).saturated_into::<i128>();
						withdraw(caller, total_fee);

						let access_list = transaction
							.access_list
							.into_iter()
							.map(|(address, keys)| {
								(address.0, keys.into_iter().map(|k| k.0).collect())
							})
							.collect();

						match transaction.to {
							ethjson::maybe::MaybeEmpty::Some(to) => {
								let data = data;
								let value: U256 = transaction.value.into();

								let _reason = executor.transact_call(
									caller,
									to.into(),
									convert_decimals_to_evm(value.saturated_into::<u128>()).into(),
									data,
									gas_limit,
									access_list,
								);
							}
							ethjson::maybe::MaybeEmpty::None => {
								let code = data;
								let value: U256 = transaction.value.into();

								let _reason = executor.transact_create(
									caller,
									convert_decimals_to_evm(value.saturated_into::<u128>()).into(),
									code,
									gas_limit,
									access_list,
								);
							}
						}

						for address in executor.state().deleted_accounts() {
							let _ = EVM::remove_contract(&caller, &address);
						}

						let actual_fee = executor.fee(vicinity.gas_price).saturated_into::<i128>();
						let miner_reward = if let ForkSpec::London = spec {
							// see EIP-1559
							let max_priority_fee_per_gas =
								test.0.transaction.max_priority_fee_per_gas();
							let max_fee_per_gas = test.0.transaction.max_fee_per_gas();
							let base_fee_per_gas =
								vicinity.block_base_fee_per_gas.unwrap_or_default();
							let priority_fee_per_gas = std::cmp::min(
								max_priority_fee_per_gas,
								max_fee_per_gas - base_fee_per_gas,
							);
							executor.fee(priority_fee_per_gas).saturated_into()
						} else {
							actual_fee
						};

						let miner = vicinity.block_coinbase.unwrap();
						executor.state_mut().touch(miner);
						deposit(miner, miner_reward);

						let refund_fee = total_fee - actual_fee;
						deposit(caller, refund_fee);

						if let Some(post_state) = state.post_state.clone() {
							let expected_state = post_state
								.into_iter()
								.map(|(acc, data)| (acc.into(), unwrap_to_account(&data)))
								.collect::<BTreeMap<H160, MemoryAccount>>();
							let actual_state = get_state(&executor.into_state());
							assert_states(expected_state, actual_state);
						} else {
							// No post state found, validate hashes
							assert_valid_hash(&state.hash.0, &get_state(&executor.into_state()));
						}

						// clear
						#[allow(deprecated)]
						module_evm::Accounts::<Runtime>::remove_all(None);
						#[allow(deprecated)]
						module_evm::AccountStorages::<Runtime>::remove_all(None);
						#[allow(deprecated)]
						module_evm::Codes::<Runtime>::remove_all(None);
						#[allow(deprecated)]
						module_evm::CodeInfos::<Runtime>::remove_all(None);
						#[allow(deprecated)]
						module_evm::ContractStorageSizes::<Runtime>::remove_all(None);
						#[allow(deprecated)]
						frame_system::Account::<Runtime>::remove_all(None);
					}
					Err(e) => {
						assert_eq!(state.expect_exception, Some(e.to_string()));
					}
				}

				println!("passed");
			}
		});
	}
}

fn assert_states(a: BTreeMap<H160, MemoryAccount>, b: BTreeMap<H160, MemoryAccount>) {
	let mut b = b;
	a.into_iter().for_each(|(address, a_account)| {
		let maybe_b_account = b.get(&address);
		assert!(
			maybe_b_account.is_some(),
			"address {:?} not found in b states",
			address
		);
		let b_account = maybe_b_account.unwrap();
		// EVM+ can't handle balance greater than u128::MAX, skip balance validation
		if a_account.balance <= U256::from(u128::MAX) {
			assert_eq!(
				a_account.balance, b_account.balance,
				"balance not eq for address {:?}",
				address
			);
		}
		assert_eq!(
			a_account.nonce, b_account.nonce,
			"nonce not eq for address {:?}",
			address
		);
		assert_eq!(
			a_account.storage, b_account.storage,
			"storage not eq for address {:?}",
			address
		);
		assert_eq!(
			a_account.code, b_account.code,
			"code not eq for address {:?}",
			address
		);
		b.remove(&address);
	});
	assert!(b.is_empty(), "unexpected state {:?}", b);
}
