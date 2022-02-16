use crate::mock::{deposit, get_state, new_test_ext, setup_state, withdraw, Runtime, EVM};
use crate::utils::*;
use ethjson::spec::ForkSpec;
use evm_utility::evm::{backend::MemoryAccount, Config, ExitError, ExitSucceed};
use lazy_static::lazy_static;
use module_evm::{
	runner::state::{PrecompileFn, PrecompileOutput, PrecompileFailure, StackState},
	Context, StackExecutor, StackSubstateMetadata, SubstrateStackState, Vicinity,
};
use parity_crypto::publickey;
use primitive_types::{H160, H256, U256};
use primitives::convert_decimals_to_evm;
use serde::Deserialize;
use sp_runtime::SaturatedConversion;
use std::collections::BTreeMap;
use std::convert::TryInto;
use std::sync::Mutex;

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
		let secret_key: H256 = self.0.transaction.secret.clone().unwrap().into();
		let secret = publickey::Secret::import_key(&secret_key[..]).unwrap();
		let public = publickey::KeyPair::from_secret(secret)
			.unwrap()
			.public()
			.clone();
		let sender = publickey::public_to_address(&public);

		sender
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
			block_coinbase: Some(self.0.env.author.clone().into()),
			// block_timestamp: self.0.env.timestamp.clone().into(),
			block_difficulty: Some(self.0.env.difficulty.clone().into()),
			block_gas_limit: Some(self.0.env.gas_limit.clone().into()),
			// chain_id: U256::one(),
			block_base_fee_per_gas: Some(block_base_fee_per_gas),
		})
	}
}

lazy_static! {
	static ref ISTANBUL_BUILTINS: BTreeMap<H160, ethcore_builtin::Builtin> =
		JsonPrecompile::builtins("./res/istanbul_builtins.json");
}

lazy_static! {
	static ref BERLIN_BUILTINS: BTreeMap<H160, ethcore_builtin::Builtin> =
		JsonPrecompile::builtins("./res/berlin_builtins.json");
}

lazy_static! {
	static ref PRECOMPILE_LIST: Mutex<BTreeMap<H160, PrecompileFn>> = Mutex::new(BTreeMap::new());
}

macro_rules! precompile_entry {
	($map:expr, $builtins:expr, $index:expr) => {
		let x: fn(
			&[u8],
			Option<u64>,
			&Context,
			bool,
		) -> Result<PrecompileOutput, PrecompileFailure> =
			|input: &[u8], gas_limit: Option<u64>, _context: &Context, _is_static: bool| {
				let builtin = $builtins.get(&H160::from_low_u64_be($index)).unwrap();
				Self::exec_as_precompile(builtin, input, gas_limit)
			};
		$map.insert(H160::from_low_u64_be($index), x);
	};
}

pub struct JsonPrecompile;

impl JsonPrecompile {
	pub fn precompile(spec: &ForkSpec) -> Option<BTreeMap<H160, PrecompileFn>> {
		match spec {
			ForkSpec::Istanbul => {
				let mut map = BTreeMap::new();
				precompile_entry!(map, ISTANBUL_BUILTINS, 1);
				precompile_entry!(map, ISTANBUL_BUILTINS, 2);
				precompile_entry!(map, ISTANBUL_BUILTINS, 3);
				precompile_entry!(map, ISTANBUL_BUILTINS, 4);
				precompile_entry!(map, ISTANBUL_BUILTINS, 5);
				precompile_entry!(map, ISTANBUL_BUILTINS, 6);
				precompile_entry!(map, ISTANBUL_BUILTINS, 7);
				precompile_entry!(map, ISTANBUL_BUILTINS, 8);
				precompile_entry!(map, ISTANBUL_BUILTINS, 9);
				Some(map)
			}
			ForkSpec::Berlin => {
				let mut map = BTreeMap::new();
				precompile_entry!(map, BERLIN_BUILTINS, 1);
				precompile_entry!(map, BERLIN_BUILTINS, 2);
				precompile_entry!(map, BERLIN_BUILTINS, 3);
				precompile_entry!(map, BERLIN_BUILTINS, 4);
				precompile_entry!(map, BERLIN_BUILTINS, 5);
				precompile_entry!(map, BERLIN_BUILTINS, 6);
				precompile_entry!(map, BERLIN_BUILTINS, 7);
				precompile_entry!(map, BERLIN_BUILTINS, 8);
				precompile_entry!(map, BERLIN_BUILTINS, 9);
				Some(map)
			}
			// precompiles for London and Berlin are the same
			ForkSpec::London => Self::precompile(&ForkSpec::Berlin),
			_ => None,
		}
	}

	fn builtins(spec_path: &str) -> BTreeMap<H160, ethcore_builtin::Builtin> {
		let reader = std::fs::File::open(spec_path).unwrap();
		let builtins: BTreeMap<ethjson::hash::Address, ethjson::spec::builtin::BuiltinCompat> =
			serde_json::from_reader(reader).unwrap();
		builtins
			.into_iter()
			.map(|(address, builtin)| {
				(
					address.into(),
					ethjson::spec::Builtin::from(builtin).try_into().unwrap(),
				)
			})
			.collect()
	}

	fn exec_as_precompile(
		builtin: &ethcore_builtin::Builtin,
		input: &[u8],
		gas_limit: Option<u64>,
	) -> Result<PrecompileOutput, PrecompileFailure> {
		let cost = builtin.cost(input, 0);

		if let Some(target_gas) = gas_limit {
			if cost > U256::from(u64::MAX) || target_gas < cost.as_u64() {
				return Err(PrecompileFailure::Error {
					exit_status: ExitError::OutOfGas,
				});
			}
		}

		let mut output = Vec::new();
		match builtin.execute(input, &mut parity_bytes::BytesRef::Flexible(&mut output)) {
			Ok(()) => Ok(PrecompileOutput {
				exit_status: ExitSucceed::Stopped,
				output,
				cost: cost.as_u64(),
				logs: Vec::new(),
			}),
			Err(e) => Err(PrecompileFailure::Error {
				exit_status: ExitError::Other(e.into()),
			}),
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

lazy_static! {
	static ref SKIP_NAMES: Vec<&'static str> = vec![
		// balance overflow
		"Create2Recursive",
		"static_Call50000_ecrec",
		"Call50000_ecrec",
		// touching addresses not the same as ethereum
		"RevertPrecompiledTouch",
		"RevertPrecompiledTouch_storage",
		"RevertPrecompiledTouchExactOOG",
	];
}

fn test_run(name: &str, test: Test) {
	// skip those tests until fixed
	if SKIP_NAMES.contains(&name) { return; }

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

				// Only execute valid transactions
				if let Ok(transaction) = crate::utils::transaction::validate(
					transaction,
					test.0.env.gas_limit.0,
					caller_balance,
					&gasometer_config,
				) {
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
						.map(|(address, keys)| (address.0, keys.into_iter().map(|k| k.0).collect()))
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
						let _ = EVM::remove_contract(&H160::default(), &address);
					}

					let actual_fee = executor.fee(vicinity.gas_price).saturated_into::<i128>();
					let miner_reward = if let ForkSpec::London = spec {
						// see EIP-1559
						let max_priority_fee_per_gas = test.0.transaction.max_priority_fee_per_gas();
						let max_fee_per_gas = test.0.transaction.max_fee_per_gas();
						let base_fee_per_gas = vicinity.block_base_fee_per_gas.unwrap_or_default();
						let priority_fee_per_gas =
							std::cmp::min(max_priority_fee_per_gas, max_fee_per_gas - base_fee_per_gas);
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
					module_evm::Accounts::<Runtime>::remove_all(None);
					module_evm::AccountStorages::<Runtime>::remove_all(None);
					module_evm::Codes::<Runtime>::remove_all(None);
					module_evm::CodeInfos::<Runtime>::remove_all(None);
					module_evm::ContractStorageSizes::<Runtime>::remove_all(None);
					frame_system::Account::<Runtime>::remove_all(None);
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
			assert_eq!(a_account.balance, b_account.balance, "balance not eq for address {:?}", address);
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
