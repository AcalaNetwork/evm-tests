use evm_utility::evm::backend::MemoryAccount;
use lazy_static::lazy_static;
use sha3::{Digest, Keccak256};
use sp_core::{H160, H256, U256};
use std::{
	collections::BTreeMap,
	fs::File,
	io::{BufRead, BufReader},
	path::Path,
};

pub fn u256_to_h256(u: U256) -> H256 {
	let mut h = H256::default();
	u.to_big_endian(&mut h[..]);
	h
}

pub fn unwrap_to_account(s: &ethjson::spec::Account) -> MemoryAccount {
	MemoryAccount {
		balance: s.balance.unwrap().into(),
		nonce: s.nonce.unwrap().into(),
		code: s.code.clone().unwrap().into(),
		storage: s
			.storage
			.as_ref()
			.unwrap()
			.iter()
			.filter_map(|(k, v)| {
				if v.0.is_zero() {
					// If value is zero then the key is not really there
					None
				} else {
					Some((u256_to_h256((*k).into()), u256_to_h256((*v).into())))
				}
			})
			.collect(),
	}
}

pub fn unwrap_to_state(a: &ethjson::spec::State) -> BTreeMap<H160, MemoryAccount> {
	match &a.0 {
		ethjson::spec::HashOrMap::Map(m) => m
			.iter()
			.map(|(k, v)| ((*k).into(), unwrap_to_account(v)))
			.collect(),
		ethjson::spec::HashOrMap::Hash(_) => panic!("Hash can not be converted."),
	}
}

/// Basic account type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrieAccount {
	/// Nonce of the account.
	pub nonce: U256,
	/// Balance of the account.
	pub balance: U256,
	/// Storage root of the account.
	pub storage_root: H256,
	/// Code hash of the account.
	pub code_hash: H256,
	/// Code version of the account.
	pub code_version: U256,
}

impl rlp::Encodable for TrieAccount {
	fn rlp_append(&self, stream: &mut rlp::RlpStream) {
		let use_short_version = self.code_version == U256::zero();

		match use_short_version {
			true => {
				stream.begin_list(4);
			}
			false => {
				stream.begin_list(5);
			}
		}

		stream.append(&self.nonce);
		stream.append(&self.balance);
		stream.append(&self.storage_root);
		stream.append(&self.code_hash);

		if !use_short_version {
			stream.append(&self.code_version);
		}
	}
}

impl rlp::Decodable for TrieAccount {
	fn decode(rlp: &rlp::Rlp) -> Result<Self, rlp::DecoderError> {
		let use_short_version = match rlp.item_count()? {
			4 => true,
			5 => false,
			_ => return Err(rlp::DecoderError::RlpIncorrectListLen),
		};

		Ok(TrieAccount {
			nonce: rlp.val_at(0)?,
			balance: rlp.val_at(1)?,
			storage_root: rlp.val_at(2)?,
			code_hash: rlp.val_at(3)?,
			code_version: if use_short_version {
				U256::zero()
			} else {
				rlp.val_at(4)?
			},
		})
	}
}

pub fn assert_valid_state(a: &ethjson::spec::State, b: &BTreeMap<H160, MemoryAccount>) {
	match &a.0 {
		ethjson::spec::HashOrMap::Map(m) => {
			assert_eq!(
				&m.iter()
					.map(|(k, v)| { ((*k).into(), unwrap_to_account(v)) })
					.collect::<BTreeMap<_, _>>(),
				b
			);
		}
		ethjson::spec::HashOrMap::Hash(h) => assert_valid_hash(&(*h).into(), b),
	}
}

pub fn assert_valid_hash(h: &H256, b: &BTreeMap<H160, MemoryAccount>) {
	let tree = b
		.iter()
		.map(|(address, account)| {
			let storage_root = ethereum::util::sec_trie_root(
				account
					.storage
					.iter()
					.map(|(k, v)| (k, rlp::encode(&U256::from_big_endian(&v[..])))),
			);
			let code_hash = H256::from_slice(Keccak256::digest(&account.code).as_slice());

			let account = TrieAccount {
				nonce: account.nonce,
				balance: account.balance,
				storage_root,
				code_hash,
				code_version: U256::zero(),
			};

			(address, rlp::encode(&account))
		})
		.collect::<Vec<_>>();

	let root = ethereum::util::sec_trie_root(tree);

	if root != *h {
		panic!(
			"Hash not equal; calculated: {:?}, expect: {:?}\nState: {:#x?}",
			root, *h, b
		);
	}
}

pub fn flush() {
	use std::io::{self, Write};

	io::stdout().flush().expect("Could not flush stdout");
}

pub mod transaction {
	use ethjson::maybe::MaybeEmpty;
	use ethjson::transaction::Transaction;
	use ethjson::uint::Uint;
	use evm_utility::evm::gasometer::{self, Gasometer};
	use sp_core::{H160, H256, U256};

	pub fn validate(
		tx: Transaction,
		block_gas_limit: U256,
		caller_balance: U256,
		config: &evm_utility::evm::Config,
	) -> Result<Transaction, InvalidTxReason> {
		if tx.nonce.0 == U256::from(u64::MAX) {
			return Err(InvalidTxReason::NonceHasMaxValue);
		}

		match intrinsic_gas(&tx, config) {
			None => return Err(InvalidTxReason::IntrinsicGas),
			Some(required_gas) => {
				if tx.gas_limit < Uint(U256::from(required_gas)) {
					return Err(InvalidTxReason::IntrinsicGas);
				}
			}
		}

		if block_gas_limit < tx.gas_limit.0 {
			return Err(InvalidTxReason::GasLimitReached);
		}

		let required_funds = tx
			.gas_limit
			.0
			.checked_mul(tx.gas_price.0)
			.and_then(|v| v.checked_add(tx.value.0))
			.ok_or(InvalidTxReason::OutOfFund)?;
		if caller_balance < required_funds {
			return Err(InvalidTxReason::OutOfFund);
		}

		Ok(tx)
	}

	fn intrinsic_gas(tx: &Transaction, config: &evm_utility::evm::Config) -> Option<u64> {
		let is_contract_creation = match tx.to {
			MaybeEmpty::None => true,
			MaybeEmpty::Some(_) => false,
		};
		let data = &tx.data;
		let access_list: Vec<(H160, Vec<H256>)> = tx
			.access_list
			.iter()
			.map(|(a, s)| (a.0, s.iter().map(|h| h.0).collect()))
			.collect();

		let cost = if is_contract_creation {
			gasometer::create_transaction_cost(data, &access_list)
		} else {
			gasometer::call_transaction_cost(data, &access_list)
		};

		let mut g = Gasometer::new(u64::MAX, config);
		g.record_transaction(cost).ok()?;

		Some(g.total_used_gas())
	}

	pub enum InvalidTxReason {
		IntrinsicGas,
		OutOfFund,
		GasLimitReached,
		NonceHasMaxValue,
	}

	impl std::fmt::Display for InvalidTxReason {
		fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
			match self {
				InvalidTxReason::IntrinsicGas => write!(f, "TR_IntrinsicGas"),
				InvalidTxReason::OutOfFund => write!(f, "TR_NoFunds"),
				InvalidTxReason::GasLimitReached => write!(f, "TR_GasLimitReached"),
				InvalidTxReason::NonceHasMaxValue => write!(f, "TR_NonceHasMaxValue"),
			}
		}
	}
}

pub fn should_skip_test(path: &Path) -> bool {
	// read .ignorecases file as a list of test cases to skip
	lazy_static! {
		static ref SKIPPED_CASES: Vec<String> = BufReader::new(
			File::open(format!(
				"{}/tests/.ignoretests",
				std::env::current_dir().unwrap().display()
			))
			.expect("open file")
		)
		.lines()
		.map(|l| l.expect("parse line").trim().to_string())
		.filter(|x| !x.is_empty() || x.starts_with('#') || x.starts_with("//"))
		.collect::<Vec<_>>();
	}

	let matches = |case: &str| {
		let file_stem = path.file_stem().unwrap();
		let dir_path = path.parent().unwrap();
		let dir_name = dir_path.file_name().unwrap();
		Path::new(dir_name).join(file_stem) == Path::new(case)
	};

	for case in SKIPPED_CASES.iter() {
		if matches(case) {
			return true;
		}
	}

	false
}
