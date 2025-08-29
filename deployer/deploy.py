import json
import os
import time
from pathlib import Path

from tenacity import retry, wait_fixed, stop_after_delay
from web3 import Web3
from solcx import compile_standard, install_solc


WEB3_PROVIDER_URL = os.getenv("WEB3_PROVIDER_URL", "http://ganache:8545")
CONTRACTS_DIR = Path("/contracts")
OUTPUT_PATH = CONTRACTS_DIR / "Allowlist.json"
SOLC_VERSION = os.getenv("SOLC_VERSION", "0.8.26")


def load_contract_source() -> str:
    source_path = CONTRACTS_DIR / "Allowlist.sol"
    with open(source_path, "r") as f:
        return f.read()


@retry(wait=wait_fixed(2), stop=stop_after_delay(60))
def wait_for_chain() -> Web3:
    web3 = Web3(Web3.HTTPProvider(WEB3_PROVIDER_URL))
    assert web3.is_connected(), "Web3 provider not reachable yet"
    return web3


def compile_contract(source: str):
    install_solc(SOLC_VERSION)
    compiled = compile_standard(
        {
            "language": "Solidity",
            "sources": {"Allowlist.sol": {"content": source}},
            "settings": {
                "outputSelection": {"*": {"*": ["abi", "evm.bytecode"]}},
            },
        },
        solc_version=SOLC_VERSION,
    )
    contract_interface = compiled["contracts"]["Allowlist.sol"]["Allowlist"]
    abi = contract_interface["abi"]
    bytecode = contract_interface["evm"]["bytecode"]["object"]
    return abi, bytecode


def get_initial_allowlist() -> list[str]:
    raw = os.getenv("INITIAL_ALLOWLIST", "")
    addresses = [a.strip() for a in raw.split(",") if a.strip()]
    return addresses


def main() -> None:
    CONTRACTS_DIR.mkdir(parents=True, exist_ok=True)
    web3 = wait_for_chain()
    accounts = web3.eth.accounts
    if not accounts:
        raise RuntimeError("No accounts available on provider")
    deployer = accounts[0]

    source = load_contract_source()
    abi, bytecode = compile_contract(source)

    contract = web3.eth.contract(abi=abi, bytecode=bytecode)
    tx = contract.constructor(get_initial_allowlist()).transact({"from": deployer})
    receipt = web3.eth.wait_for_transaction_receipt(tx)
    address = receipt.contractAddress

    out = {"address": address, "abi": abi}
    with open(OUTPUT_PATH, "w") as f:
        json.dump(out, f)

    print(f"Deployed Allowlist at {address}; written to {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
