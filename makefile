DIRSIGNER = 'pythonref'
PYTHON=pythonref/myenv/bin/python
CORES := $(shell nproc)

# INSTALL

install: install_signer install_verifier

install_signer:
	make -C $(DIRSIGNER) install

install_verifier:
	foundryup
	forge install ZKNOXHQ/InterfaceVerifier
	forge install 0xsequence/sstore2

# GENERATION OF TEST VECTORS

gen_test_vectors:
	make -C $(DIRSIGNER) generate_test_vectors


# TESTS

test: test_signer test_verifier test_onchain

test_slow: test_signer test_verifier_slow test_onchain

test_signer:
	make -C $(DIRSIGNER) test

test_verifier:
	FOUNDRY_PROFILE=lite forge test -j$(CORES) -vv

test_verifier_slow:
	forge test -j$(CORES) -vv

RPC_ONCHAIN ?= https://sepolia.optimism.io

# For each of FALCON, ETHFALCON and EPERVIER: generate a key pair, sign a
# message and verify it on-chain (read-only `cast call`). Everything happens in
# a temporary directory, deleted afterwards, so no key file of the repository
# (e.g. ./private_key.pem) is ever overwritten.
test_onchain:
	@set -e; \
	PY="$(abspath $(PYTHON))"; CLI="$(abspath pythonref/sign_cli.py)"; \
	TMP=$$(mktemp -d); trap 'rm -rf "$$TMP"' EXIT; \
	for args in "falcon 0123 0xD088Ede58BD1736477d66d114D842bDE279A41Fa" \
	            "ethfalcon 4567 0x2F27b854B719921f03f30d1e5d0aE8e0aE7f96cA" \
	            "epervier 89ab 0x5ab1d6db02f48bad63cbef5d51c534A76aEB824B"; do \
		set -- $$args; \
		echo "== $$1"; \
		mkdir "$$TMP/$$1"; cd "$$TMP/$$1"; \
		"$$PY" "$$CLI" genkeys --version="$$1"; \
		"$$PY" "$$CLI" sign --privkey=private_key.pem --data="$$2"; \
		"$$PY" "$$CLI" verifyonchain --pubkey=public_key.pem --data="$$2" --signature=sig --contractaddress="$$3" --rpc='$(RPC_ONCHAIN)'; \
	done

# BENCH

bench:
	forge test -j$(CORES) test/Benchmarks.t.sol -vv | grep -A1 "Logs" | grep -v "Logs" | grep -v "\-\-"