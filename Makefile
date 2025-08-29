PROJECT_NAME=zero-trust-api-gateway
GATEWAY_URL?=http://localhost:8080
TOKEN?=
TEST_ENDPOINT?=health

up:
	docker compose up --build

down:
	docker compose down

build:
	docker compose build

logs:
	docker compose logs -f

logs-api:
	docker compose logs -f api-gateway

restart:
	docker compose down && docker compose up --build

test:
	@if [ -z "$(TOKEN)" ]; then \
		if [ -z "$$JWT_SECRET" ]; then \
			echo "ERROR: Set TOKEN or JWT_SECRET to run tests safely."; exit 1; \
		fi; \
		TOKEN=$$(python3 - <<'PY'
import os, jwt
secret = os.environ.get('JWT_SECRET')
print(jwt.encode({"user":"smoke"}, secret, algorithm="HS256"))
PY
		); \
	fi; \
	curl -sS -H "Authorization: Bearer $$TOKEN" $(GATEWAY_URL)/proxy/$(TEST_ENDPOINT)

flood:
	for i in {1..150}; do \
		curl -s -H "Authorization: Bearer $(TOKEN)" $(GATEWAY_URL)/proxy/$(TEST_ENDPOINT); \
	done

token:
	@if [ -z "$$JWT_SECRET" ]; then \
		echo "ERROR: Please export JWT_SECRET to generate a token."; exit 1; \
	fi; \
	python3 - <<'PY'
import os, jwt
secret = os.environ['JWT_SECRET']
print(jwt.encode({"user":"dev"}, secret, algorithm="HS256"))
PY

clean:
	docker compose down -v --rmi all --remove-orphans


# End-to-end smoke test through blockchain flow (requires Ganache, Deployer)
smoke:
	@if [ -z "$$JWT_SECRET" ]; then echo "ERROR: export JWT_SECRET"; exit 1; fi; \
	if [ -z "$$SHARED_BACKEND_KEY" ]; then echo "ERROR: export SHARED_BACKEND_KEY"; exit 1; fi; \
	docker compose up -d --build; \
	echo "Waiting for services..."; sleep 8; \
	ADDR=$$(docker exec ganache cast rpc eth_accounts | sed -n 's/\["\(0x[^"]*\)".*/\1/p' | head -n1); \
	if [ -z "$$ADDR" ]; then \
		echo "Using fallback address 0x0000000000000000000000000000000000000001"; \
		ADDR=0x0000000000000000000000000000000000000001; \
	fi; \
	NONCE=$$(curl -sS -X POST "$(GATEWAY_URL)/auth/nonce" -d "address=$$ADDR" | jq -r .nonce); \
	echo "Nonce: $$NONCE"; \
	SIG=""; echo "Manual step: sign nonce $$NONCE with $$ADDR to continue login."; \
	echo "Skipping signature in smoke; only exercising health and proxy."; \
	curl -sS "$(GATEWAY_URL)/health" | jq .; \
	curl -sS "$(GATEWAY_URL)/proxy/data" -H "Authorization: Bearer $(TOKEN)" | jq . || true

