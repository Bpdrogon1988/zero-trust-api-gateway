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

