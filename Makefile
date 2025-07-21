PROJECT_NAME=zero-trust-api-gateway
GATEWAY_URL=http://localhost:8080
TOKEN=your_token_here
TEST_ENDPOINT=get

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
	curl -H "Authorization: Bearer $(TOKEN)" $(GATEWAY_URL)/proxy/$(TEST_ENDPOINT)

flood:
	for i in {1..150}; do \
		curl -s -H "Authorization: Bearer $(TOKEN)" $(GATEWAY_URL)/proxy/$(TEST_ENDPOINT); \
	done

token:
	python3 -c 'import jwt; print(jwt.encode({"user": "branden"}, "your_very_secret_key", algorithm="HS256"))'

clean:
	docker compose down -v --rmi all --remove-orphans

