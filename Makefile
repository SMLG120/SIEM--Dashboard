.PHONY: backend-test frontend-install frontend-dev compose-up compose-down

backend-test:
	mvn clean verify

frontend-install:
	cd frontend/siem-dashboard && npm install

frontend-dev:
	cd frontend/siem-dashboard && npm run dev

compose-up:
	docker compose up --build

compose-down:
	docker compose down

