.PHONY: install format lint test benchmark demo docker clean

install:
	uv sync --frozen --all-extras

format:
	uv run ruff format .
	uv run ruff check --fix .

lint:
	uv lock --check
	uv run ruff check .
	uv run ruff format --check .
	uv run mypy src

test:
	uv run pytest --cov=secure_data_clean_room --cov-report=term-missing --cov-report=xml

benchmark:
	CLEAN_ROOM_DEMO_MODE=1 uv run clean-room benchmark --iterations 10

demo:
	CLEAN_ROOM_DEMO_MODE=1 CLEAN_ROOM_AUTO_INIT=1 uv run clean-room serve --host 127.0.0.1 --port 8080

docker:
	docker compose up --build

clean:
	rm -rf .coverage coverage.xml reports/*.json reports/*.csv reports/*.md var
