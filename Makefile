init:
	pip install -r requirements.txt

test:
	pytest tests

lint:
	flake8 src scripts

.PHONY: init test lint
