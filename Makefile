PYTHON := $(shell command -v python3)
CLEAN_PATHS := $(PWD)/build $(PWD)/dist $(PWD)/*.egg-info
WHL_PATH := $(wildcard dist/*.whl)

.PHONY: clean
clean:
	@-rm -rf $(CLEAN_PATHS)

fmt:
	@command -v black || $(PYTHON) -m pip install -r requirements.txt
	$(shell black ja3requests)

lint:
	@command -v pylint || $(PYTHON) -m pip install -r requirements.txt
	$(shell pylint ja3requests)

.PHONY: dist
dist:
	@if [ -f 'setup.py' ]; then $(PYTHON) setup.py sdist;fi

.PHONY: build
build: dist
	@if [ -f 'setup.py' ]; then $(PYTHON) setup.py bdist_wheel;fi

upload:
	@if [ -f '$(WHL_PATH)' ];then twine upload $(wildcard dist/*); else echo "File not existed.";fi
