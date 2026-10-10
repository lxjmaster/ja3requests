PYTHON := $(shell command -v python3)
CLEAN_PATHS := $(PWD)/build $(PWD)/*.egg-info
RELEASE_VERSION ?=
RELEASE_FILES := dist/ja3requests-$(RELEASE_VERSION)-py3-none-any.whl dist/ja3requests-$(RELEASE_VERSION).tar.gz

.PHONY: clean
clean:
	@-rm -rf $(CLEAN_PATHS)

.PHONY: clean-dist
clean-dist:
	@-rm -rf $(PWD)/dist

fmt:
	@command -v black || $(PYTHON) -m pip install -r requirements.txt
	$(shell black ja3requests)

lint:
	@command -v pylint || $(PYTHON) -m pip install -r requirements.txt
	@pylint ja3requests

.PHONY: dist
dist:
	@if [ -f 'setup.py' ]; then $(PYTHON) setup.py sdist;fi

.PHONY: build
build: dist
	@if [ -f 'setup.py' ]; then $(PYTHON) setup.py bdist_wheel;fi

upload:
	@test -n "$(RELEASE_VERSION)" || { echo "RELEASE_VERSION is required (for example: make upload RELEASE_VERSION=2.3.0)" >&2; exit 2; }
	@test -f "dist/ja3requests-$(RELEASE_VERSION)-py3-none-any.whl" || { echo "Wheel not found for RELEASE_VERSION=$(RELEASE_VERSION)" >&2; exit 2; }
	@test -f "dist/ja3requests-$(RELEASE_VERSION).tar.gz" || { echo "sdist not found for RELEASE_VERSION=$(RELEASE_VERSION)" >&2; exit 2; }
	twine upload $(RELEASE_FILES)
