PYTHON := $(shell command -v python3)

fmt:
	command -v black || $(PYTHON) -m pip install -r requirements.txt
	black ja3requests

lint:
	command -v pylint || $(PYTHON) -m pip install -r requirements.txt
	pylint ja3requests

package:
	if [ -f 'setup.py' ]; then $(PYTHON) setup.py sdist;fi

package_whl:
	if [ -f 'setup.py' ]; then $(PYTHON) setup.py bdist_wheel;fi
