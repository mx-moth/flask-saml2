.PHONY: release clean build

version:
	bumpversion minor
	git push
	git push --tags

release:
	${MAKE} clean
	${MAKE} build
	twine upload --username mobify --password ${PYPI_PASSWORD} dist/*

build:
	python setup.py bdist_wheel
	python setup.py sdist

clean:
	rm -rf ${PWD}/{build,dist}/
