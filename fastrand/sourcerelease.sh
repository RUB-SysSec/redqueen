# change version in https://github.com/lemire/fastrand/blob/master/setup.py first
# install twine with pip install twine
rm -rf dist && python setup.py sdist  && twine upload dist/*.tar.gz
# tag the release with the version (e.g., git tag -a v1.2 -m "version 1.2" && git push --tags)
# CI should do the rest
