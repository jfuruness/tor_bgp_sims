[![Python 3.10](https://img.shields.io/badge/python-3.10-blue.svg)](https://www.python.org/downloads/release/python-3100/)
[![Python 3.11](https://img.shields.io/badge/python-3.11-blue.svg)](https://www.python.org/downloads/release/python-3110/)
![Tests](https://github.com/jfuruness/tor_bgp_sims/actions/workflows/tests.yml/badge.svg)

# tor\_bgp\_sims

* [Description](#package-description)
* [Usage](#usage)
* [Installation](#installation)
* [Testing](#testing)
* [Development/Contributing](#developmentcontributing)
* [Licence](#license)

## Package Description

Runs TOR BGP Simulations for our publication

## Usage
* [tor\_bgp\_sims](#tor\_bgp\_sims)

From the command line, after installing and activating a pypy environment:

```
pypy3 -O -m tor_bgp_sims
```

## Installation
* [tor\_bgp\_sims](#tor\_bgp\_sims)

Install python and pip if you have not already.

NOTE: if you can, run this with pypy3 instead, which is >10x faster

Then run:

```bash
# Needed for graphviz and Pillow
pip3 install pip --upgrade
pip3 install wheel
```

For production:

```bash
pip3 install tor_bgp_sims
```

This will install the package and all of it's python dependencies.

If you want to install the project for development:
```bash
git clone https://github.com/jfuruness/tor_bgp_sims.git
cd tor_bgp_sims
pip3 install -e .[test]
pre-commit install
```

To test the development package: [Testing](#testing)


## Testing
* [tor\_bgp\_sims](#tor\_bgp\_sims)

To test the package after installation:

```
cd tor_bgp_sims
pytest tor_bgp_sims
ruff tor_bgp_sims
black tor_bgp_sims
mypy tor_bgp_sims
```

If you want to run it across multiple environments, and have python 3.10 and 3.11 installed:

```
cd tor_bgp_sims
tox
```


## Development/Contributing
* [tor\_bgp\_sims](#tor\_bgp\_sims)

1. Fork it!
2. Create your feature branch: `git checkout -b my-new-feature`
3. Test it
5. Run tox
6. Commit your changes: `git commit -am 'Add some feature'`
7. Push to the branch: `git push origin my-new-feature`
8. Ensure github actions are passing tests
9. Email me at jfuruness@gmail.com if it's been a while and I haven't seen it

## License
* [tor\_bgp\_sims](#tor\_bgp\_sims)

BSD License (see license file)
