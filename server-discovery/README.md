Sure, here's a basic README for your codebase:

# DNS Zone Scan

This repository contains a script for scanning DNS zones and performing network scans on the resulting IP addresses.

## Requirements

- Python 3
- dnspython
- GitPython
- python-nmap

## Installation

1. Clone the repository.
2. Install the required packages using pip:

```
pip install -r requirements.txt
```

## Usage

1. Run the script with the zone name and zone file path as arguments:

```
python dns_zone_scan.py <zone_name> <zone_file_path>
```

For example:

```
python dns_zone_scan.py domain.com.au dns_zone.txt
```

2. The script will parse the zone file, extract the A records, and perform a network scan on the resulting IP addresses.
3. The scan results will be saved in a CSV file with the same name as the zone name.

## License

This project is licensed under the MIT License.

## Contributing

Contributions are welcome. Please submit a pull request.

## Authors

- [Adam Boyce](https://github.com/adz80)

## Acknowledgments

- [dnspython](https://github.com/rthalley/dnspython)
- [GitPython](https://github.com/gitpython-developers/GitPython)
- [python-nmap](https://github.com/savon-noir/python-nmap)
