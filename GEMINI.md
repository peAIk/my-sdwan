# Project Overview

This directory contains a collection of Python scripts designed to interact with a Cisco SD-WAN vManage API. The scripts are used to fetch information about network devices, configuration groups, and generate reports.

The main technologies used are:
*   **Python 3**
*   **requests**: for making HTTP requests to the vManage API.
*   **PyYAML**: for handling YAML data.
*   **csv**: for generating CSV reports.

# Building and Running

These scripts are designed to be run directly from the command line. There is no build process.

**Dependencies:**

The scripts require the following Python libraries:
*   `requests`
*   `PyYAML`

You can install them using pip:
```bash
pip install requests pyyaml
```

**Running the scripts:**

Each script can be run as a standalone executable. For example:

```bash
python EdgesReport.py
```

**Credentials:**

The scripts use hardcoded credentials to authenticate with the vManage API. These may need to be updated before running.

**vManage hosts:**
*   `vman.cz.net.sys`
*   `vman-atm.cz.net.sys`

# Development Conventions

*   The scripts share a common `Authentication` class for connecting to the vManage API.
*   Error handling is done through `try...except` blocks, with error messages printed to the console.
*   The scripts are intended to be run from the command line and provide informative output to the user.
*   Some scripts generate CSV reports as output.
