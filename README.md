# PyroTorch - Firewall Audit Tool

**Version 1.0.0**

A Python-based firewall audit tool that analyzes firewall rules from CSV exports and generates comprehensive PDF reports. This tool helps network security teams identify unused rules, overly permissive configurations, and high-usage patterns.

## Features

- **Comprehensive Analysis**
  - Unused rules detection (configurable threshold, default 90 days)
  - Zero-hit rules identification
  - Overly permissive rules detection (any source, destination, or service)
  - High-usage rules analysis (configurable threshold, default 1000 hits)
  - Services, ports, and protocols breakdown

- **Professional PDF Reports**
  - Executive summary with detailed metrics and descriptions
  - Detailed analysis sections for each rule category
  - Services, ports, and protocols analysis
  - Automatically named reports with firewall name and timestamp
  - Landscape orientation for better table visibility

- **Flexible Input**
  - Supports Palo Alto firewall CSV exports
  - Automatic column mapping
  - Handles optional columns gracefully

## Requirements

- Python 3.7+
- pandas
- reportlab

## Installation

1. Clone the repository:
```bash
git clone https://github.com/denismapa/PyroTorch.git
cd PyroTorch
```

2. Create a virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Quick Start

```bash
# Clone the repository
git clone https://github.com/denismapa/PyroTorch.git
cd PyroTorch

# Set up virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run the audit (output will be auto-named with timestamp)
python firewall_audit.py your_firewall_rules.csv output.pdf
```

## Usage

### Basic Usage

```bash
python firewall_audit.py <input_csv> <output_pdf>
```

The output PDF will be automatically named as: `{Firewall_Name}_{YYYY-MM-DD_HHMMSS}.pdf`

### Example

```bash
python firewall_audit.py "/path/to/firewall_rules.csv" output.pdf
```

### Command Line Options

```
positional arguments:
  input_csv             Path to the input CSV file containing firewall rules
  output_pdf            Path for the output PDF report

optional arguments:
  --log-level {DEBUG,INFO,WARNING,ERROR}
                        Set the logging level (default: INFO)
  --unused-days DAYS    Number of days to consider a rule as unused (default: 90)
  --high-usage-threshold COUNT
                        Minimum hit count to consider a rule as high usage (default: 1000)
  --firewall-name NAME  Name of the firewall (default: derived from CSV filename)
```

### Example with Options

```bash
python firewall_audit.py firewall_rules.csv output.pdf \
  --unused-days 60 \
  --high-usage-threshold 5000 \
  --firewall-name "Production-FW-01" \
  --log-level DEBUG
```

## CSV Input Format

The tool expects CSV files exported from Palo Alto firewalls with the following columns:

### Required Columns
- Name (Rule ID)
- Source Address
- Destination Address
- Service (Protocol)
- Action
- Created (Date)

### Optional Columns
- Rule Usage Last Hit
- Rule Usage Hit Count
- Source Zone
- Destination Zone
- Application
- Profile
- Tags

## Report Sections

1. **Executive Summary** - Overview of all metrics with descriptions
2. **Unused Rules Analysis** - Rules not used within the specified threshold
3. **Zero-Hit Rules Analysis** - Rules with zero recorded hits
4. **Overly Permissive Rules Analysis** - Rules with any/all configurations
5. **High Usage Rules Analysis** - Rules exceeding the usage threshold
6. **Services, Ports & Protocols** - Breakdown of all services used

## Output

The tool generates a professional landscape PDF report with:
- Clickable table of contents
- Color-coded sections
- Detailed tables with proper text wrapping
- Automatic filename: `{Firewall_Name}_{YYYY-MM-DD_HHMMSS}.pdf`

## License

This project is licensed under the MIT License.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Version History

### Version 1.0.0 (2025-09-29)
- Initial release
- Comprehensive firewall rule analysis
- PDF report generation with 6 sections
- Support for Palo Alto firewall CSV exports
- Configurable thresholds for unused and high-usage rules
- Executive summary with metric descriptions
- Services, ports, and protocols analysis
- Automatic report naming with timestamp