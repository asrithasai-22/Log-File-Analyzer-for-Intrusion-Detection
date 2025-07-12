```markdown
# Log File Analyzer for Intrusion Detection

![Python](https://img.shields.io/badge/Python-3.11%2B-blue)
![Flask](https://img.shields.io/badge/Flask-2.3%2B-lightgrey)
![Pandas](https://img.shields.io/badge/Pandas-2.0%2B-orange)

A Python-based tool for analyzing server logs to detect security threats like brute force attacks, port scanning, and DoS attempts. Generates security reports and visualizations.

## Features

- 🕵️‍♂️ Detects brute force attacks, scanning activity, and DoS attempts
- 📊 Generates visualizations of traffic patterns
- 📥 Exports security findings as CSV and HTML reports
- 🌐 Web-based interface for easy log analysis
- ⚙️ Automatic threat detection with configurable thresholds

## Installation

```bash
# Clone repository
git clone https://github.com/yourusername/log-analyzer.git
cd log-analyzer

# Create virtual environment
python -m venv venv

# Activate environment (Windows)
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## Usage

### Web Interface
```bash
python app.py
```
Visit http://localhost:5000

### Command Line
```bash
python run_analyzer.py --apache sample_apache.log --ssh sample_auth.log
```

## Sample Output

| Threat Type       | IP Address     | Count | Message                          |
|-------------------|----------------|-------|----------------------------------|
| brute_force       | 192.168.1.105  | 7     | SSH brute force attempt          |
| scanning          | 192.168.1.201  | 15    | Web scanning detected            |
| blacklisted_ip    | 93.184.216.34  | -     | IP found in public blacklist     |

![Requests Over Time](https://via.placeholder.com/800x400.png?text=Sample+Visualization)

## Repository Structure

```
log-analyzer/
├── app.py                 # Flask web application
├── log_analyzer.py        # Core analysis logic
├── run_analyzer.py        # CLI interface
├── test_analyzer.py       # Unit tests
├── templates/             # HTML templates
├── static/                # CSS assets
├── samples/               # Sample log files
├── requirements.txt       # Dependencies
└── README.md              # Documentation
```

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/improvement`)
3. Commit your changes (`git commit -am 'Add new feature'`)
4. Push to the branch (`git push origin feature/improvement`)
5. Create a new Pull Request

## License

Distributed under the MIT License. See `LICENSE` for more information.
```

This README includes:
- Badges for key technologies
- Clear installation instructions
- Usage examples for both web and CLI
- Sample output table
- Repository structure visualization
- Contribution guidelines
- License information

The markdown is formatted for easy copy-pasting into GitHub. It uses:
- Standard GitHub-flavored markdown
- Emojis for visual interest
- Code blocks for commands
- Table for sample output
- Directory tree visualization
- Badges for key technologies
