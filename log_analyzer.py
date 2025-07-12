import re
import pandas as pd
import matplotlib.pyplot as plt
import requests
from datetime import datetime
import os
import warnings
from typing import Optional, List, Dict, Union, Any
import pytz

class LogAnalyzer:
    def __init__(self):
        self.suspicious_activities: List[Dict[str, Any]] = []
        self.ip_blacklist: set = self._load_blacklist()
        warnings.filterwarnings('ignore', category=UserWarning)
        
    def _load_blacklist(self) -> set:
        """Load IP blacklist from public source"""
        try:
            response = requests.get(
                'https://lists.blocklist.de/lists/all.txt',
                timeout=5,
                headers={'User-Agent': 'LogAnalyzer/1.0'}
            )
            return set(response.text.strip().splitlines()) if response.status_code == 200 else set()
        except Exception as e:
            print(f"Warning: Could not load blacklist - {e}")
            return set()

    def _parse_apache_timestamp(self, timestamp_str: str) -> Optional[datetime]:
        """Parse Apache timestamp with timezone handling"""
        try:
            dt = datetime.strptime(timestamp_str, '%d/%b/%Y:%H:%M:%S %z')
            return dt.astimezone(pytz.UTC)
        except ValueError as e:
            print(f"Warning: Could not parse Apache timestamp - {e}")
            return None

    def _parse_ssh_timestamp(self, timestamp_str: str) -> Optional[datetime]:
        """Parse SSH timestamp with automatic year handling"""
        try:
            dt = datetime.strptime(timestamp_str, '%b %d %H:%M:%S')
            return dt.replace(year=datetime.now().year).astimezone()
        except ValueError as e:
            print(f"Warning: Could not parse SSH timestamp - {e}")
            return None

    def parse_apache_log(self, log_file: str) -> pd.DataFrame:
        """Parse Apache access logs"""
        if not os.path.exists(log_file):
            print(f"Error: File not found - {log_file}")
            return pd.DataFrame()

        pattern = r'^(\S+) \S+ \S+ \[([^]]+)\] "(\S+) (\S+).*?" (\d+) (\d+)'
        entries = []
        
        with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                match = re.match(pattern, line.strip())
                if match:
                    ip, timestamp, method, url, status, size = match.groups()
                    dt = self._parse_apache_timestamp(timestamp)
                    if dt:
                        entries.append({
                            'ip': ip,
                            'timestamp': dt,
                            'method': method,
                            'url': url,
                            'status': int(status),
                            'size': int(size),
                            'type': 'apache'
                        })

        df = pd.DataFrame(entries) if entries else pd.DataFrame()
        if not df.empty:
            df['timestamp'] = pd.to_datetime(df['timestamp'], utc=True)
        return df

    def parse_ssh_log(self, log_file: str) -> pd.DataFrame:
        """Parse SSH auth logs"""
        if not os.path.exists(log_file):
            print(f"Error: File not found - {log_file}")
            return pd.DataFrame()

        patterns = {
            'failed': r'Failed password for (\S+) from (\S+) port (\d+)',
            'accepted': r'Accepted password for (\S+) from (\S+) port (\d+)'
        }
        entries = []
        
        with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                for status, pattern in patterns.items():
                    match = re.search(pattern, line.strip())
                    if match:
                        user, ip, port = match.groups()
                        timestamp_str = ' '.join(line.split()[:3])
                        dt = self._parse_ssh_timestamp(timestamp_str)
                        if dt:
                            entries.append({
                                'ip': ip,
                                'timestamp': dt,
                                'user': user,
                                'port': port,
                                'status': status,
                                'type': 'ssh'
                            })
                        break

        df = pd.DataFrame(entries) if entries else pd.DataFrame()
        if not df.empty:
            df['timestamp'] = pd.to_datetime(df['timestamp'], utc=True)
        return df

    def detect_threats(self, log_data: pd.DataFrame):
        """Detect security threats"""
        if log_data.empty or 'timestamp' not in log_data.columns:
            return

        log_data['timestamp'] = pd.to_datetime(log_data['timestamp'], utc=True)
        log_data = log_data.dropna(subset=['timestamp'])
        self.suspicious_activities = []

        # Brute force detection
        if 'ssh' in log_data['type'].values:
            ssh_failures = log_data[(log_data['type'] == 'ssh') & (log_data['status'] == 'failed')]
            for ip, count in ssh_failures['ip'].value_counts().items():
                if count >= 5:
                    self.suspicious_activities.append({
                        'type': 'brute_force',
                        'ip': ip,
                        'count': count,
                        'timestamp': datetime.now(pytz.UTC),
                        'message': f"SSH brute force attempt ({count} failures)"
                    })

        # Scanning detection
        if 'apache' in log_data['type'].values:
            url_access = log_data[log_data['type'] == 'apache']
            for ip, count in url_access.groupby('ip')['url'].nunique().items():
                if count >= 10:
                    self.suspicious_activities.append({
                        'type': 'scanning',
                        'ip': ip,
                        'count': count,
                        'timestamp': datetime.now(pytz.UTC),
                        'message': f"Web scanning detected ({count} unique URLs)"
                    })

        # DoS detection
        if 'apache' in log_data['type'].values:
            apache_data = log_data[log_data['type'] == 'apache'].copy()
            apache_data['minute'] = apache_data['timestamp'].dt.floor('min')
            for (ip, minute), count in apache_data.groupby(['ip', 'minute']).size().items():
                if count >= 100:
                    self.suspicious_activities.append({
                        'type': 'dos',
                        'ip': ip,
                        'count': count,
                        'timestamp': minute,
                        'message': f"Potential DoS attack ({count} requests/min)"
                    })

        # Blacklist check
        malicious_ips = set(log_data['ip'].unique()) & self.ip_blacklist
        for ip in malicious_ips:
            self.suspicious_activities.append({
                'type': 'blacklisted_ip',
                'ip': ip,
                'timestamp': datetime.now(pytz.UTC),
                'message': "IP found in public blacklist"
            })

    def generate_visualizations(self, log_data: pd.DataFrame):
        """Generate security visualizations"""
        if log_data.empty:
            return

        try:
            plt.style.use('ggplot')
            
            # Requests over time
            plt.figure(figsize=(12, 6))
            log_data.set_index('timestamp')['ip'].resample('H').count().plot()
            plt.title('Requests Over Time (UTC)')
            plt.ylabel('Request Count')
            plt.tight_layout()
            plt.savefig('requests_over_time.png')
            plt.close()
            
            # Top IPs
            plt.figure(figsize=(12, 6))
            log_data['ip'].value_counts().head(10).plot(kind='bar')
            plt.title('Top 10 IPs by Request Count')
            plt.tight_layout()
            plt.savefig('top_ips.png')
            plt.close()
        except Exception as e:
            print(f"Error generating visualizations: {e}")

    def generate_reports(self):
        """Generate security reports"""
        if not self.suspicious_activities:
            return

        try:
            df = pd.DataFrame(self.suspicious_activities)
            df.to_csv('incident_report.csv', index=False)
            
            html = df.to_html(classes='table table-striped', index=False)
            with open('incident_report.html', 'w', encoding='utf-8') as f:
                f.write(f"""<html>
<head><title>Security Report</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="container mt-4">
    <h1>Security Incident Report</h1>
    <p>Generated at {datetime.now(pytz.UTC).strftime('%Y-%m-%d %H:%M:%S %Z')}</p>
    {html}
</body></html>""")
        except Exception as e:
            print(f"Error generating reports: {e}")

    def analyze(self, apache_log: Optional[str] = None, ssh_log: Optional[str] = None) -> bool:
        """Main analysis workflow"""
        logs = []
        
        if apache_log:
            apache_data = self.parse_apache_log(apache_log)
            if not apache_data.empty:
                logs.append(apache_data)

        if ssh_log:
            ssh_data = self.parse_ssh_log(ssh_log)
            if not ssh_data.empty:
                logs.append(ssh_data)

        if not logs:
            return False

        try:
            combined_logs = pd.concat(logs)
            combined_logs['timestamp'] = pd.to_datetime(combined_logs['timestamp'], utc=True)
            combined_logs = combined_logs.dropna(subset=['timestamp'])
            
            self.detect_threats(combined_logs)
            self.generate_visualizations(combined_logs)
            self.generate_reports()
            return True
        except Exception as e:
            print(f"Error during analysis: {e}")
            return False
