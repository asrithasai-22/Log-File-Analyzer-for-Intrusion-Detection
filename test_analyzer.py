from log_analyzer import LogAnalyzer
import unittest
import os
import pandas as pd
from datetime import datetime
import pytz

class TestLogAnalyzer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.analyzer = LogAnalyzer()
        
        # Create comprehensive test logs
        with open("test_apache.log", "w", encoding='utf-8') as f:
            f.write("""192.168.1.1 - - [12/Jul/2023:10:30:45 +0000] "GET / HTTP/1.1" 200 1234
192.168.1.2 - - [12/Jul/2023:10:30:46 +0000] "GET /admin.php HTTP/1.1" 403 321
192.168.1.1 - - [12/Jul/2023:10:30:47 +0000] "POST /login.php HTTP/1.1" 200 543
invalid line that should be skipped
192.168.1.3 - - [12/Jul/2023:10:30:48 +0000] "GET /wp-admin HTTP/1.1" 404 123
""")

        with open("test_auth.log", "w", encoding='utf-8') as f:
            f.write("""Jul 12 10:31:22 server sshd[1234]: Failed password for root from 192.168.1.2 port 5678 ssh2
Jul 12 10:31:23 server sshd[1235]: Accepted password for admin from 192.168.1.3 port 4321 ssh2
malformed entry that should be ignored
Jul 12 10:31:24 server sshd[1236]: Failed password for root from 192.168.1.2 port 5678 ssh2
""")

    def test_apache_parser_valid_entries(self):
        """Test parsing of valid Apache log entries"""
        df = self.analyzer.parse_apache_log("test_apache.log")
        self.assertIsInstance(df, pd.DataFrame)
        self.assertEqual(len(df), 4)  # Should skip 1 invalid line
        self.assertEqual(df.iloc[0]['ip'], '192.168.1.1')
        self.assertEqual(df.iloc[1]['status'], 403)
        self.assertTrue(pd.api.types.is_datetime64_any_dtype(df['timestamp']))
        self.assertEqual(df.iloc[0]['timestamp'].tz, pytz.UTC)

    def test_apache_parser_invalid_file(self):
        """Test handling of non-existent Apache log"""
        df = self.analyzer.parse_apache_log("nonexistent.log")
        self.assertTrue(df.empty)

    def test_ssh_parser_valid_entries(self):
        """Test parsing of valid SSH log entries"""
        df = self.analyzer.parse_ssh_log("test_auth.log")
        self.assertIsInstance(df, pd.DataFrame)
        self.assertEqual(len(df), 3)  # Should skip 1 invalid line
        self.assertEqual(df.iloc[0]['ip'], '192.168.1.2')
        self.assertEqual(df.iloc[1]['status'], 'accepted')
        self.assertTrue(pd.api.types.is_datetime64_any_dtype(df['timestamp']))
        self.assertEqual(df.iloc[0]['timestamp'].year, datetime.now().year)

    def test_empty_log_handling(self):
        """Test handling of empty log files"""
        with open("empty.log", "w", encoding='utf-8') as f:
            f.write("")
        
        df = self.analyzer.parse_apache_log("empty.log")
        self.assertTrue(df.empty)
        os.remove("empty.log")

    def test_threat_detection_brute_force(self):
        """Test detection of SSH brute force attacks"""
        ssh_data = self.analyzer.parse_ssh_log("test_auth.log")
        self.analyzer.suspicious_activities = []  # Reset
        
        # Should detect 2 failed attempts from 192.168.1.2
        self.analyzer.detect_threats(ssh_data)
        self.assertEqual(len(self.analyzer.suspicious_activities), 1)
        self.assertEqual(self.analyzer.suspicious_activities[0]['type'], 'brute_force')
        self.assertEqual(self.analyzer.suspicious_activities[0]['ip'], '192.168.1.2')
        self.assertEqual(self.analyzer.suspicious_activities[0]['count'], 2)

    def test_threat_detection_scanning(self):
        """Test detection of web scanning"""
        apache_data = self.analyzer.parse_apache_log("test_apache.log")
        self.analyzer.suspicious_activities = []  # Reset
        
        # Modify test data to simulate scanning (5 unique URLs from one IP)
        apache_data.loc[apache_data['ip'] == '192.168.1.1', 'url'] = [f'/page{i}' for i in range(5)]
        
        self.analyzer.detect_threats(apache_data)
        self.assertEqual(len(self.analyzer.suspicious_activities), 1)
        self.assertEqual(self.analyzer.suspicious_activities[0]['type'], 'scanning')
        self.assertEqual(self.analyzer.suspicious_activities[0]['ip'], '192.168.1.1')
        self.assertEqual(self.analyzer.suspicious_activities[0]['count'], 5)

    def test_blacklist_check(self):
        """Test IP blacklist functionality"""
        test_log = "test_blacklist.log"
        with open(test_log, "w", encoding='utf-8') as f:
            f.write("192.168.1.99 - - [12/Jul/2023:10:30:49 +0000] \"GET / HTTP/1.1\" 200 1234\n")
        
        # Add test IP to blacklist
        self.analyzer.ip_blacklist.add('192.168.1.99')
        
        df = self.analyzer.parse_apache_log(test_log)
        self.analyzer.detect_threats(df)
        
        self.assertEqual(len(self.analyzer.suspicious_activities), 1)
        self.assertEqual(self.analyzer.suspicious_activities[0]['type'], 'blacklisted_ip')
        self.assertEqual(self.analyzer.suspicious_activities[0]['ip'], '192.168.1.99')
        
        os.remove(test_log)

    def test_report_generation(self):
        """Test report generation workflow"""
        ssh_data = self.analyzer.parse_ssh_log("test_auth.log")
        self.analyzer.detect_threats(ssh_data)
        
        # Test CSV report
        self.analyzer.generate_reports()
        self.assertTrue(os.path.exists('incident_report.csv'))
        
        # Test HTML report
        self.assertTrue(os.path.exists('incident_report.html'))
        
        # Clean up
        os.remove('incident_report.csv')
        os.remove('incident_report.html')

    @classmethod
    def tearDownClass(cls):
        """Clean up test files"""
        test_files = ["test_apache.log", "test_auth.log"]
        for f in test_files:
            if os.path.exists(f):
                try:
                    os.remove(f)
                except PermissionError:
                    print(f"Warning: Could not remove {f} - file may be locked")

if __name__ == "__main__":
    unittest.main(failfast=True, verbosity=2)
