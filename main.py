from log_analyzer import LogAnalyzer
import os

def main():
    print("Log File Analyzer for Intrusion Detection")
    print("----------------------------------------")
    
    # Default log files
    apache_log = "sample_apache.log"
    ssh_log = "sample_auth.log"
    
    # Verify files exist
    if not os.path.exists(apache_log):
        print(f"Warning: Apache log file not found at {apache_log}")
        apache_log = None
        
    if not os.path.exists(ssh_log):
        print(f"Warning: SSH log file not found at {ssh_log}")
        ssh_log = None
    
    if not apache_log and not ssh_log:
        print("Error: No log files available for analysis")
        return
    
    # Run analysis
    analyzer = LogAnalyzer()
    if analyzer.analyze(apache_log=apache_log, ssh_log=ssh_log):
        print("\nAnalysis completed successfully!")
        print("Generated files:")
        print("- incident_report.csv")
        print("- incident_report.html")
        print("- requests_over_time.png")
        print("- top_ips.png")

if __name__ == "__main__":
    main()
