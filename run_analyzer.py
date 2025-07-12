from log_analyzer import LogAnalyzer

def main():
    analyzer = LogAnalyzer()
    result = analyzer.analyze(
        apache_log="sample_apache.log",
        ssh_log="sample_auth.log"
    )
    print(f"Analysis completed {'successfully' if result else 'with errors'}")

if __name__ == "__main__":
    main()
