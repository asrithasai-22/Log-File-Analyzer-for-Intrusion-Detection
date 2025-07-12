from flask import Flask, render_template, request, send_file
from io import BytesIO
import pandas as pd
import os
from log_analyzer import LogAnalyzer

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        analyzer = LogAnalyzer()
        temp_files = []
        
        try:
            # Process uploaded files
            apache_path = None
            ssh_path = None
            
            if 'apache_file' in request.files:
                apache_file = request.files['apache_file']
                if apache_file.filename != '':
                    apache_path = 'temp_apache.log'
                    apache_file.save(apache_path)
                    temp_files.append(apache_path)
            
            if 'ssh_file' in request.files:
                ssh_file = request.files['ssh_file']
                if ssh_file.filename != '':
                    ssh_path = 'temp_auth.log'
                    ssh_file.save(ssh_path)
                    temp_files.append(ssh_path)
            
            if not temp_files:
                return render_template('index.html', error="No valid log files uploaded")

            # Analyze logs
            if analyzer.analyze(apache_log=apache_path, ssh_log=ssh_path):
                # Create in-memory CSV
                csv_data = BytesIO()
                pd.DataFrame(analyzer.suspicious_activities).to_csv(csv_data, index=False)
                csv_data.seek(0)
                
                return send_file(
                    csv_data,
                    mimetype='text/csv',
                    as_attachment=True,
                    download_name='security_report.csv'
                )
            
            return render_template('index.html', error="Analysis failed - check log formats")
            
        except Exception as e:
            return render_template('index.html', error=f"Error during analysis: {str(e)}")
            
        finally:
            # Clean up temp files
            for file in temp_files:
                if os.path.exists(file):
                    os.remove(file)
    
    return render_template('index.html')

@app.route('/test_csv')
def test_csv():
    """Test route to verify CSV download functionality"""
    test_data = [{'ip': '192.168.1.1', 'threat': 'brute_force', 'timestamp': '2023-07-15 14:30:22'}, 
                {'ip': '192.168.1.2', 'threat': 'scanning', 'timestamp': '2023-07-15 14:31:45'}]
    
    try:
        csv_data = BytesIO()
        pd.DataFrame(test_data).to_csv(csv_data, index=False)
        csv_data.seek(0)
        
        return send_file(
            csv_data,
            mimetype='text/csv',
            as_attachment=True,
            download_name='test_report.csv'
        )
    except Exception as e:
        return f"Error generating test CSV: {str(e)}", 500

if __name__ == '__main__':
    os.makedirs('uploads', exist_ok=True)
    app.run(debug=True, port=5000)
