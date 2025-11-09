from flask import Flask, render_template, request, flash, redirect, url_for, Response, jsonify
import os
import subprocess
import hashlib
import json
import requests
from werkzeug.utils import secure_filename
import logging
from datetime import datetime
import zipfile
import re
import tempfile
import shutil

import threading
from uuid import uuid4
import time

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max file size
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ALLOWED_EXTENSIONS'] = {'apk'}

# Create upload directory if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

class AdvancedAPKAnalyzer:
    def __init__(self):
        # Expanded list of suspicious permissions
        self.suspicious_permissions = [
            'android.permission.SEND_SMS',
            'android.permission.RECEIVE_SMS',
            'android.permission.READ_SMS',
            'android.permission.WRITE_SMS',
            'android.permission.READ_CONTACTS',
            'android.permission.WRITE_CONTACTS',
            'android.permission.READ_PHONE_STATE',
            'android.permission.CALL_PHONE',
            'android.permission.PROCESS_OUTGOING_CALLS',
            'android.permission.ACCESS_FINE_LOCATION',
            'android.permission.ACCESS_COARSE_LOCATION',
            'android.permission.RECORD_AUDIO',
            'android.permission.CAMERA',
            'android.permission.READ_EXTERNAL_STORAGE',
            'android.permission.WRITE_EXTERNAL_STORAGE',
            'android.permission.SYSTEM_ALERT_WINDOW',
            'android.permission.BIND_ACCESSIBILITY_SERVICE',
            'android.permission.PACKAGE_USAGE_STATS',
            'android.permission.REQUEST_INSTALL_PACKAGES',
            'android.permission.INTERNET',
            'android.permission.ACCESS_WIFI_STATE',
            'android.permission.CHANGE_WIFI_STATE',
            'android.permission.ACCESS_NETWORK_STATE',
            'android.permission.RECEIVE_BOOT_COMPLETED',
            'android.permission.DISABLE_KEYGUARD',
            'android.permission.WAKE_LOCK'
        ]
        
        # High-risk permissions that immediately raise flags
        self.high_risk_permissions = [
            'android.permission.SYSTEM_ALERT_WINDOW',
            'android.permission.BIND_ACCESSIBILITY_SERVICE',
            'android.permission.REQUEST_INSTALL_PACKAGES'
        ]
        
        # Known malicious patterns in code
        self.malicious_patterns = [
            'runtime.exec', 'getRuntime', 'su', 'root', 'bin/bash',
            'chmod', 'mount', 'system/bin', 'data/local', 'payload',
            'exploit', 'inject', 'hook', 'bypass', 'obfuscate',
            'crypt', 'encrypt', 'decrypt', 'keylogger', 'stealer',
            'phish', 'banking', 'login', 'password', 'credit.card',
            'facebook.com', 'google.com', 'paypal.com', 'amazon.com'
        ]
        
        # Known malicious package names and patterns
        self.malicious_package_patterns = [
            'com.security.update', 'com.android.verification',
            'com.google.update', 'com.facebook.security',
            'com.whatsapp.update', 'com.instagram.verification',
            'com.banking.security', 'com.payment.verification'
        ]
    
    def allowed_file(self, filename):
        return '.' in filename and \
               filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']
    
    def calculate_hash(self, filepath):
        """Calculate MD5, SHA1, and SHA256 hashes of the file"""
        hashes = {}
        hash_functions = {
            'md5': hashlib.md5(),
            'sha1': hashlib.sha1(),
            'sha256': hashlib.sha256()
        }
        
        with open(filepath, 'rb') as f:
            while chunk := f.read(4096):
                for hash_func in hash_functions.values():
                    hash_func.update(chunk)
        
        for name, hash_func in hash_functions.items():
            hashes[name] = hash_func.hexdigest()
        
        return hashes
    
    def get_file_type(self, filepath):
        """Determine file type by checking signature"""
        with open(filepath, 'rb') as f:
            header = f.read(4)
            
        if header.startswith(b'PK'):
            return "Android Package (APK)"
        else:
            return "Unknown file type"
    
    def extract_apk_info(self, filepath):
        """Extract APK information using aapt"""
        try:
            # Try to get package info using aapt
            result = subprocess.run([
                'aapt', 'dump', 'badging', filepath
            ], capture_output=True, text=True, timeout=30)
            
            info = {
                'package_name': 'Unknown',
                'version': 'Unknown',
                'sdk_versions': 'Unknown',
                'permissions': [],
                'activities': [],
                'services': [],
                'receivers': []
            }
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if line.startswith('package:'):
                        parts = line.split()
                        for part in parts:
                            if part.startswith('name='):
                                info['package_name'] = part.split('=')[1].strip("'")
                            elif part.startswith('versionName='):
                                info['version'] = part.split('=')[1].strip("'")
                            elif part.startswith('versionCode='):
                                info['version_code'] = part.split('=')[1].strip("'")
                    elif line.startswith('sdkVersion:'):
                        info['sdk_versions'] = line.split(':')[1].strip()
                    elif line.startswith('uses-permission:'):
                        perm = line.split(':')[1].split('=')[1].strip("'")
                        info['permissions'].append(perm)
                    elif line.startswith('launchable-activity:'):
                        activity = line.split(':')[1].split('=')[1].strip("'")
                        info['activities'].append(activity)
                    elif line.startswith('service:'):
                        service = line.split(':')[1].split('=')[1].strip("'")
                        info['services'].append(service)
                    elif line.startswith('receiver:'):
                        receiver = line.split(':')[1].split('=')[1].strip("'")
                        info['receivers'].append(receiver)
            
            return info
        except Exception as e:
            logger.error(f"Error extracting APK info: {e}")
            return self.fallback_extract_info(filepath)
    
    def fallback_extract_info(self, filepath):
        """Fallback method to extract info from APK without aapt"""
        info = {
            'package_name': 'Unknown',
            'version': 'Unknown',
            'sdk_versions': 'Unknown',
            'permissions': [],
            'activities': [],
            'services': [],
            'receivers': []
        }
        
        try:
            # Try to extract AndroidManifest.xml from APK
            with zipfile.ZipFile(filepath, 'r') as apk:
                if 'AndroidManifest.xml' in apk.namelist():
                    manifest = apk.read('AndroidManifest.xml')
                    
                    # Try to find package name in binary XML
                    package_match = re.search(b'package="([^"]+)"', manifest)
                    if package_match:
                        info['package_name'] = package_match.group(1).decode('utf-8', errors='ignore')
                    
                    # Look for permission patterns
                    permission_matches = re.findall(b'android.permission.([A-Z_]+)', manifest)
                    for perm in permission_matches:
                        info['permissions'].append(f"android.permission.{perm.decode('utf-8', errors='ignore')}")
        except Exception as e:
            logger.error(f"Error in fallback extraction: {e}")
        
        return info
    
    def check_package_name(self, package_name):
        """Check if package name matches known malicious patterns"""
        for pattern in self.malicious_package_patterns:
            if pattern in package_name:
                return True
        return False
    
    def check_for_malicious_code(self, filepath):
        """Search for malicious code patterns in APK files"""
        malicious_findings = []
        
        try:
            with zipfile.ZipFile(filepath, 'r') as apk:
                for file_name in apk.namelist():
                    # Check for suspicious files
                    if any(x in file_name for x in ['.so', '.dex', '.xml']):
                        try:
                            content = apk.read(file_name)
                            # Convert to string for pattern matching
                            try:
                                content_str = content.decode('utf-8', errors='ignore')
                            except:
                                content_str = str(content)
                            
                            # Check for malicious patterns
                            for pattern in self.malicious_patterns:
                                if pattern in content_str:
                                    malicious_findings.append(f"Pattern '{pattern}' found in {file_name}")
                        except:
                            continue
        except Exception as e:
            logger.error(f"Error checking for malicious code: {e}")
        
        return malicious_findings
    
    def check_virustotal(self, file_hash):
        """Check file hash against VirusTotal (placeholder)"""
        return {
            'detected': False,
            'scan_results': {},
            'message': 'VirusTotal integration requires API key'
        }
    
    def analyze_apk(self, filepath, progress_cb=None):
        """Comprehensive APK analysis with enhanced detection"""
        results = {
            'basic_info': {},
            'hashes': {},
            'suspicious_permissions': [],
            'high_risk_permissions': [],
            'malicious_patterns_found': [],
            'risk_score': 0,
            'threat_level': 'low',
            'warnings': [],
            'recommendations': []
        }
        
        # Calculate file hashes
        if progress_cb:
            progress_cb('Calculating file hashes')
        results['hashes'] = self.calculate_hash(filepath)
        
        # Get file type
        if progress_cb:
            progress_cb('Determining file type')
        results['file_type'] = self.get_file_type(filepath)
        
        # Extract APK information
        if progress_cb:
            progress_cb('Extracting APK information')
        apk_info = self.extract_apk_info(filepath)
        if apk_info:
            results['basic_info'] = apk_info
            
            # Check for suspicious permissions
            for perm in apk_info['permissions']:
                if perm in self.suspicious_permissions:
                    results['suspicious_permissions'].append(perm)
                    results['risk_score'] += 3
                
                if perm in self.high_risk_permissions:
                    results['high_risk_permissions'].append(perm)
                    results['risk_score'] += 10
            
            # Check for excessive permissions
            if len(apk_info['permissions']) > 15:
                results['warnings'].append('Excessive number of permissions requested')
                results['risk_score'] += 10
            
            # Check package name for suspicious patterns
            if self.check_package_name(apk_info['package_name']):
                results['warnings'].append(f'Suspicious package name: {apk_info["package_name"]}')
                results['risk_score'] += 15
        
        # Check file size (suspicious if too small or too large)
        file_size = os.path.getsize(filepath)
        results['file_size'] = file_size
        if file_size < 500000:  # Less than 500KB
            results['warnings'].append('APK file size is unusually small (potential trojan)')
            results['risk_score'] += 10
        elif file_size > 100000000:  # More than 100MB
            results['warnings'].append('APK file size is unusually large (potential bloatware)')
            results['risk_score'] += 5
        
        # Check for malicious code patterns
        if progress_cb:
            progress_cb('Scanning for malicious code patterns')
        malicious_code = self.check_for_malicious_code(filepath)
        if malicious_code:
            results['malicious_patterns_found'] = malicious_code
            results['risk_score'] += len(malicious_code) * 5
            results['warnings'].append(f'Found {len(malicious_code)} malicious code patterns')
        
        # Check against VirusTotal (placeholder)
        if progress_cb:
            progress_cb('Checking VirusTotal (placeholder)')
        vt_result = self.check_virustotal(results['hashes']['sha256'])
        results['virustotal'] = vt_result
        
        # Determine threat level
        if progress_cb:
            progress_cb('Computing threat level')
        if results['risk_score'] >= 30:
            results['threat_level'] = 'high'
        elif results['risk_score'] >= 15:
            results['threat_level'] = 'medium'
        
        # Generate recommendations
        if progress_cb:
            progress_cb('Generating recommendations')
        if results['threat_level'] == 'high':
            results['recommendations'].append('🚨 DO NOT INSTALL - High risk of malware/phishing detected')
        elif results['threat_level'] == 'medium':
            results['recommendations'].append('⚠️ Exercise extreme caution - Multiple suspicious indicators found')
        else:
            results['recommendations'].append('APK appears relatively safe, but always download from trusted sources')
        
        if progress_cb:
            progress_cb('Analysis complete')
        return results

# Initialize analyzer
analyzer = AdvancedAPKAnalyzer()

# In-memory job store for live analysis
jobs = {}  # job_id -> {'status': 'running'|'complete', 'logs': [str], 'results': dict or None}

def run_analysis(job_id, filepath, filename):
    def progress(msg):
        jobs[job_id]['logs'].append(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")

    try:
        progress(f"Received file: {filename}")
        res = analyzer.analyze_apk(filepath, progress_cb=progress)
        jobs[job_id]['results'] = res
        jobs[job_id]['status'] = 'complete'
        progress("Finalizing and cleaning up")
    except Exception as e:
        jobs[job_id]['logs'].append(f"[{datetime.now().strftime('%H:%M:%S')}] Error: {e}")
        jobs[job_id]['status'] = 'complete'
    finally:
        try:
            if os.path.exists(filepath):
                os.remove(filepath)
        except:
            pass

@app.route('/stream/<job_id>')
def stream(job_id):
    def event_stream():
        last_index = 0
        while True:
            job = jobs.get(job_id)
            if not job:
                break
            logs = job['logs']
            while last_index < len(logs):
                yield f"data: {logs[last_index]}\n\n"
                last_index += 1
            if job['status'] == 'complete':
                yield "event: complete\ndata: done\n\n"
                break
            time.sleep(0.5)
    return Response(event_stream(), mimetype='text/event-stream')

@app.route('/view_result/<job_id>')
def view_result(job_id):
    job = jobs.get(job_id)
    if not job or job['results'] is None:
        flash('Results not ready yet')
        return redirect(url_for('index'))
    return render_template('results.html', results=job['results'], filename=None)

@app.route('/result/<job_id>')
def get_result(job_id):
    job = jobs.get(job_id)
    if not job or job['results'] is None:
        return jsonify({'ready': False}), 200
    return jsonify({'ready': True, 'results': job['results']}), 200

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze_apk():
    if 'apk_file' not in request.files:
        flash('No file selected')
        return redirect(request.url)
    
    file = request.files['apk_file']
    if file.filename == '':
        flash('No file selected')
        return redirect(request.url)
    
    if file and analyzer.allowed_file(file.filename):
        filename = secure_filename(str(file.filename))
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        # Start background analysis with live streaming
        job_id = str(uuid4())
        jobs[job_id] = {'status': 'running', 'logs': [], 'results': None}
        threading.Thread(target=run_analysis, args=(job_id, filepath, filename), daemon=True).start()
        
        # Render results page in "live" mode
        return render_template('results.html', results=None, filename=filename, job_id=job_id)
        
    else:
        flash('Invalid file type. Please upload an APK file.')
        return redirect(request.url)

if __name__ == '__main__':
    app.run(debug=True, port=5001)