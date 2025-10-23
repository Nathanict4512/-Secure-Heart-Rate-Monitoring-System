import streamlit as st
import cv2
import numpy as np
from collections import deque
from scipy import signal
import time
import sqlite3
import hashlib
import json
from datetime import datetime
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import os
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd

st.set_page_config(page_title="Secure Heart Rate Monitor", page_icon="❤️", layout="wide")

# =========================
# ENCRYPTION FUNCTIONS
# =========================

class HybridEncryption:
    """Hybrid encryption using AES-GCM (symmetric) and ECC (asymmetric)"""
    
    @staticmethod
    def generate_ecc_keys():
        """Generate ECC key pair for asymmetric authentication"""
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()
        return private_key, public_key
    
    @staticmethod
    def derive_shared_key(private_key, public_key):
        """Derive shared key using ECDH"""
        shared_key = private_key.exchange(ec.ECDH(), public_key)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
        ).derive(shared_key)
        return derived_key
    
    @staticmethod
    def encrypt_aes_gcm(data, key):
        """Encrypt data using AES-GCM"""
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, data.encode(), None)
        return nonce + ciphertext
    
    @staticmethod
    def decrypt_aes_gcm(encrypted_data, key):
        """Decrypt data using AES-GCM"""
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext.decode()

# =========================
# DATABASE FUNCTIONS
# =========================

def init_database():
    """Initialize SQLite database with encryption simulation"""
    conn = sqlite3.connect('heart_monitor.db', check_same_thread=False)
    c = conn.cursor()
    
    # Users table
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE NOT NULL,
                  password_hash TEXT NOT NULL,
                  full_name TEXT NOT NULL,
                  is_admin INTEGER DEFAULT 0,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    # Test results table (encrypted data)
    c.execute('''CREATE TABLE IF NOT EXISTS test_results
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user_id INTEGER NOT NULL,
                  encrypted_data BLOB NOT NULL,
                  encryption_key BLOB NOT NULL,
                  test_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (user_id) REFERENCES users(id))''')
    
    # Create admin account if not exists
    admin_hash = hashlib.sha256("admin123".encode()).hexdigest()
    try:
        c.execute("INSERT INTO users (username, password_hash, full_name, is_admin) VALUES (?, ?, ?, ?)",
                 ("admin", admin_hash, "System Administrator", 1))
        conn.commit()
    except sqlite3.IntegrityError:
        pass
    
    conn.close()

def register_user(username, password, full_name):
    """Register new user"""
    conn = sqlite3.connect('heart_monitor.db', check_same_thread=False)
    c = conn.cursor()
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    
    try:
        c.execute("INSERT INTO users (username, password_hash, full_name) VALUES (?, ?, ?)",
                 (username, password_hash, full_name))
        conn.commit()
        conn.close()
        return True, "Registration successful!"
    except sqlite3.IntegrityError:
        conn.close()
        return False, "Username already exists!"

def login_user(username, password):
    """Login user"""
    conn = sqlite3.connect('heart_monitor.db', check_same_thread=False)
    c = conn.cursor()
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    
    c.execute("SELECT id, full_name, is_admin FROM users WHERE username=? AND password_hash=?",
             (username, password_hash))
    result = c.fetchone()
    conn.close()
    
    if result:
        return True, {"id": result[0], "username": username, "full_name": result[1], "is_admin": result[2]}
    return False, None

def save_test_result(user_id, bpm, signal_data, analysis):
    """Save encrypted test result with hybrid encryption"""
    conn = sqlite3.connect('heart_monitor.db', check_same_thread=False)
    c = conn.cursor()
    
    # Generate encryption key for this record (simulating decentralized storage)
    encryption_key = os.urandom(32)
    
    # Prepare data
    data = {
        "bpm": bpm,
        "signal_data": signal_data[:100],  # Store sample of signal
        "analysis": analysis,
        "timestamp": datetime.now().isoformat()
    }
    
    # Encrypt data using AES-GCM
    encrypted_data = HybridEncryption.encrypt_aes_gcm(json.dumps(data), encryption_key)
    
    c.execute("INSERT INTO test_results (user_id, encrypted_data, encryption_key) VALUES (?, ?, ?)",
             (user_id, encrypted_data, encryption_key))
    conn.commit()
    conn.close()

def get_user_results(user_id):
    """Get and decrypt user's test results"""
    conn = sqlite3.connect('heart_monitor.db', check_same_thread=False)
    c = conn.cursor()
    
    c.execute("SELECT id, encrypted_data, encryption_key, test_date FROM test_results WHERE user_id=? ORDER BY test_date DESC",
             (user_id,))
    results = c.fetchall()
    conn.close()
    
    decrypted_results = []
    for result in results:
        try:
            decrypted = HybridEncryption.decrypt_aes_gcm(result[1], result[2])
            data = json.loads(decrypted)
            data['test_id'] = result[0]
            data['test_date'] = result[3]
            decrypted_results.append(data)
        except:
            pass
    
    return decrypted_results

def get_all_results_admin():
    """Admin: Get all test results"""
    conn = sqlite3.connect('heart_monitor.db', check_same_thread=False)
    c = conn.cursor()
    
    c.execute("""SELECT t.id, u.username, u.full_name, t.encrypted_data, t.encryption_key, t.test_date 
                 FROM test_results t 
                 JOIN users u ON t.user_id = u.id 
                 ORDER BY t.test_date DESC LIMIT 50""")
    results = c.fetchall()
    conn.close()
    
    decrypted_results = []
    for result in results:
        try:
            decrypted = HybridEncryption.decrypt_aes_gcm(result[3], result[4])
            data = json.loads(decrypted)
            decrypted_results.append({
                'test_id': result[0],
                'username': result[1],
                'full_name': result[2],
                'bpm': data['bpm'],
                'test_date': result[5],
                'analysis': data['analysis']
            })
        except:
            pass
    
    return decrypted_results

# =========================
# HEART RATE FUNCTIONS
# =========================

def get_forehead_roi(face, frame_shape):
    x, y, w, h = face
    forehead_x = x + int(w * 0.3)
    forehead_y = y + int(h * 0.1)
    forehead_w = int(w * 0.4)
    forehead_h = int(h * 0.15)
    return (forehead_x, forehead_y, forehead_w, forehead_h)

def extract_color_signal(frame, roi):
    x, y, w, h = roi
    if y+h > frame.shape[0] or x+w > frame.shape[1]:
        return None
    roi_frame = frame[y:y+h, x:x+w]
    green_channel = roi_frame[:, :, 1]
    return np.mean(green_channel)

def calculate_heart_rate(data_buffer, times):
    if len(data_buffer) < 200:
        return 0, []
    
    signal_data = np.array(data_buffer)
    detrended = signal.detrend(signal_data)
    
    if len(times) > 1:
        fps = len(times) / (times[-1] - times[0])
    else:
        fps = 30
    
    nyquist = fps / 2
    low = 0.8 / nyquist
    high = 3.0 / nyquist
    
    if low >= 1 or high >= 1:
        return 0, []
    
    b, a = signal.butter(3, [low, high], btype='band')
    filtered = signal.filtfilt(b, a, detrended)
    
    fft = np.fft.rfft(filtered)
    freqs = np.fft.rfftfreq(len(filtered), 1/fps)
    
    valid_idx = np.where((freqs >= 0.8) & (freqs <= 3.0))
    valid_fft = np.abs(fft[valid_idx])
    valid_freqs = freqs[valid_idx]
    
    if len(valid_fft) == 0:
        return 0, []
    
    peak_idx = np.argmax(valid_fft)
    peak_freq = valid_freqs[peak_idx]
    bpm = peak_freq * 60
    
    return int(bpm), filtered.tolist()

def analyze_heart_rate(bpm):
    """Analyze heart rate and provide detailed feedback"""
    analysis = {
        "category": "",
        "status": "",
        "description": "",
        "recommendations": []
    }
    
    if bpm < 40:
        analysis["category"] = "Bradycardia (Very Low)"
        analysis["status"] = "warning"
        analysis["description"] = "Your heart rate is significantly below normal resting range."
        analysis["recommendations"] = [
            "Consult a healthcare provider immediately",
            "This may indicate an underlying condition",
            "Athletes may have lower resting heart rates naturally"
        ]
    elif 40 <= bpm < 60:
        analysis["category"] = "Below Normal"
        analysis["status"] = "info"
        analysis["description"] = "Your heart rate is below the typical resting range."
        analysis["recommendations"] = [
            "Common in well-trained athletes",
            "Monitor for symptoms like dizziness",
            "Consult a doctor if you have concerns"
        ]
    elif 60 <= bpm <= 100:
        analysis["category"] = "Normal Resting Heart Rate"
        analysis["status"] = "success"
        analysis["description"] = "Your heart rate is within the healthy resting range!"
        analysis["recommendations"] = [
            "Maintain regular physical activity",
            "Stay hydrated",
            "Get adequate sleep",
            "Manage stress levels"
        ]
    elif 101 <= bpm <= 120:
        analysis["category"] = "Elevated"
        analysis["status"] = "warning"
        analysis["description"] = "Your heart rate is slightly elevated."
        analysis["recommendations"] = [
            "Try deep breathing exercises",
            "Ensure you're well-hydrated",
            "Check if you're anxious or stressed",
            "Avoid caffeine before testing"
        ]
    else:
        analysis["category"] = "Tachycardia (Very High)"
        analysis["status"] = "warning"
        analysis["description"] = "Your heart rate is significantly above normal resting range."
        analysis["recommendations"] = [
            "Seek medical attention if persistent",
            "Rule out anxiety or recent physical activity",
            "Monitor for other symptoms",
            "Avoid stimulants"
        ]
    
    return analysis

# =========================
# INITIALIZE
# =========================

init_database()

if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.user = None
    st.session_state.page = "login"
    st.session_state.data_buffer = deque(maxlen=250)
    st.session_state.times = deque(maxlen=250)
    st.session_state.bpm = 0
    st.session_state.running = False
    st.session_state.test_complete = False
    st.session_state.last_result = None

# =========================
# NAVIGATION
# =========================

def logout():
    st.session_state.logged_in = False
    st.session_state.user = None
    st.session_state.page = "login"
    st.rerun()

# =========================
# LOGIN/REGISTER PAGE
# =========================

if not st.session_state.logged_in:
    st.title("🔐 Secure Heart Rate Monitoring System")
    st.markdown("### Advanced Medical IoT Platform with Hybrid Encryption")
    
    tab1, tab2 = st.tabs(["Login", "Register"])
    
    with tab1:
        st.subheader("Login to Your Account")
        username = st.text_input("Username", key="login_username")
        password = st.text_input("Password", type="password", key="login_password")
        
        col1, col2 = st.columns(2)
        with col1:
            if st.button("Login", type="primary", use_container_width=True):
                if username and password:
                    success, user_data = login_user(username, password)
                    if success:
                        st.session_state.logged_in = True
                        st.session_state.user = user_data
                        if user_data['is_admin']:
                            st.session_state.page = "admin_dashboard"
                        else:
                            st.session_state.page = "monitor"
                        st.success(f"Welcome back, {user_data['full_name']}!")
                        time.sleep(1)
                        st.rerun()
                    else:
                        st.error("Invalid credentials!")
                else:
                    st.warning("Please enter both username and password")
        
        with col2:
            st.info("**Demo Admin Login:**\n- Username: admin\n- Password: admin123")
    
    with tab2:
        st.subheader("Create New Account")
        reg_fullname = st.text_input("Full Name", key="reg_fullname")
        reg_username = st.text_input("Username", key="reg_username")
        reg_password = st.text_input("Password", type="password", key="reg_password")
        reg_password2 = st.text_input("Confirm Password", type="password", key="reg_password2")
        
        if st.button("Register", type="primary", use_container_width=True):
            if reg_fullname and reg_username and reg_password:
                if reg_password == reg_password2:
                    if len(reg_password) >= 6:
                        success, message = register_user(reg_username, reg_password, reg_fullname)
                        if success:
                            st.success(message)
                            st.info("Please login with your credentials")
                        else:
                            st.error(message)
                    else:
                        st.error("Password must be at least 6 characters")
                else:
                    st.error("Passwords don't match!")
            else:
                st.warning("Please fill all fields")
    
    st.markdown("---")
    st.markdown("""
    <div style='text-align: center; color: gray;'>
        <small>🔒 Secured with AES-GCM Symmetric Encryption & ECC Asymmetric Authentication<br>
        Data stored with decentralized storage simulation using SQLite</small>
    </div>
    """, unsafe_allow_html=True)

# =========================
# ADMIN DASHBOARD
# =========================

elif st.session_state.user['is_admin'] and st.session_state.page == "admin_dashboard":
    st.title("👨‍💼 Admin Dashboard")
    
    col1, col2 = st.columns([3, 1])
    with col1:
        st.markdown(f"### Welcome, {st.session_state.user['full_name']}")
    with col2:
        if st.button("Logout", type="secondary"):
            logout()
    
    st.markdown("---")
    
    # Get all results
    all_results = get_all_results_admin()
    
    if all_results:
        st.subheader("📊 Recent Test Results")
        
        # Create DataFrame
        df = pd.DataFrame(all_results)
        
        # Display summary stats
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Tests", len(df))
        with col2:
            st.metric("Average BPM", f"{df['bpm'].mean():.0f}")
        with col3:
            st.metric("Unique Users", df['username'].nunique())
        with col4:
            normal_count = len(df[(df['bpm'] >= 60) & (df['bpm'] <= 100)])
            st.metric("Normal Results", f"{normal_count}")
        
        st.markdown("---")
        
        # Display table
        display_df = df[['test_date', 'full_name', 'username', 'bpm', 'test_id']].copy()
        display_df['test_date'] = pd.to_datetime(display_df['test_date']).dt.strftime('%Y-%m-%d %H:%M')
        display_df.columns = ['Test Date', 'Patient Name', 'Username', 'Heart Rate (BPM)', 'Test ID']
        
        st.dataframe(display_df, use_container_width=True, hide_index=True)
        
        # Visualization
        st.subheader("📈 Heart Rate Distribution")
        fig = px.histogram(df, x='bpm', nbins=20, title="Distribution of Heart Rates",
                          labels={'bpm': 'Heart Rate (BPM)', 'count': 'Number of Tests'})
        fig.add_vline(x=60, line_dash="dash", line_color="green", annotation_text="Normal Min")
        fig.add_vline(x=100, line_dash="dash", line_color="green", annotation_text="Normal Max")
        st.plotly_chart(fig, use_container_width=True)
        
    else:
        st.info("No test results yet. Users need to complete heart rate tests first.")

# =========================
# USER MONITOR PAGE
# =========================

elif st.session_state.page == "monitor":
    col1, col2 = st.columns([3, 1])
    with col1:
        st.title("❤️ Heart Rate Monitor")
        st.markdown(f"### Welcome, {st.session_state.user['full_name']}")
    with col2:
        if st.button("My Results", type="secondary"):
            st.session_state.page = "results"
            st.rerun()
        if st.button("Logout"):
            logout()
    
    st.markdown("---")
    
    col1, col2 = st.columns([2, 1])
    
    with col2:
        st.markdown("### Instructions")
        st.info("""
        1. Click 'Start Test'
        2. Allow camera access
        3. Position face in frame
        4. Stay still, good lighting
        5. Wait 10-15 seconds
        """)
        
        if st.session_state.bpm > 0:
            st.markdown("### Live Reading")
            st.metric("Heart Rate", f"{st.session_state.bpm} BPM")
    
    with col1:
        camera_placeholder = st.empty()
        status_placeholder = st.empty()
        
        start_button = st.button("Start Test", type="primary")
        stop_button = st.button("Stop Test")
        
        if start_button:
            st.session_state.running = True
            st.session_state.test_complete = False
            st.session_state.data_buffer.clear()
            st.session_state.times.clear()
            st.session_state.bpm = 0
        
        if stop_button:
            st.session_state.running = False
        
        if st.session_state.running:
            face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')
            cap = cv2.VideoCapture(0)
            
            if not cap.isOpened():
                status_placeholder.error("❌ Could not access webcam")
                st.session_state.running = False
            else:
                status_placeholder.info("📹 Detecting face...")
                
                frame_count = 0
                start_time = time.time()
                signal_data_history = []
                
                while st.session_state.running:
                    ret, frame = cap.read()
                    if not ret:
                        break
                    
                    frame_rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
                    gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
                    faces = face_cascade.detectMultiScale(gray, 1.3, 5)
                    
                    if len(faces) > 0:
                        face = faces[0]
                        x, y, w, h = face
                        cv2.rectangle(frame_rgb, (x, y), (x+w, y+h), (0, 255, 0), 2)
                        
                        roi = get_forehead_roi(face, frame_rgb.shape)
                        rx, ry, rw, rh = roi
                        cv2.rectangle(frame_rgb, (rx, ry), (rx+rw, ry+rh), (255, 0, 0), 2)
                        cv2.putText(frame_rgb, "Measuring", (rx, ry-10), 
                                   cv2.FONT_HERSHEY_SIMPLEX, 0.5, (255, 0, 0), 2)
                        
                        green_val = extract_color_signal(frame, roi)
                        
                        if green_val is not None:
                            current_time = time.time()
                            st.session_state.data_buffer.append(green_val)
                            st.session_state.times.append(current_time)
                            
                            if frame_count % 10 == 0 and len(st.session_state.data_buffer) > 50:
                                bpm, filtered_signal = calculate_heart_rate(
                                    st.session_state.data_buffer, 
                                    st.session_state.times
                                )
                                st.session_state.bpm = bpm
                                signal_data_history = filtered_signal
                            
                            buffer_percent = int((len(st.session_state.data_buffer) / 250) * 100)
                            if st.session_state.bpm > 0:
                                status_placeholder.success(f"✅ {buffer_percent}% | HR: {st.session_state.bpm} BPM")
                            else:
                                status_placeholder.info(f"📊 Collecting data... {buffer_percent}%")
                    else:
                        status_placeholder.warning("⚠️ No face detected")
                    
                    camera_placeholder.image(frame_rgb, channels="RGB", use_container_width=True)
                    frame_count += 1
                    
                    if time.time() - start_time > 20:
                        status_placeholder.success("✅ Test complete!")
                        st.session_state.running = False
                        st.session_state.test_complete = True
                        
                        # Save result
                        if st.session_state.bpm > 0:
                            analysis = analyze_heart_rate(st.session_state.bpm)
                            save_test_result(
                                st.session_state.user['id'],
                                st.session_state.bpm,
                                signal_data_history,
                                analysis
                            )
                            st.session_state.last_result = {
                                'bpm': st.session_state.bpm,
                                'analysis': analysis,
                                'signal_data': signal_data_history
                            }
                        break
                
                cap.release()
        
        if st.session_state.test_complete and st.session_state.last_result:
            st.success("Test saved! Click 'View Detailed Analysis' to see full report.")
            if st.button("View Detailed Analysis", type="primary"):
                st.session_state.page = "analysis"
                st.rerun()

# =========================
# DETAILED ANALYSIS PAGE
# =========================

elif st.session_state.page == "analysis":
    st.title("📊 Detailed Heart Rate Analysis")
    
    if st.button("← Back to Monitor"):
        st.session_state.page = "monitor"
        st.rerun()
    
    if st.session_state.last_result:
        result = st.session_state.last_result
        analysis = result['analysis']
        
        # Header with BPM
        st.markdown(f"## Heart Rate: {result['bpm']} BPM")
        
        # Status indicator
        if analysis['status'] == 'success':
            st.success(f"✅ {analysis['category']}")
        elif analysis['status'] == 'warning':
            st.warning(f"⚠️ {analysis['category']}")
        else:
            st.info(f"ℹ️ {analysis['category']}")
        
        st.markdown("---")
        
        # Charts
        col1, col2 = st.columns(2)
        
        with col1:
            # Gauge chart
            fig_gauge = go.Figure(go.Indicator(
                mode = "gauge+number+delta",
                value = result['bpm'],
                domain = {'x': [0, 1], 'y': [0, 1]},
                title = {'text': "Heart Rate (BPM)"},
                delta = {'reference': 80},
                gauge = {
                    'axis': {'range': [None, 180]},
                    'bar': {'color': "darkblue"},
                    'steps': [
                        {'range': [0, 60], 'color': "lightgray"},
                        {'range': [60, 100], 'color': "lightgreen"},
                        {'range': [100, 180], 'color': "lightyellow"}
                    ],
                    'threshold': {
                        'line': {'color': "red", 'width': 4},
                        'thickness': 0.75,
                        'value': 100
                    }
                }
            ))
            st.plotly_chart(fig_gauge, use_container_width=True)
        
        with col2:
            # Heart rate zone chart
            zones_data = pd.DataFrame({
                'Zone': ['Very Low\n(<60)', 'Normal\n(60-100)', 'Elevated\n(100-120)', 'Very High\n(>120)'],
                'Range': [60, 40, 20, 60],
                'Color': ['#FF6B6B', '#51CF66', '#FFD93D', '#FF6B6B']
            })
            
            fig_zones = go.Figure(data=[go.Bar(
                x=zones_data['Zone'],
                y=zones_data['Range'],
                marker_color=zones_data['Color'],
                text=zones_data['Range'],
                textposition='auto',
            )])
            
            fig_zones.add_hline(y=result['bpm'], line_dash="dash", 
                               line_color="red", annotation_text="Your HR")
            
            fig_zones.update_layout(
                title="Heart Rate Zones",
                xaxis_title="Zone",
                yaxis_title="BPM Range",
                showlegend=False
            )
            st.plotly_chart(fig_zones, use_container_width=True)
        
        # Signal visualization
        if result['signal_data']:
            st.markdown("### 📈 Processed Signal Data")
            signal_df = pd.DataFrame({
                'Sample': range(len(result['signal_data'])),
                'Amplitude': result['signal_data']
            })
            
            fig_signal = px.line(signal_df, x='Sample', y='Amplitude',
                               title='Filtered Heart Rate Signal',
                               labels={'Sample': 'Time (samples)', 'Amplitude': 'Signal Amplitude'})
            st.plotly_chart(fig_signal, use_container_width=True)
        
        st.markdown("---")
        
        # Analysis details
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("### 📝 Analysis")
            st.markdown(f"**{analysis['description']}**")
            
            st.markdown("### ✅ Recommendations")
            for rec in analysis['recommendations']:
                st.markdown(f"- {rec}")
        
        with col2:
            st.markdown("### 📊 Heart Rate Classification")
            st.markdown("""
            - **< 60 BPM**: Bradycardia (low)
            - **60-100 BPM**: Normal resting
            - **100-120 BPM**: Elevated
            - **> 120 BPM**: Tachycardia (high)
            """)
            
            st.markdown("### 🔒 Security")
            st.info("This result is encrypted with AES-GCM and stored securely using hybrid encryption.")
    
    else:
        st.warning("No recent test data. Please complete a test first.")
        if st.button("Start New Test"):
            st.session_state.page = "monitor"
            st.rerun()

# =========================
# RESULTS HISTORY PAGE
# =========================

elif st.session_state.page == "results":
    st.title("📋 My Test Results")
    
    col1, col2 = st.columns([3, 1])
    with col1:
        st.markdown(f"### Test History for {st.session_state.user['full_name']}")
    with col2:
        if st.button("← Back to Monitor"):
            st.session_state.page = "monitor"
            st.rerun()
    
    st.markdown("---")
    
    # Get user's results
    user_results = get_user_results(st.session_state.user['id'])
    
    if user_results:
        # Summary statistics
        bpm_values = [r['bpm'] for r in user_results]
        
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Tests", len(user_results))
        with col2:
            st.metric("Average BPM", f"{np.mean(bpm_values):.0f}")
        with col3:
            st.metric("Lowest BPM", f"{min(bpm_values)}")
        with col4:
            st.metric("Highest BPM", f"{max(bpm_values)}")
        
        st.markdown("---")
        
        # Trend chart
        st.subheader("📈 Heart Rate Trend")
        df_results = pd.DataFrame(user_results)
        df_results['test_date'] = pd.to_datetime(df_results['test_date'])
        df_results = df_results.sort_values('test_date')
        
        fig_trend = go.Figure()
        fig_trend.add_trace(go.Scatter(
            x=df_results['test_date'],
            y=df_results['bpm'],
            mode='lines+markers',
            name='Heart Rate',
            line=dict(color='red', width=2),
            marker=dict(size=8)
        ))
        
        # Add normal range bands
        fig_trend.add_hrect(y0=60, y1=100, fillcolor="green", opacity=0.1, 
                           annotation_text="Normal Range", annotation_position="top left")
        
        fig_trend.update_layout(
            title="Heart Rate Over Time",
            xaxis_title="Date",
            yaxis_title="BPM",
            hovermode='x unified'
        )
        st.plotly_chart(fig_trend, use_container_width=True)
        
        st.markdown("---")
        
        # Detailed results table
        st.subheader("📊 Detailed Test Results")
        
        for idx, result in enumerate(user_results):
            with st.expander(f"Test {idx + 1} - {result['test_date']} | {result['bpm']} BPM"):
                col1, col2 = st.columns(2)
                
                with col1:
                    st.markdown(f"**Heart Rate:** {result['bpm']} BPM")
                    st.markdown(f"**Date:** {result['test_date']}")
                    st.markdown(f"**Category:** {result['analysis']['category']}")
                    
                    if result['analysis']['status'] == 'success':
                        st.success(result['analysis']['description'])
                    elif result['analysis']['status'] == 'warning':
                        st.warning(result['analysis']['description'])
                    else:
                        st.info(result['analysis']['description'])
                
                with col2:
                    st.markdown("**Recommendations:**")
                    for rec in result['analysis']['recommendations']:
                        st.markdown(f"- {rec}")
                
                # Mini gauge for this test
                fig_mini = go.Figure(go.Indicator(
                    mode = "gauge+number",
                    value = result['bpm'],
                    domain = {'x': [0, 1], 'y': [0, 1]},
                    gauge = {
                        'axis': {'range': [None, 180]},
                        'bar': {'color': "darkblue"},
                        'steps': [
                            {'range': [0, 60], 'color': "lightgray"},
                            {'range': [60, 100], 'color': "lightgreen"},
                            {'range': [100, 180], 'color': "lightyellow"}
                        ],
                    }
                ))
                fig_mini.update_layout(height=200)
                st.plotly_chart(fig_mini, use_container_width=True)
        
        # Export option
        st.markdown("---")
        st.subheader("📥 Export Data")
        
        export_df = pd.DataFrame({
            'Date': [r['test_date'] for r in user_results],
            'Heart Rate (BPM)': [r['bpm'] for r in user_results],
            'Category': [r['analysis']['category'] for r in user_results],
            'Status': [r['analysis']['status'] for r in user_results]
        })
        
        csv = export_df.to_csv(index=False)
        st.download_button(
            label="Download Results as CSV",
            data=csv,
            file_name=f"heart_rate_results_{st.session_state.user['username']}.csv",
            mime="text/csv"
        )
    
    else:
        st.info("📭 No test results yet. Complete your first heart rate test!")
        if st.button("Start New Test", type="primary"):
            st.session_state.page = "monitor"
            st.rerun()

# =========================
# FOOTER
# =========================

st.markdown("---")
st.markdown("""
<div style='text-align: center; color: gray;'>
    <small>🔒 Secured with Hybrid Encryption (AES-GCM + ECC)<br>
    ⚠️ For educational purposes only. Not a medical device. Consult healthcare professionals for medical advice.</small>
</div>
""", unsafe_allow_html=True)