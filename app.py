from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import requests
import secrets
import os
from datetime import datetime
from datetime import datetime, timedelta
import re
from werkzeug.utils import secure_filename
import os
import uuid
from werkzeug.utils import secure_filename
from functools import wraps
import os
import uuid
import mysql.connector
from werkzeug.security import check_password_hash, generate_password_hash
import re
import requests
import json
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime, timedelta
import json
from datetime import datetime



app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this'

# Database configuration
DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',  # Change to your MySQL username
    'password': '56964',  # Change to your MySQL password
    'database': 'ayurvedic_portal',
    'charset': 'utf8mb4',
    'use_unicode': True,
    'get_warnings': True,
    'autocommit': True
}

# Google OAuth configuration
GOOGLE_CLIENT_ID = "your-google-client-id.apps.googleusercontent.com"
GOOGLE_CLIENT_SECRET = "your-google-client-secret"
GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_id' not in session:
            flash('Please log in as admin to access this page.', 'error')
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function


# ADD THIS TO YOUR app.py FILE

def get_user_profile_photo(user_id):
    """Get user's profile photo for navbar display"""
    if not user_id:
        return None
        
    try:
        connection = get_db_connection()
        if not connection:
            return None
        
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT profile_photo FROM normal_user_profiles WHERE user_id = %s", (user_id,))
        
        result = cursor.fetchone()
        cursor.close()
        connection.close()
        
        if result and result['profile_photo']:
            return result['profile_photo']
        return None
        
    except Exception as e:
        print(f"Error fetching profile photo: {e}")
        return None

# IMPORTANT: Add this line AFTER creating your Flask app
app.jinja_env.globals.update(get_user_profile_photo=get_user_profile_photo)


def get_db_connection():
    """Create database connection"""
    try:
        connection = mysql.connector.connect(**DB_CONFIG)
        return connection
    except mysql.connector.Error as err:
        print(f"Database connection error: {err}")
        return None

def login_required(f):
    """Decorator to require login"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('signin'))
        return f(*args, **kwargs)
    return decorated_function

def validate_email(email):
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email)

def validate_password(password):
    """Validate password strength"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one number"
    return True, "Password is valid"

@app.context_processor
def inject_datetime():
    return {'datetime': datetime}

@app.template_filter('datetime_format')
def datetime_format(value, format='%B %d, %Y'):
    """Custom datetime filter for Jinja2"""
    if isinstance(value, str):
        return value
    return value.strftime(format) if value else ''

@app.context_processor
def inject_now():
    """Inject current datetime into all templates"""
    return {
        'now': datetime.now(),
        'current_year': datetime.now().year,
        'current_month': datetime.now().strftime('%B'),
        'current_date': datetime.now().strftime('%B %d, %Y'),
        'current_day': datetime.now().strftime('%A, %B %d')
    }

@app.route('/')
def index():
    """Landing page"""
    return render_template('index.html')

@app.route('/signin', methods=['GET', 'POST'])
def signin():
    """Sign-in page"""
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')

        if not email or not password:
            flash('Please fill in all fields.', 'error')
            return render_template('signin.html')

        if not validate_email(email):
            flash('Please enter a valid email address.', 'error')
            return render_template('signin.html')

        connection = get_db_connection()
        if not connection:
            flash('Database connection error. Please try again.', 'error')
            return render_template('signin.html')

        try:
            cursor = connection.cursor(dictionary=True)

            # Check in normal_users table
            cursor.execute("SELECT * FROM normal_users WHERE email = %s", (email,))
            user = cursor.fetchone()

            if user and check_password_hash(user['password'], password):
                session['user_id'] = user['id']
                session['user_type'] = 'normal'
                session['user_name'] = user['name']
                session['user_email'] = user['email']
                flash(f'Welcome back, {user["name"]}!', 'success')
                return redirect(url_for('normal_dashboard'))

            # Check in doctor_users table
            cursor.execute("SELECT * FROM doctor_users WHERE email = %s", (email,))
            doctor = cursor.fetchone()

            if doctor and check_password_hash(doctor['password'], password):
                session['user_id'] = doctor['id']
                session['user_type'] = 'doctor'
                session['user_name'] = doctor['name']
                session['user_email'] = doctor['email']
                session['specialty'] = doctor['specialty']
                session['qualification'] = doctor['qualification']
                flash(f'Welcome back, Dr. {doctor["name"]}!', 'success')
                return redirect(url_for('doctor_dashboard'))

            flash('Invalid email or password.', 'error')

        except mysql.connector.Error as err:
            flash('Login failed. Please try again.', 'error')
            print(f"Database error: {err}")
        finally:
            if connection:
                connection.close()

    return render_template('signin.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """Sign-up page"""
    if request.method == 'POST':
        user_type = request.form.get('user_type')
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        captcha = request.form.get('captcha', '').strip()

        # Basic validation
        if not all([user_type, name, email, password, confirm_password, captcha]):
            flash('Please fill in all fields.', 'error')
            return render_template('signup.html')

        if not validate_email(email):
            flash('Please enter a valid email address.', 'error')
            return render_template('signup.html')

        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('signup.html')

        is_valid, message = validate_password(password)
        if not is_valid:
            flash(message, 'error')
            return render_template('signup.html')

        # Simple captcha validation (you can implement more sophisticated captcha)
        if captcha.lower() != session.get('captcha', '').lower():
            flash('Invalid captcha. Please try again.', 'error')
            return render_template('signup.html')

        connection = get_db_connection()
        if not connection:
            flash('Database connection error. Please try again.', 'error')
            return render_template('signup.html')

        try:
            cursor = connection.cursor()

            # Check if email already exists
            cursor.execute("SELECT email FROM normal_users WHERE email = %s UNION SELECT email FROM doctor_users WHERE email = %s", (email, email))
            if cursor.fetchone():
                flash('Email already registered. Please use a different email.', 'error')
                return render_template('signup.html')

            hashed_password = generate_password_hash(password)

            if user_type == 'normal':
                cursor.execute("""
                    INSERT INTO normal_users (name, email, password, created_at) 
                    VALUES (%s, %s, %s, %s)
                """, (name, email, hashed_password, datetime.now()))

                flash('Normal user account created successfully! Please sign in.', 'success')

            elif user_type == 'doctor':
                specialty = request.form.get('specialty', '').strip()
                qualification = request.form.get('qualification', '').strip()

                if not specialty or not qualification:
                    flash('Please fill in specialty and qualification fields.', 'error')
                    return render_template('signup.html')

                cursor.execute("""
                    INSERT INTO doctor_users (name, email, password, specialty, qualification, created_at) 
                    VALUES (%s, %s, %s, %s, %s, %s)
                """, (name, email, hashed_password, specialty, qualification, datetime.now()))

                flash('Doctor account created successfully! Please sign in.', 'success')

            connection.commit()
            return redirect(url_for('signin'))

        except mysql.connector.Error as err:
            flash('Registration failed. Please try again.', 'error')
            print(f"Database error: {err}")
        finally:
            if connection:
                connection.close()

    return render_template('signup.html')

@app.route('/google-login')
def google_login():
    """Initiate Google OAuth login"""
    # Generate state parameter for security
    state = secrets.token_urlsafe(32)
    session['oauth_state'] = state

    google_auth_url = (
        f"https://accounts.google.com/o/oauth2/auth?"
        f"client_id={GOOGLE_CLIENT_ID}&"
        f"redirect_uri={request.url_root}google-callback&"
        f"scope=openid email profile&"
        f"response_type=code&"
        f"state={state}"
    )

    return redirect(google_auth_url)

@app.route('/google-callback')
def google_callback():
    """Handle Google OAuth callback"""
    code = request.args.get('code')
    state = request.args.get('state')

    # Verify state parameter
    if state != session.get('oauth_state'):
        flash('Invalid state parameter. Please try again.', 'error')
        return redirect(url_for('signin'))

    if not code:
        flash('Authorization failed. Please try again.', 'error')
        return redirect(url_for('signin'))

    try:
        # Exchange code for access token
        token_data = {
            'client_id': GOOGLE_CLIENT_ID,
            'client_secret': GOOGLE_CLIENT_SECRET,
            'code': code,
            'grant_type': 'authorization_code',
            'redirect_uri': f'{request.url_root}google-callback'
        }

        response = requests.post('https://oauth2.googleapis.com/token', data=token_data)
        tokens = response.json()

        if 'access_token' not in tokens:
            flash('Failed to obtain access token. Please try again.', 'error')
            return redirect(url_for('signin'))

        # Get user info from Google
        headers = {'Authorization': f"Bearer {tokens['access_token']}"}
        user_response = requests.get('https://www.googleapis.com/oauth2/v2/userinfo', headers=headers)
        user_info = user_response.json()

        email = user_info.get('email')
        name = user_info.get('name')

        if not email:
            flash('Failed to get user information from Google.', 'error')
            return redirect(url_for('signin'))

        connection = get_db_connection()
        if not connection:
            flash('Database connection error. Please try again.', 'error')
            return redirect(url_for('signin'))

        try:
            cursor = connection.cursor(dictionary=True)

            # Check if user exists in normal_users
            cursor.execute("SELECT * FROM normal_users WHERE email = %s", (email,))
            user = cursor.fetchone()

            if user:
                session['user_id'] = user['id']
                session['user_type'] = 'normal'
                session['user_name'] = user['name']
                session['user_email'] = user['email']
                flash(f'Welcome back, {user["name"]}!', 'success')
                return redirect(url_for('normal_dashboard'))

            # Check if user exists in doctor_users
            cursor.execute("SELECT * FROM doctor_users WHERE email = %s", (email,))
            doctor = cursor.fetchone()

            if doctor:
                session['user_id'] = doctor['id']
                session['user_type'] = 'doctor'
                session['user_name'] = doctor['name']
                session['user_email'] = doctor['email']
                session['specialty'] = doctor['specialty']
                session['qualification'] = doctor['qualification']
                flash(f'Welcome back, Dr. {doctor["name"]}!', 'success')
                return redirect(url_for('doctor_dashboard'))

            # Create new normal user account
            cursor.execute("""
                INSERT INTO normal_users (name, email, password, google_id, created_at) 
                VALUES (%s, %s, %s, %s, %s)
            """, (name, email, generate_password_hash(secrets.token_urlsafe(32)), user_info.get('id'), datetime.now()))

            user_id = cursor.lastrowid
            connection.commit()

            session['user_id'] = user_id
            session['user_type'] = 'normal'
            session['user_name'] = name
            session['user_email'] = email
            flash(f'Welcome, {name}! Your account has been created.', 'success')
            return redirect(url_for('normal_dashboard'))

        except mysql.connector.Error as err:
            flash('Login failed. Please try again.', 'error')
            print(f"Database error: {err}")
        finally:
            if connection:
                connection.close()

    except Exception as e:
        flash('Google login failed. Please try again.', 'error')
        print(f"Google OAuth error: {e}")

    return redirect(url_for('signin'))

@app.route('/normal-dashboard')
@login_required
def normal_dashboard():
    """Normal user dashboard"""
    if session.get('user_type') != 'normal':
        flash('Access denied.', 'error')
        return redirect(url_for('signin'))

    return render_template('normal_dashboard.html')

@app.route('/doctor-dashboard')
@login_required
def doctor_dashboard():
    """Doctor dashboard"""
    if session.get('user_type') != 'doctor':
        flash('Access denied.', 'error')
        return redirect(url_for('signin'))

    return render_template('doctor_dashboard.html')

@app.route('/logout')
def logout():
    """Logout user"""
    session.clear()
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('index'))

@app.route('/generate-captcha')
def generate_captcha():
    """Generate simple captcha"""
    import random
    import string

    captcha_text = ''.join(random.choices(string.ascii_uppercase + string.digits, k=5))
    session['captcha'] = captcha_text

    return jsonify({'captcha': captcha_text})

# Profile Management Routes
@app.route('/profile')
@login_required
def profile():
    """Normal user profile page with View/Edit mode and file upload support"""
    if session.get('user_type') != 'normal':
        flash('Access denied. Profile page is only for patients.', 'error')
        return redirect(url_for('index'))
    
    connection = get_db_connection()
    if not connection:
        flash('Database connection error. Please try again.', 'error')
        return redirect(url_for('normal_dashboard'))
    
    try:
        cursor = connection.cursor(dictionary=True)
        
        # Get or create user profile
        cursor.execute("""
            SELECT * FROM normal_user_profiles 
            WHERE user_id = %s
        """, (session['user_id'],))
        
        profile = cursor.fetchone()
        
        if not profile:
            # Create default profile if doesn't exist
            cursor.execute("""
                INSERT INTO normal_user_profiles (user_id, full_name, email_id, country) 
                VALUES (%s, %s, %s, %s)
            """, (session['user_id'], session['user_name'], session['user_email'], 'India'))
            
            connection.commit()
            
            # Fetch the newly created profile
            cursor.execute("""
                SELECT * FROM normal_user_profiles 
                WHERE user_id = %s
            """, (session['user_id'],))
            
            profile = cursor.fetchone()
        
        cursor.close()
        connection.close()
        
        return render_template('normal_profile.html', profile=profile)
        
    except mysql.connector.Error as err:
        flash('Error loading profile. Please try again.', 'error')
        print(f"Profile error: {err}")
        return redirect(url_for('normal_dashboard'))

@app.route('/profile/update', methods=['POST'])
@login_required
def update_profile():
    """Update user profile with identity proof file upload support"""
    if session.get('user_type') != 'normal':
        flash('Access denied.', 'error')
        return redirect(url_for('index'))
    
    connection = get_db_connection()
    if not connection:
        flash('Database connection error. Please try again.', 'error')
        return redirect(url_for('profile'))
    
    try:
        cursor = connection.cursor(dictionary=True)
        
        # Get current profile to check restrictions
        cursor.execute("""
            SELECT identity_proof_type, identity_proof_number, identity_proof_file 
            FROM normal_user_profiles 
            WHERE user_id = %s
        """, (session['user_id'],))
        
        current_profile = cursor.fetchone()
        
        # Get form data
        full_name = request.form.get('full_name', '').strip()
        mobile_number = request.form.get('mobile_number', '').strip()
        gender = request.form.get('gender')
        blood_group = request.form.get('blood_group')
        marital_status = request.form.get('marital_status')
        date_of_birth = request.form.get('date_of_birth')
        address = request.form.get('address', '').strip()
        city = request.form.get('city', '').strip()
        state = request.form.get('state', '').strip()
        country = request.form.get('country', 'India').strip()
        pincode = request.form.get('pincode', '').strip()
        emergency_contact_name = request.form.get('emergency_contact_name', '').strip()
        
        # Handle identity proof (restricted fields)
        identity_proof_type = request.form.get('identity_proof_type')
        identity_proof_number = request.form.get('identity_proof_number', '').strip()
        
        # Handle identity proof file upload
        identity_proof_file_path = None
        if 'identity_proof_file' in request.files:
            file = request.files['identity_proof_file']
            
            # Only process file if current profile doesn't have one and file is selected
            if file and file.filename and (not current_profile or not current_profile['identity_proof_file']):
                if allowed_identity_file(file.filename):
                    # Validate file size (10MB limit)
                    if file.content_length and file.content_length > 10 * 1024 * 1024:
                        flash('❌ File size too large. Please upload files smaller than 10MB.', 'error')
                        return redirect(url_for('profile'))
                    
                    filename = secure_filename(file.filename)
                    
                    # Create unique filename
                    file_extension = filename.rsplit('.', 1)[1].lower()
                    unique_filename = f"identity_{session['user_id']}_{uuid.uuid4().hex[:8]}.{file_extension}"
                    
                    # Create upload directory if it doesn't exist
                    upload_folder = os.path.join('static', 'uploads', 'normal_profiles', 'documents')
                    os.makedirs(upload_folder, exist_ok=True)
                    
                    file_path = os.path.join(upload_folder, unique_filename)
                    
                    try:
                        file.save(file_path)
                        identity_proof_file_path = f"uploads/normal_profiles/documents/{unique_filename}"
                        flash('📎 Identity proof document uploaded successfully!', 'success')
                    except Exception as e:
                        flash('❌ Error saving file. Please try again.', 'error')
                        print(f"File upload error: {e}")
                        return redirect(url_for('profile'))
                        
                else:
                    flash('❌ Invalid file type. Please upload PDF, JPEG, JPG, or PNG files only.', 'error')
                    return redirect(url_for('profile'))
                    
            elif current_profile and current_profile['identity_proof_file'] and file and file.filename:
                flash('❌ Identity proof document cannot be changed once uploaded.', 'error')
                return redirect(url_for('profile'))
        
        # Validation
        if not full_name:
            flash('Full name is required.', 'error')
            return redirect(url_for('profile'))
        
        # Validate mobile number format if provided
        if mobile_number:
            import re
            mobile_pattern = r'^[+]?[0-9\\s\\-\\(\\)]{10,15}$'
            clean_mobile = mobile_number.replace(' ', '').replace('-', '').replace('(', '').replace(')', '')
            if not re.match(mobile_pattern, mobile_number) or len(clean_mobile.replace('+', '')) < 10:
                flash('Please enter a valid mobile number (minimum 10 digits).', 'error')
                return redirect(url_for('profile'))
        
        # Check if identity proof is being changed when already set
        if current_profile:
            if (current_profile['identity_proof_type'] and 
                identity_proof_type and 
                current_profile['identity_proof_type'] != identity_proof_type):
                flash('Identity proof type cannot be changed once submitted.', 'error')
                return redirect(url_for('profile'))
            
            if (current_profile['identity_proof_number'] and 
                identity_proof_number and 
                current_profile['identity_proof_number'] != identity_proof_number):
                flash('Identity proof number cannot be changed once submitted.', 'error')
                return redirect(url_for('profile'))
        
        # Prepare update query
        update_fields = []
        update_values = []
        
        # Always updatable fields (includes mobile_number)
        update_fields.extend([
            'full_name = %s', 'mobile_number = %s', 'gender = %s', 'blood_group = %s', 
            'marital_status = %s', 'date_of_birth = %s', 'address = %s', 'city = %s', 
            'state = %s', 'country = %s', 'pincode = %s', 'emergency_contact_name = %s'
        ])
        update_values.extend([
            full_name, mobile_number, gender, blood_group, marital_status, 
            date_of_birth or None, address, city, state, country, pincode, 
            emergency_contact_name
        ])
        
        # Add identity proof only if not already set
        if not current_profile or not current_profile['identity_proof_type']:
            if identity_proof_type:
                update_fields.extend(['identity_proof_type = %s', 'identity_proof_number = %s'])
                update_values.extend([identity_proof_type, identity_proof_number])
        
        # Add identity proof file if uploaded
        if identity_proof_file_path:
            update_fields.append('identity_proof_file = %s')
            update_values.append(identity_proof_file_path)
        
        # Check profile completion
        is_complete = all([
            full_name, gender, blood_group, address, city, state, country, pincode
        ])
        update_fields.append('is_profile_complete = %s')
        update_values.append(is_complete)
        
        # Add user_id for WHERE clause
        update_values.append(session['user_id'])
        
        # Execute update
        update_query = f"""
            UPDATE normal_user_profiles 
            SET {', '.join(update_fields)}
            WHERE user_id = %s
        """
        
        cursor.execute(update_query, update_values)
        connection.commit()
        
        # Update session name if changed
        if full_name != session.get('user_name'):
            session['user_name'] = full_name
            
            # Also update in normal_users table
            cursor.execute("""
                UPDATE normal_users 
                SET name = %s 
                WHERE id = %s
            """, (full_name, session['user_id']))
            connection.commit()
        
        cursor.close()
        connection.close()
        
        # Enhanced success message
        completion_status = "complete" if is_complete else "incomplete"
        flash(f'✅ Profile updated successfully! Your profile is now {completion_status}.', 'success')
        
        return redirect(url_for('profile'))
        
    except mysql.connector.Error as err:
        flash('❌ Error updating profile. Please try again.', 'error')
        print(f"Profile update error: {err}")
        return redirect(url_for('profile'))

@app.route('/profile/upload-photo', methods=['POST'])
@login_required
def upload_profile_photo():
    """Upload profile photo"""
    if session.get('user_type') != 'normal':
        flash('Access denied.', 'error')
        return redirect(url_for('index'))
    
    if 'profile_photo' not in request.files:
        flash('No file selected.', 'error')
        return redirect(url_for('profile'))
    
    file = request.files['profile_photo']
    
    if file.filename == '':
        flash('No file selected.', 'error')
        return redirect(url_for('profile'))
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        
        # Create unique filename
        unique_filename = f"{session['user_id']}_{uuid.uuid4().hex[:8]}_{filename}"
        
        # Create upload directory if it doesn't exist
        upload_folder = os.path.join('static', 'uploads', 'normal_profiles', 'profile_photos')
        os.makedirs(upload_folder, exist_ok=True)
        
        file_path = os.path.join(upload_folder, unique_filename)
        file.save(file_path)
        
        # Update database
        connection = get_db_connection()
        if connection:
            try:
                cursor = connection.cursor()
                cursor.execute("""
                    UPDATE normal_user_profiles 
                    SET profile_photo = %s 
                    WHERE user_id = %s
                """, (f"uploads/normal_profiles/profile_photos/{unique_filename}", session['user_id']))
                
                connection.commit()
                cursor.close()
                connection.close()
                
                flash('📷 Profile photo updated successfully!', 'success')
            except mysql.connector.Error as err:
                flash('❌ Error saving photo. Please try again.', 'error')
                print(f"Photo upload error: {err}")
        else:
            flash('❌ Database connection error.', 'error')
    else:
        flash('❌ Invalid file type. Please upload JPG, JPEG, PNG files.', 'error')
    
    return redirect(url_for('profile'))

def allowed_file(filename):
    """Check if file extension is allowed"""
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'pdf'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def allowed_identity_file(filename):
    """Check if file extension is allowed for identity proof documents"""
    ALLOWED_EXTENSIONS = {'pdf', 'jpeg', 'jpg', 'png'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/profile-test')
def profile_test():
    return "<h1>Profile Test Route Working!</h1><p>If you see this, Flask routing is working.</p>"

@app.route('/settings')
@login_required
def settings():
    """Settings page for both Normal Users and Doctor Users"""
    # Both user types can access settings
    if session.get('user_type') not in ['normal', 'doctor']:
        flash('Access denied.', 'error')
        return redirect(url_for('index'))

    return render_template('settings.html')

@app.route('/update_email', methods=['POST'])
@login_required
def update_email():
    """Update user email address"""
    if session.get('user_type') not in ['normal', 'doctor']:
        flash('Access denied.', 'error')
        return redirect(url_for('index'))

    new_email = request.form.get('new_email', '').strip().lower()
    current_password = request.form.get('current_password', '')
    user_type = session.get('user_type')
    user_id = session.get('user_id')

    # Validation
    if not new_email or not current_password:
        flash('❌ Please fill in all fields.', 'error')
        return redirect(url_for('settings'))

    # Email format validation
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_pattern, new_email):
        flash('❌ Please enter a valid email address.', 'error')
        return redirect(url_for('settings'))

    # Check if new email is same as current
    if new_email == session.get('user_email'):
        flash('⚠️ The new email is the same as your current email.', 'warning')
        return redirect(url_for('settings'))

    connection = get_db_connection()
    if not connection:
        flash('❌ Database connection error. Please try again.', 'error')
        return redirect(url_for('settings'))

    try:
        cursor = connection.cursor(dictionary=True)

        # Get current user data and verify password
        if user_type == 'normal':
            cursor.execute("SELECT * FROM normal_users WHERE id = %s", (user_id,))
        else:
            cursor.execute("SELECT * FROM doctor_users WHERE id = %s", (user_id,))

        user_data = cursor.fetchone()

        if not user_data or not check_password_hash(user_data['password'], current_password):
            flash('❌ Current password is incorrect.', 'error')
            cursor.close()
            connection.close()
            return redirect(url_for('settings'))

        # Check if new email already exists
        if user_type == 'normal':
            cursor.execute("SELECT id FROM normal_users WHERE email = %s AND id != %s", (new_email, user_id))
        else:
            cursor.execute("SELECT id FROM doctor_users WHERE email = %s AND id != %s", (new_email, user_id))

        existing_user = cursor.fetchone()
        if existing_user:
            flash('❌ This email address is already registered with another account.', 'error')
            cursor.close()
            connection.close()
            return redirect(url_for('settings'))

        # Also check in the other user type table
        if user_type == 'normal':
            cursor.execute("SELECT id FROM doctor_users WHERE email = %s", (new_email,))
        else:
            cursor.execute("SELECT id FROM normal_users WHERE email = %s", (new_email,))

        cross_existing_user = cursor.fetchone()
        if cross_existing_user:
            flash('❌ This email address is already registered with another account.', 'error')
            cursor.close()
            connection.close()
            return redirect(url_for('settings'))

        # Update email in main user table
        if user_type == 'normal':
            cursor.execute("""
                UPDATE normal_users 
                SET email = %s, updated_at = CURRENT_TIMESTAMP 
                WHERE id = %s
            """, (new_email, user_id))

            # Also update in user_profiles if exists
            cursor.execute("""
                UPDATE user_profiles 
                SET email_id = %s 
                WHERE user_id = %s
            """, (new_email, user_id))
        else:
            cursor.execute("""
                UPDATE doctor_users 
                SET email = %s, updated_at = CURRENT_TIMESTAMP 
                WHERE id = %s
            """, (new_email, user_id))

        connection.commit()
        cursor.close()
        connection.close()

        # Update session
        session['user_email'] = new_email

        flash('✅ Email address updated successfully! Please log in again for security.', 'success')

        # Optional: Force logout for security
        # return redirect(url_for('logout'))

        return redirect(url_for('settings'))

    except mysql.connector.Error as err:
        flash('❌ Error updating email. Please try again.', 'error')
        print(f"Email update error: {err}")
        if cursor:
            cursor.close()
        if connection:
            connection.close()
        return redirect(url_for('settings'))

@app.route('/update_password', methods=['POST'])
@login_required
def update_password():
    """Update user password"""
    if session.get('user_type') not in ['normal', 'doctor']:
        flash('Access denied.', 'error')
        return redirect(url_for('index'))

    current_password = request.form.get('current_password', '')
    new_password = request.form.get('new_password', '')
    confirm_password = request.form.get('confirm_password', '')
    user_type = session.get('user_type')
    user_id = session.get('user_id')

    # Validation
    if not current_password or not new_password or not confirm_password:
        flash('❌ Please fill in all fields.', 'error')
        return redirect(url_for('settings'))

    if new_password != confirm_password:
        flash('❌ New passwords do not match.', 'error')
        return redirect(url_for('settings'))

    # Password strength validation
    if not validate_password_strength(new_password):
        flash('❌ Password does not meet requirements. Please use at least 8 characters with uppercase, lowercase, numbers, and special characters.', 'error')
        return redirect(url_for('settings'))

    # Check if new password is same as current
    if current_password == new_password:
        flash('⚠️ New password must be different from current password.', 'warning')
        return redirect(url_for('settings'))

    connection = get_db_connection()
    if not connection:
        flash('❌ Database connection error. Please try again.', 'error')
        return redirect(url_for('settings'))

    try:
        cursor = connection.cursor(dictionary=True)

        # Get current user data and verify current password
        if user_type == 'normal':
            cursor.execute("SELECT * FROM normal_users WHERE id = %s", (user_id,))
        else:
            cursor.execute("SELECT * FROM doctor_users WHERE id = %s", (user_id,))

        user_data = cursor.fetchone()

        if not user_data or not check_password_hash(user_data['password'], current_password):
            flash('❌ Current password is incorrect.', 'error')
            cursor.close()
            connection.close()
            return redirect(url_for('settings'))

        # Hash new password
        hashed_password = generate_password_hash(new_password)

        # Update password
        if user_type == 'normal':
            cursor.execute("""
                UPDATE normal_users 
                SET password = %s, updated_at = CURRENT_TIMESTAMP 
                WHERE id = %s
            """, (hashed_password, user_id))
        else:
            cursor.execute("""
                UPDATE doctor_users 
                SET password = %s, updated_at = CURRENT_TIMESTAMP 
                WHERE id = %s
            """, (hashed_password, user_id))

        connection.commit()
        cursor.close()
        connection.close()

        flash('✅ Password updated successfully! Please log in again with your new password.', 'success')

        # Force logout for security
        session.clear()
        return redirect(url_for('signin'))

    except mysql.connector.Error as err:
        flash('❌ Error updating password. Please try again.', 'error')
        print(f"Password update error: {err}")
        if cursor:
            cursor.close()
        if connection:
            connection.close()
        return redirect(url_for('settings'))

def validate_password_strength(password):
    """Validate password strength requirements"""
    if len(password) < 8:
        return False

    # Check for uppercase letter
    if not re.search(r'[A-Z]', password):
        return False

    # Check for lowercase letter
    if not re.search(r'[a-z]', password):
        return False

    # Check for digit
    if not re.search(r'\d', password):
        return False

    # Check for special character
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False

    return True

# Enhanced login_required decorator (if not already exists)
def login_required(f):
    from functools import wraps

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('🔐 Please log in to access this page.', 'error')
            return redirect(url_for('signin'))
        return f(*args, **kwargs)
    return decorated_function

# FLASK ROUTES FOR DOCTOR PROFILE SYSTEM
# Add these routes to your app.py file

@app.route('/doctor_profile')
@login_required
def doctor_profile():
    """Doctor profile page with verification status sync"""
    if session.get('user_type') != 'doctor':
        flash('Access denied. This page is only for doctors.', 'error')
        return redirect(url_for('index'))

    connection = get_db_connection()
    if not connection:
        flash('Database connection error. Please try again.', 'error')
        return redirect(url_for('doctor_dashboard'))

    try:
        cursor = connection.cursor(dictionary=True)

        # Use dp.user_id to join and filter
        cursor.execute("""
            SELECT dp.*, 
                   du.verification_status, 
                   du.verified_at, 
                   du.verified_by,
                   admin.full_name AS verified_by_admin
            FROM doctor_user_profiles dp
            LEFT JOIN doctor_users du ON dp.user_id = du.id
            LEFT JOIN admin_users admin ON du.verified_by = admin.id
            WHERE dp.user_id = %s
        """, (session['user_id'],))

        profile = cursor.fetchone()

        if not profile:
            # Insert using user_id, not dp.id
            cursor.execute("""
                INSERT INTO doctor_user_profiles (user_id, full_name, email_id, country) 
                VALUES (%s, %s, %s, %s)
            """, (session['user_id'], session['user_name'], session['user_email'], 'India'))

            connection.commit()

            # Re-fetch with correct join
            cursor.execute("""
                SELECT dp.*, 
                       du.verification_status, 
                       du.verified_at, 
                       du.verified_by,
                       admin.full_name AS verified_by_admin
                FROM doctor_user_profiles dp
                LEFT JOIN doctor_users du ON dp.user_id = du.id
                LEFT JOIN admin_users admin ON du.verified_by = admin.id
                WHERE dp.user_id = %s
            """, (session['user_id'],))

            profile = cursor.fetchone()

        cursor.close()
        connection.close()

        return render_template('doctor_profile.html', profile=profile)

    except Exception as err:
        flash('Error loading profile. Please try again.', 'error')
        print(f"Doctor profile error: {err}")
        return redirect(url_for('doctor_dashboard'))

@app.route('/doctor_profile/update', methods=['POST'])
@login_required
def update_doctor_profile():
    """Update doctor profile with professional fields and file uploads"""
    if session.get('user_type') != 'doctor':
        flash('Access denied.', 'error')
        return redirect(url_for('index'))

    connection = get_db_connection()
    if not connection:
        flash('Database connection error. Please try again.', 'error')
        return redirect(url_for('doctor_profile'))

    try:
        cursor = connection.cursor(dictionary=True)

        # Get current profile to check restrictions
        cursor.execute("""
            SELECT identity_proof_type, identity_proof_number, identity_proof_file, qualification_proof
            FROM doctor_user_profiles 
            WHERE user_id = %s
        """, (session['user_id'],))

        current_profile = cursor.fetchone()

        # Get form data - Personal Information
        full_name = request.form.get('full_name', '').strip()
        mobile_number = request.form.get('mobile_number', '').strip()
        gender = request.form.get('gender')
        blood_group = request.form.get('blood_group')
        marital_status = request.form.get('marital_status')
        date_of_birth = request.form.get('date_of_birth')

        # Professional Information
        specialty = request.form.get('specialty', '').strip()
        qualification = request.form.get('qualification', '').strip()
        experience = request.form.get('experience')
        consultant_fee = request.form.get('consultant_fee')

        # Address Information
        address = request.form.get('address', '').strip()
        city = request.form.get('city', '').strip()
        state = request.form.get('state', '').strip()
        country = request.form.get('country', 'India').strip()
        pincode = request.form.get('pincode', '').strip()
        emergency_contact_name = request.form.get('emergency_contact_name', '').strip()

        # Identity proof (restricted fields)
        identity_proof_type = request.form.get('identity_proof_type')
        identity_proof_number = request.form.get('identity_proof_number', '').strip()

        # Handle file uploads
        qualification_proof_path = None
        identity_proof_file_path = None

        # Qualification Proof Upload
        if 'qualification_proof' in request.files:
            file = request.files['qualification_proof']

            if file and file.filename and (not current_profile or not current_profile['qualification_proof']):
                if allowed_document_file(file.filename):
                    if file.content_length and file.content_length > 10 * 1024 * 1024:
                        flash('❌ Qualification file size too large. Please upload files smaller than 10MB.', 'error')
                        return redirect(url_for('doctor_profile'))

                    filename = secure_filename(file.filename)
                    file_extension = filename.rsplit('.', 1)[1].lower()
                    unique_filename = f"qualification_{session['user_id']}_{uuid.uuid4().hex[:8]}.{file_extension}"

                    # Upload to doctor profiles documents directory
                    upload_folder = os.path.join('static', 'uploads', 'doctor_profiles', 'documents')
                    os.makedirs(upload_folder, exist_ok=True)

                    file_path = os.path.join(upload_folder, unique_filename)

                    try:
                        file.save(file_path)
                        qualification_proof_path = f"uploads/doctor_profiles/documents/{unique_filename}"
                        flash('📎 Qualification document uploaded successfully!', 'success')
                    except Exception as e:
                        flash('❌ Error saving qualification file. Please try again.', 'error')
                        print(f"Qualification file upload error: {e}")
                        return redirect(url_for('doctor_profile'))

                else:
                    flash('❌ Invalid file type for qualification. Please upload PDF, JPEG, JPG, or PNG files only.', 'error')
                    return redirect(url_for('doctor_profile'))

            elif current_profile and current_profile['qualification_proof'] and file and file.filename:
                flash('❌ Qualification document cannot be changed once uploaded.', 'error')
                return redirect(url_for('doctor_profile'))

        # Identity Proof Upload
        if 'identity_proof_file' in request.files:
            file = request.files['identity_proof_file']

            if file and file.filename and (not current_profile or not current_profile['identity_proof_file']):
                if allowed_document_file(file.filename):
                    if file.content_length and file.content_length > 10 * 1024 * 1024:
                        flash('❌ Identity file size too large. Please upload files smaller than 10MB.', 'error')
                        return redirect(url_for('doctor_profile'))

                    filename = secure_filename(file.filename)
                    file_extension = filename.rsplit('.', 1)[1].lower()
                    unique_filename = f"identity_{session['user_id']}_{uuid.uuid4().hex[:8]}.{file_extension}"

                    upload_folder = os.path.join('static', 'uploads', 'doctor_profiles', 'documents')
                    os.makedirs(upload_folder, exist_ok=True)

                    file_path = os.path.join(upload_folder, unique_filename)

                    try:
                        file.save(file_path)
                        identity_proof_file_path = f"uploads/doctor_profiles/documents/{unique_filename}"
                        flash('📎 Identity document uploaded successfully!', 'success')
                    except Exception as e:
                        flash('❌ Error saving identity file. Please try again.', 'error')
                        print(f"Identity file upload error: {e}")
                        return redirect(url_for('doctor_profile'))

                else:
                    flash('❌ Invalid file type for identity. Please upload PDF, JPEG, JPG, or PNG files only.', 'error')
                    return redirect(url_for('doctor_profile'))

            elif current_profile and current_profile['identity_proof_file'] and file and file.filename:
                flash('❌ Identity proof document cannot be changed once uploaded.', 'error')
                return redirect(url_for('doctor_profile'))

        # Validation
        if not full_name:
            flash('Full name is required.', 'error')
            return redirect(url_for('doctor_profile'))

        if not specialty:
            flash('Medical specialty is required.', 'error')
            return redirect(url_for('doctor_profile'))

        if not qualification:
            flash('Qualification is required.', 'error')
            return redirect(url_for('doctor_profile'))

        if not experience or int(experience) < 0:
            flash('Valid experience is required.', 'error')
            return redirect(url_for('doctor_profile'))

        if not consultant_fee or float(consultant_fee) <= 0:
            flash('Valid consultation fee is required.', 'error')
            return redirect(url_for('doctor_profile'))

        # Validate mobile number format if provided
        if mobile_number:
            import re
            mobile_pattern = r'^[+]?[0-9\s\-\(\)]{10,15}$'
            clean_mobile = mobile_number.replace(' ', '').replace('-', '').replace('(', '').replace(')', '')
            if not re.match(mobile_pattern, mobile_number) or len(clean_mobile.replace('+', '')) < 10:
                flash('Please enter a valid mobile number (minimum 10 digits).', 'error')
                return redirect(url_for('doctor_profile'))

        # Check if identity proof is being changed when already set
        if current_profile:
            if (current_profile['identity_proof_type'] and 
                identity_proof_type and 
                current_profile['identity_proof_type'] != identity_proof_type):
                flash('Identity proof type cannot be changed once submitted.', 'error')
                return redirect(url_for('doctor_profile'))

            if (current_profile['identity_proof_number'] and 
                identity_proof_number and 
                current_profile['identity_proof_number'] != identity_proof_number):
                flash('Identity proof number cannot be changed once submitted.', 'error')
                return redirect(url_for('doctor_profile'))

        # Prepare update query
        update_fields = []
        update_values = []

        # Always updatable fields
        update_fields.extend([
            'full_name = %s', 'mobile_number = %s', 'gender = %s', 'blood_group = %s', 
            'marital_status = %s', 'date_of_birth = %s', 'address = %s', 'city = %s', 
            'state = %s', 'country = %s', 'pincode = %s', 'emergency_contact_name = %s', 
            'specialty = %s', 'qualification = %s',
            'experience = %s', 'consultant_fee = %s'
        ])
        update_values.extend([
            full_name, mobile_number, gender, blood_group, marital_status, 
            date_of_birth or None, address, city, state, country, pincode, 
            emergency_contact_name, specialty, qualification,
            int(experience), float(consultant_fee)
        ])

        # Add identity proof only if not already set
        if not current_profile or not current_profile['identity_proof_type']:
            if identity_proof_type:
                update_fields.extend(['identity_proof_type = %s', 'identity_proof_number = %s'])
                update_values.extend([identity_proof_type, identity_proof_number])

        # Add file paths if uploaded
        if qualification_proof_path:
            update_fields.append('qualification_proof = %s')
            update_values.append(qualification_proof_path)

        if identity_proof_file_path:
            update_fields.append('identity_proof_file = %s')
            update_values.append(identity_proof_file_path)

        # Check profile completion
        is_complete = all([
            full_name, specialty, qualification, experience, consultant_fee,
            address, city, state, country, pincode
        ])
        update_fields.append('is_profile_complete = %s')
        update_values.append(is_complete)

        # Add doctor_id for WHERE clause
        update_values.append(session['user_id'])

        # Execute update
        update_query = f"""
            UPDATE doctor_user_profiles 
            SET {', '.join(update_fields)}
            WHERE user_id = %s
        """

        cursor.execute(update_query, update_values)
        connection.commit()

        # Update session name if changed
        if full_name != session.get('user_name'):
            session['user_name'] = full_name

            # Also update in doctor_users table
            cursor.execute("""
                UPDATE doctor_users 
                SET name = %s 
                WHERE id = %s
            """, (full_name, session['user_id']))
            connection.commit()

        cursor.close()
        connection.close()

        # Enhanced success message
        completion_status = "complete" if is_complete else "incomplete"
        flash(f'✅ Doctor profile updated successfully! Your profile is now {completion_status}.', 'success')

        return redirect(url_for('doctor_profile'))

    except Exception as err:
        flash('❌ Error updating profile. Please try again.', 'error')
        print(f"Doctor profile update error: {err}")
        return redirect(url_for('doctor_profile'))

@app.route('/doctor_profile/upload-photo', methods=['POST'])
@login_required
def upload_doctor_photo():
    """Upload doctor profile photo"""
    if session.get('user_type') != 'doctor':
        flash('Access denied.', 'error')
        return redirect(url_for('index'))

    if 'profile_photo' not in request.files:
        flash('No file selected.', 'error')
        return redirect(url_for('doctor_profile'))

    file = request.files['profile_photo']

    if file.filename == '':
        flash('No file selected.', 'error')
        return redirect(url_for('doctor_profile'))

    if file and allowed_image_file(file.filename):
        filename = secure_filename(file.filename)

        # Create unique filename
        unique_filename = f"doctor_{session['user_id']}_{uuid.uuid4().hex[:8]}_{filename}"

        # Create upload directory for doctor profiles
        upload_folder = os.path.join('static', 'uploads', 'doctor_profiles', 'profile_photos')
        os.makedirs(upload_folder, exist_ok=True)

        file_path = os.path.join(upload_folder, unique_filename)
        file.save(file_path)

        # Update database
        connection = get_db_connection()
        if connection:
            try:
                cursor = connection.cursor()
                cursor.execute("""
                    UPDATE doctor_user_profiles 
                    SET profile_photo = %s 
                    WHERE user_id = %s
                """, (f"uploads/doctor_profiles/profile_photos/{unique_filename}", session['user_id']))

                connection.commit()
                cursor.close()
                connection.close()

                flash('📷 Profile photo updated successfully!', 'success')
            except mysql.connector.Error as err:
                flash('❌ Error saving photo. Please try again.', 'error')
                print(f"Doctor photo upload error: {err}")
        else:
            flash('❌ Database connection error.', 'error')
    else:
        flash('❌ Invalid file type. Please upload JPG, JPEG, PNG, or GIF files.', 'error')

    return redirect(url_for('doctor_profile'))

def allowed_image_file(filename):
    """Check if file extension is allowed for profile photos"""
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def allowed_document_file(filename):
    """Check if file extension is allowed for documents"""
    ALLOWED_EXTENSIONS = {'pdf', 'jpeg', 'jpg', 'png'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Function to get doctor profile photo (for navbar/sidebar)
def get_doctor_profile_photo(user_id):
    """Get doctor's profile photo for display"""
    if not user_id:
        return None

    try:
        connection = get_db_connection()
        if not connection:
            return None

        cursor = connection.cursor(dictionary=True)
        cursor.execute("""
            SELECT profile_photo 
            FROM doctor_user_profiles 
            WHERE user_id = %s
        """, (user_id,))

        result = cursor.fetchone()
        cursor.close()
        connection.close()

        if result and result['profile_photo']:
            return result['profile_photo']
        return None

    except Exception as e:
        print(f"Error fetching doctor profile photo: {e}")
        return None

# Register the function as Jinja2 global (add this after your app initialization)
app.jinja_env.globals.update(get_doctor_profile_photo=get_doctor_profile_photo)

@app.route('/ai-chat')
@login_required
def ai_chat():
    """AI Chat page for both user types"""
    user_type = session.get('user_type', 'normal')
    
    if user_type == 'normal':
        return render_template('ai_chat.html', 
                             chat_title="AI Health Assistant",
                             user_type=user_type,
                             welcome_message="Hello! I'm your AI Health Assistant. Ask me about health, medicines, symptoms, or wellness tips.")
    else:
        return render_template('ai_chat.html', 
                             chat_title="AI Medical Assistant",
                             user_type=user_type,
                             welcome_message="Hello Doctor! I'm your AI Medical Assistant. I can help with medical research, diagnosis support, and treatment options.")

@app.route('/ai-chat/send', methods=['POST'])
@login_required
def send_ai_message():
    """Send message to AI and get response"""
    try:
        data = request.get_json()
        user_message = data.get('message', '').strip()
        user_type = session.get('user_type', 'normal')
        
        if not user_message:
            return jsonify({'error': 'Message is required'}), 400
        
        # Create context-aware prompt
        system_prompt = get_system_prompt(user_type)
        full_prompt = f"{system_prompt}\n\nUser: {user_message}\nAssistant:"
        
        # Call Ollama API
        ollama_response = call_ollama(full_prompt)
        
        if ollama_response:
            # Save to database
            save_chat_message(session['user_id'], user_type, user_message, ollama_response)
            
            return jsonify({
                'response': ollama_response,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            })
        else:
            return jsonify({'error': 'AI service unavailable. Please try again.'}), 500
            
    except Exception as e:
        print(f"AI Chat error: {e}")
        return jsonify({'error': 'Something went wrong. Please try again.'}), 500

def call_ollama(prompt):
    """Call Ollama API with the prompt"""
    try:
        url = "http://localhost:11434/api/generate"
        
        payload = {
            "model": "llama3.2:3b",
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0.7,
                "top_p": 0.9,
                "max_tokens": 2000
            }
        }
        
        response = requests.post(url, json=payload, timeout=60)
        
        if response.status_code == 200:
            result = response.json()
            return result.get('response', '').strip()
        else:
            print(f"Ollama API error: {response.status_code}")
            return None
            
    except Exception as e:
        print(f"Ollama connection error: {e}")
        return None

def get_system_prompt(user_type):
    """Get appropriate system prompt based on user type"""
    if user_type == 'doctor':
        return """You are an AI Medical Assistant helping healthcare professionals. You provide:
        - Evidence-based medical information
        - Differential diagnosis support
        - Treatment option suggestions
        - Latest medical research insights
        - Drug interactions and contraindications
        - Clinical guidelines and protocols
        
        Always remind doctors to use clinical judgment and verify information. Focus on Ayurvedic and modern medicine integration."""
    else:
        return """You are an AI Health Assistant for patients. You provide:
        - General health information and wellness tips
        - Basic symptom information (not diagnosis)
        - Healthy lifestyle suggestions
        - Nutrition and exercise advice
        - Medicine information and basic uses
        - When to seek medical attention
        
        Always remind users to consult healthcare professionals for medical advice. Focus on Ayurvedic wellness and preventive care."""

def save_chat_message(user_id, user_type, message, response):
    """Save chat message to database"""
    try:
        connection = get_db_connection()
        cursor = connection.cursor()
        
        cursor.execute("""
            INSERT INTO ai_chat_history (user_id, user_type, message, response, created_at)
            VALUES (%s, %s, %s, %s, %s)
        """, (user_id, user_type, message, response, datetime.now()))
        
        connection.commit()
        cursor.close()
        connection.close()
        
    except Exception as e:
        print(f"Save chat error: {e}")


@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    """Admin login page"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            flash('Please enter both username and password.', 'error')
            return render_template('admin/admin_login.html')

        connection = get_db_connection()
        if connection:
            try:
                cursor = connection.cursor(dictionary=True)
                cursor.execute("""
                    SELECT id, username, email, password_hash, full_name, role, is_active
                    FROM admin_users 
                    WHERE (username = %s OR email = %s) AND is_active = TRUE
                """, (username, username))

                admin = cursor.fetchone()

                if admin and check_password_hash(admin['password_hash'], password):
                    # Update last login
                    cursor.execute("""
                        UPDATE admin_users SET last_login = %s WHERE id = %s
                    """, (datetime.now(), admin['id']))
                    connection.commit()

                    # Set session
                    session['admin_id'] = admin['id']
                    session['admin_username'] = admin['username']
                    session['admin_name'] = admin['full_name']
                    session['admin_role'] = admin['role']

                    flash('Welcome to Admin Panel!', 'success')
                    return redirect(url_for('admin_dashboard'))
                else:
                    flash('Invalid credentials.', 'error')

                cursor.close()
                connection.close()

            except Exception as e:
                print(f"Admin login error: {e}")
                flash('Login failed. Please try again.', 'error')

    return render_template('admin/admin_login.html')

@app.route('/admin/medicines')
@admin_required
def admin_medicines():
    """Display all medicines with management options"""
    connection = get_db_connection()
    if not connection:
        flash('Database connection error.', 'error')
        return redirect(url_for('admin_dashboard'))
    
    try:
        cursor = connection.cursor(dictionary=True)
        
        # Get search and filter parameters
        search = request.args.get('search', '').strip()
        category = request.args.get('category', '')
        status = request.args.get('status', '')
        sort_by = request.args.get('sort', 'name')
        page = int(request.args.get('page', 1))
        per_page = 20
        
        # Build query conditions
        where_conditions = []
        params = []
        
        if search:
            where_conditions.append("(name LIKE %s OR manufacturer LIKE %s OR generic_name LIKE %s)")
            search_term = f"%{search}%"
            params.extend([search_term, search_term, search_term])
        
        if category:
            where_conditions.append("category = %s")
            params.append(category)
        
        # ✅ FIXED: Use 1/0 instead of TRUE/FALSE
        if status == 'active':
            where_conditions.append("is_active = 1")
        elif status == 'inactive':
            where_conditions.append("is_active = 0")
        elif status == 'low_stock':
            where_conditions.append("stock_quantity < 20")
        
        where_clause = " WHERE " + " AND ".join(where_conditions) if where_conditions else ""
        
        # Sorting options
        order_by = {
            'name': 'name ASC',
            'manufacturer': 'manufacturer ASC', 
            'price': 'price DESC',
            'stock': 'stock_quantity ASC',
            'created': 'created_at DESC'
        }.get(sort_by, 'name ASC')
        
        # Count total medicines
        count_query = f"SELECT COUNT(*) as total FROM medicines {where_clause}"
        cursor.execute(count_query, params)
        total_medicines = cursor.fetchone()['total']
        
        # Calculate pagination
        offset = (page - 1) * per_page
        total_pages = (total_medicines + per_page - 1) // per_page
        
        # ✅ FIXED: Explicit column selection
        medicines_query = f"""
            SELECT 
                id, name, manufacturer, generic_name, category,
                price, stock_quantity, medicine_image,
                prescription_required, is_active, created_at,
                expiry_date, batch_number
            FROM medicines 
            {where_clause}
            ORDER BY {order_by}
            LIMIT %s OFFSET %s
        """
        cursor.execute(medicines_query, params + [per_page, offset])
        medicines = cursor.fetchall()
        
        # Get categories for filter
        cursor.execute("SELECT DISTINCT category FROM medicines WHERE category IS NOT NULL ORDER BY category")
        categories = [row['category'] for row in cursor.fetchall()]
        
        # ✅ FIXED: Use 1/0 for boolean comparisons  
        cursor.execute("""
            SELECT 
                COUNT(*) as total_medicines,
                SUM(CASE WHEN is_active = 1 THEN 1 ELSE 0 END) as active_medicines,
                SUM(CASE WHEN stock_quantity < 20 THEN 1 ELSE 0 END) as low_stock_medicines,
                SUM(CASE WHEN stock_quantity = 0 THEN 1 ELSE 0 END) as out_of_stock,
                SUM(CASE WHEN prescription_required = 1 THEN 1 ELSE 0 END) as prescription_medicines
            FROM medicines
        """)
        stats = cursor.fetchone()
        
        cursor.close()
        connection.close()
        
        return render_template('admin/medicines.html',
                             medicines=medicines,
                             categories=categories,
                             stats=stats,
                             search=search,
                             category=category,
                             status=status,
                             sort_by=sort_by,
                             page=page,
                             total_pages=total_pages,
                             total_medicines=total_medicines)
        
    except Exception as e:
        print(f"Admin medicines error: {e}")
        flash('Error loading medicines.', 'error')
        return redirect(url_for('admin_dashboard'))

### **2. Add New Medicine**
@app.route('/admin/medicines/add', methods=['GET', 'POST'])
@admin_required
def admin_add_medicine():
    """Add new medicine"""
    if request.method == 'GET':
        return render_template('admin/add_medicine.html')

    try:
        # Get form data
        name = request.form.get('name', '').strip()
        manufacturer = request.form.get('manufacturer', '').strip()
        generic_name = request.form.get('generic_name', '').strip()
        description = request.form.get('description', '').strip()
        category = request.form.get('category', '').strip()
        price = float(request.form.get('price', 0))
        stock_quantity = int(request.form.get('stock_quantity', 0))
        dosage = request.form.get('dosage', '').strip()
        ingredients = request.form.get('ingredients', '').strip()
        usage_instructions = request.form.get('usage_instructions', '').strip()
        side_effects = request.form.get('side_effects', '').strip()
        warnings = request.form.get('warnings', '').strip()
        prescription_required = 'prescription_required' in request.form
        batch_number = request.form.get('batch_number', '').strip()
        expiry_date = request.form.get('expiry_date')

        # Validation
        if not name or not manufacturer or price <= 0:
            flash('Name, manufacturer, and valid price are required.', 'error')
            return redirect(request.url)

        # Handle file upload
        medicine_image = None
        if 'medicine_image' in request.files:
            file = request.files['medicine_image']
            if file and file.filename:
                medicine_image = save_medicine_image(file, name)

        connection = get_db_connection()
        cursor = connection.cursor()

        # Insert medicine
        cursor.execute("""
            INSERT INTO medicines (
                name, manufacturer, generic_name, description, category,
                price, stock_quantity, dosage, ingredients, usage_instructions,
                side_effects, warnings, prescription_required, batch_number,
                expiry_date, medicine_image, is_active
            ) VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s, %s, TRUE
            )
        """, (
            name, manufacturer, generic_name, description, category,
            price, stock_quantity, dosage, ingredients, usage_instructions,
            side_effects, warnings, prescription_required, batch_number,
            expiry_date if expiry_date else None, medicine_image
        ))

        medicine_id = cursor.lastrowid
        connection.commit()

        # Log admin activity
        log_admin_activity(
            session['admin_id'],
            'MEDICINE_ADDED',
            'medicine',
            medicine_id,
            {'name': name, 'manufacturer': manufacturer, 'price': price}
        )

        cursor.close()
        connection.close()

        flash(f'Medicine "{name}" added successfully!', 'success')
        return redirect(url_for('admin_medicines'))

    except Exception as e:
        print(f"Add medicine error: {e}")
        flash('Error adding medicine.', 'error')
        return redirect(url_for('admin_medicines'))

### **3. Edit Medicine**
@app.route('/admin/medicines/<int:medicine_id>/edit', methods=['GET', 'POST'])
@admin_required
def admin_edit_medicine(medicine_id):
    """Edit existing medicine"""
    connection = get_db_connection()
    if not connection:
        flash('Database connection error.', 'error')
        return redirect(url_for('admin_medicines'))

    try:
        cursor = connection.cursor(dictionary=True)

        # Get medicine data
        cursor.execute("SELECT * FROM medicines WHERE id = %s", (medicine_id,))
        medicine = cursor.fetchone()

        if not medicine:
            flash('Medicine not found.', 'error')
            return redirect(url_for('admin_medicines'))

        if request.method == 'GET':
            cursor.close()
            connection.close()
            return render_template('admin/edit_medicine.html', medicine=medicine)

        # Handle POST - Update medicine
        name = request.form.get('name', '').strip()
        manufacturer = request.form.get('manufacturer', '').strip()
        generic_name = request.form.get('generic_name', '').strip()
        description = request.form.get('description', '').strip()
        category = request.form.get('category', '').strip()
        price = float(request.form.get('price', 0))
        stock_quantity = int(request.form.get('stock_quantity', 0))
        dosage = request.form.get('dosage', '').strip()
        ingredients = request.form.get('ingredients', '').strip()
        usage_instructions = request.form.get('usage_instructions', '').strip()
        side_effects = request.form.get('side_effects', '').strip()
        warnings = request.form.get('warnings', '').strip()
        prescription_required = 'prescription_required' in request.form
        batch_number = request.form.get('batch_number', '').strip()
        expiry_date = request.form.get('expiry_date')
        is_active = 'is_active' in request.form

        # Validation
        if not name or not manufacturer or price <= 0:
            flash('Name, manufacturer, and valid price are required.', 'error')
            return redirect(request.url)

        # Handle image update
        medicine_image = medicine['medicine_image']  # Keep existing
        if 'medicine_image' in request.files:
            file = request.files['medicine_image']
            if file and file.filename:
                medicine_image = save_medicine_image(file, name)

        # Update medicine
        cursor.execute("""
            UPDATE medicines SET
                name = %s, manufacturer = %s, generic_name = %s,
                description = %s, category = %s, price = %s,
                stock_quantity = %s, dosage = %s, ingredients = %s,
                usage_instructions = %s, side_effects = %s, warnings = %s,
                prescription_required = %s, batch_number = %s,
                expiry_date = %s, medicine_image = %s, is_active = %s,
                updated_at = NOW()
            WHERE id = %s
        """, (
            name, manufacturer, generic_name, description, category, price,
            stock_quantity, dosage, ingredients, usage_instructions,
            side_effects, warnings, prescription_required, batch_number,
            expiry_date if expiry_date else None, medicine_image, is_active,
            medicine_id
        ))

        connection.commit()

        # Log activity
        log_admin_activity(
            session['admin_id'],
            'MEDICINE_UPDATED',
            'medicine',
            medicine_id,
            {'name': name, 'changes': 'Updated medicine details'}
        )

        cursor.close()
        connection.close()

        flash(f'Medicine "{name}" updated successfully!', 'success')
        return redirect(url_for('admin_medicines'))

    except Exception as e:
        print(f"Edit medicine error: {e}")
        flash('Error updating medicine.', 'error')
        return redirect(url_for('admin_medicines'))

### **4. Delete Medicine**
@app.route('/admin/medicines/<int:medicine_id>/delete', methods=['POST'])
@admin_required
def admin_delete_medicine(medicine_id):
    """Delete medicine (soft delete by setting is_active = False)"""
    connection = get_db_connection()
    if not connection:
        flash('Database connection error.', 'error')
        return redirect(url_for('admin_medicines'))

    try:
        cursor = connection.cursor(dictionary=True)

        # Get medicine info for logging
        cursor.execute("SELECT name, manufacturer FROM medicines WHERE id = %s", (medicine_id,))
        medicine = cursor.fetchone()

        if not medicine:
            flash('Medicine not found.', 'error')
            return redirect(url_for('admin_medicines'))

        # Soft delete (set is_active = False)
        cursor.execute("UPDATE medicines SET is_active = FALSE WHERE id = %s", (medicine_id,))
        connection.commit()

        # Log activity
        log_admin_activity(
            session['admin_id'],
            'MEDICINE_DELETED',
            'medicine',
            medicine_id,
            {'name': medicine['name'], 'manufacturer': medicine['manufacturer']}
        )

        cursor.close()
        connection.close()

        flash(f'Medicine "{medicine["name"]}" deleted successfully!', 'success')
        return redirect(url_for('admin_medicines'))

    except Exception as e:
        print(f"Delete medicine error: {e}")
        flash('Error deleting medicine.', 'error')
        return redirect(url_for('admin_medicines'))

### **5. Bulk Stock Update**
@app.route('/admin/medicines/bulk-stock', methods=['POST'])
@admin_required
def admin_bulk_stock_update():
    """Bulk update medicine stock quantities"""
    try:
        updates = request.json.get('updates', [])

        if not updates:
            return jsonify({'success': False, 'message': 'No updates provided'})

        connection = get_db_connection()
        cursor = connection.cursor()

        updated_count = 0
        for update in updates:
            medicine_id = int(update.get('id'))
            new_stock = int(update.get('stock', 0))

            if new_stock >= 0:
                cursor.execute(
                    "UPDATE medicines SET stock_quantity = %s WHERE id = %s",
                    (new_stock, medicine_id)
                )
                updated_count += 1

        connection.commit()
        cursor.close()
        connection.close()

        # Log bulk activity
        log_admin_activity(
            session['admin_id'],
            'BULK_STOCK_UPDATE',
            'medicine',
            None,
            {'updated_count': updated_count}
        )

        return jsonify({'success': True, 'message': f'{updated_count} medicines updated'})

    except Exception as e:
        print(f"Bulk stock update error: {e}")
        return jsonify({'success': False, 'message': 'Error updating stock'})

### **6. Medicine Analytics**
@app.route('/admin/medicines/analytics')
@admin_required
def admin_medicine_analytics():
    """Medicine analytics and reports"""
    connection = get_db_connection()
    if not connection:
        flash('Database connection error.', 'error')
        return redirect(url_for('admin_medicines'))

    try:
        cursor = connection.cursor(dictionary=True)

        # Overall statistics
        cursor.execute("""
            SELECT 
                COUNT(*) as total_medicines,
                SUM(CASE WHEN is_active = TRUE THEN 1 ELSE 0 END) as active_medicines,
                SUM(CASE WHEN stock_quantity < 20 THEN 1 ELSE 0 END) as low_stock,
                SUM(CASE WHEN stock_quantity = 0 THEN 1 ELSE 0 END) as out_of_stock,
                SUM(CASE WHEN prescription_required = TRUE THEN 1 ELSE 0 END) as prescription_required,
                AVG(price) as avg_price,
                SUM(stock_quantity * price) as total_inventory_value
        """)
        stats = cursor.fetchone()

        # Category breakdown
        cursor.execute("""
            SELECT 
                category,
                COUNT(*) as count,
                AVG(price) as avg_price,
                SUM(stock_quantity) as total_stock
            FROM medicines 
            WHERE is_active = TRUE AND category IS NOT NULL
            GROUP BY category
            ORDER BY count DESC
        """)
        category_stats = cursor.fetchall()

        # Manufacturer breakdown
        cursor.execute("""
            SELECT 
                manufacturer,
                COUNT(*) as medicine_count,
                AVG(price) as avg_price
            FROM medicines 
            WHERE is_active = TRUE
            GROUP BY manufacturer
            ORDER BY medicine_count DESC
            LIMIT 10
        """)
        manufacturer_stats = cursor.fetchall()

        # Low stock medicines
        cursor.execute("""
            SELECT name, manufacturer, stock_quantity, price
            FROM medicines 
            WHERE stock_quantity < 20 AND is_active = TRUE
            ORDER BY stock_quantity ASC
            LIMIT 20
        """)
        low_stock_medicines = cursor.fetchall()

        # Expensive medicines
        cursor.execute("""
            SELECT name, manufacturer, price, category
            FROM medicines 
            WHERE is_active = TRUE
            ORDER BY price DESC
            LIMIT 10
        """)
        expensive_medicines = cursor.fetchall()

        cursor.close()
        connection.close()

        return render_template('admin/medicine_analytics.html',
                             stats=stats,
                             category_stats=category_stats,
                             manufacturer_stats=manufacturer_stats,
                             low_stock_medicines=low_stock_medicines,
                             expensive_medicines=expensive_medicines)

    except Exception as e:
        print(f"Medicine analytics error: {e}")
        flash('Error loading analytics.', 'error')
        return redirect(url_for('admin_medicines'))

### **Helper Functions**
def save_medicine_image(file, medicine_name):
    """Save uploaded medicine image"""
    if not file or not file.filename:
        return None

    try:
        import os
        from werkzeug.utils import secure_filename
        import time

        # Create upload directory
        upload_dir = os.path.join(os.getcwd(), 'static', 'images', 'medicines')
        os.makedirs(upload_dir, exist_ok=True)

        # Generate secure filename
        original_filename = secure_filename(file.filename)
        name, ext = os.path.splitext(original_filename)

        # Create unique filename
        timestamp = int(time.time())
        safe_medicine_name = secure_filename(medicine_name.replace(' ', '_').lower())
        unique_filename = f"{safe_medicine_name}_{timestamp}{ext}"

        # Save file
        file_path = os.path.join(upload_dir, unique_filename)
        file.save(file_path)

        # Return relative path for database
        return f"/static/images/medicines/{unique_filename}"

    except Exception as e:
        print(f"Error saving medicine image: {e}")
        return None

def log_admin_activity(admin_id, action, resource_type, resource_id, details):
    """Log admin activity for medicine management"""
    try:
        connection = get_db_connection()
        cursor = connection.cursor()

        cursor.execute("""
            INSERT INTO admin_activity_log (
                admin_id, action, resource_type, resource_id, details, created_at
            ) VALUES (%s, %s, %s, %s, %s, NOW())
        """, (admin_id, action, resource_type, resource_id, str(details)))

        connection.commit()
        cursor.close()
        connection.close()

    except Exception as e:
        print(f"Error logging admin activity: {e}")

@app.route('/admin/logout')
@admin_required
def admin_logout():
    """Admin logout"""
    session.pop('admin_id', None)
    session.pop('admin_username', None)
    session.pop('admin_name', None)
    session.pop('admin_role', None)
    flash('Logged out successfully.', 'success')
    return redirect(url_for('admin_login'))

@app.route('/admin')
@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    """Admin dashboard with user statistics"""
    connection = get_db_connection()
    if not connection:
        flash('Database connection error.', 'error')
        return redirect(url_for('admin_login'))

    try:
        cursor = connection.cursor(dictionary=True)

        # Get user counts
        cursor.execute("SELECT COUNT(*) as count FROM normal_users WHERE is_active = TRUE")
        normal_users_count = cursor.fetchone()['count']

        cursor.execute("SELECT COUNT(*) as count FROM doctor_users WHERE is_active = TRUE") 
        doctor_users_count = cursor.fetchone()['count']

        cursor.execute("SELECT COUNT(*) as count FROM doctor_users WHERE verification_status = 'pending'")
        pending_verifications = cursor.fetchone()['count']

        # Recent registrations (last 7 days)
        cursor.execute("""
            SELECT COUNT(*) as count FROM normal_users 
            WHERE created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
        """)
        recent_normal_users = cursor.fetchone()['count']

        cursor.execute("""
            SELECT COUNT(*) as count FROM doctor_users 
            WHERE created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
        """)
        recent_doctor_users = cursor.fetchone()['count']

        cursor.close()
        connection.close()

        stats = {
            'normal_users_count': normal_users_count,
            'doctor_users_count': doctor_users_count,
            'total_users': normal_users_count + doctor_users_count,
            'pending_verifications': pending_verifications,
            'recent_normal_users': recent_normal_users,
            'recent_doctor_users': recent_doctor_users
        }

        return render_template('admin/admin_dashboard.html', stats=stats)

    except Exception as e:
        print(f"Admin dashboard error: {e}")
        flash('Error loading dashboard.', 'error')
        return redirect(url_for('admin_login'))

# Normal User Management Routes
@app.route('/admin/normal-users')
@admin_required
def admin_normal_users():
    """Manage normal users"""
    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', '')
    status_filter = request.args.get('status', 'all')

    connection = get_db_connection()
    if not connection:
        flash('Database connection error.', 'error')
        return redirect(url_for('admin_dashboard'))

    try:
        cursor = connection.cursor(dictionary=True)

        # Build query with filters
        where_clauses = []
        params = []

        if search:
            where_clauses.append("(name LIKE %s OR email LIKE %s OR id LIKE %s)")
            params.extend([f"%{search}%", f"%{search}%", f"%{search}%"])

        if status_filter == 'active':
            where_clauses.append("is_active = TRUE AND (banned_until IS NULL OR banned_until < NOW())")
        elif status_filter == 'inactive':
            where_clauses.append("is_active = FALSE")
        elif status_filter == 'banned':
            where_clauses.append("banned_until > NOW()")

        where_sql = " WHERE " + " AND ".join(where_clauses) if where_clauses else ""

        # Get users with pagination
        limit = 20
        offset = (page - 1) * limit

        cursor.execute(f"""
            SELECT id, name, email, is_active, banned_until, 
                   ban_reason, created_at, last_login
            FROM normal_users 
            {where_sql}
            ORDER BY created_at DESC
            LIMIT %s OFFSET %s
        """, params + [limit, offset])

        users = cursor.fetchall()

        # Get total count for pagination
        cursor.execute(f"""
            SELECT COUNT(*) as total FROM normal_users {where_sql}
        """, params)

        total_users = cursor.fetchone()['total']
        total_pages = (total_users + limit - 1) // limit

        cursor.close()
        connection.close()

        return render_template('admin/normal_users.html', 
                             users=users,
                             current_page=page,
                             total_pages=total_pages,
                             search=search,
                             status_filter=status_filter)

    except Exception as e:
        print(f"Admin normal users error: {e}")
        flash('Error loading users.', 'error')
        return redirect(url_for('admin_dashboard'))

@app.route('/admin/normal-users/add', methods=['GET', 'POST'])
@admin_required
def admin_add_normal_user():
    """Add new normal user - CORRECTED VERSION"""
    if request.method == 'POST':
        # Get form data
        email = request.form.get('email', '').strip()
        name = request.form.get('name', '').strip()  # Note: using 'name' to match your form
        password = request.form.get('password', '').strip()

        # Validation
        if not all([email, name, password]):
            flash('All fields are required.', 'error')
            return render_template('admin/add_normal_user.html')

        connection = get_db_connection()
        if connection:
            try:
                cursor = connection.cursor()

                # Check if email already exists
                cursor.execute("SELECT id FROM normal_users WHERE email = %s", (email,))
                if cursor.fetchone():
                    flash('Email already exists.', 'error')
                    cursor.close()
                    connection.close()
                    return render_template('admin/add_normal_user.html')

                # Create password hash
                from werkzeug.security import generate_password_hash
                password_hash = generate_password_hash(password)

                # Insert user - CORRECTED PARAMETER PASSING
                cursor.execute("""
                    INSERT INTO normal_users (email, name, password, is_active, created_by_admin, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s)
                """, (email, name, password_hash, True, True, datetime.now()))

                connection.commit()

                # Log activity
                try:
                    log_admin_activity(session['admin_id'], 'ADD_USER', 'normal', 
                                     cursor.lastrowid, {'email': email, 'name': name})
                except:
                    pass  # Log activity is optional

                cursor.close()
                connection.close()

                flash('Normal user created successfully!', 'success')
                return redirect(url_for('admin_normal_users'))

            except Exception as e:
                print(f"Add normal user error: {e}")
                flash('Error creating user. Please try again.', 'error')

    return render_template('admin/add_normal_user.html')

@app.route('/admin/normal-users/<int:user_id>/edit', methods=['GET', 'POST'])
@admin_required
def admin_edit_normal_user(user_id):
    """Edit normal user"""
    connection = get_db_connection()
    if not connection:
        flash('Database connection error.', 'error')
        return redirect(url_for('admin_normal_users'))

    try:
        cursor = connection.cursor(dictionary=True)

        # Get user data
        cursor.execute("""
            SELECT * FROM normal_users WHERE id = %s
        """, (user_id,))

        user = cursor.fetchone()
        if not user:
            flash('User not found.', 'error')
            return redirect(url_for('admin_normal_users'))

        if request.method == 'POST':
            # username = request.form.get('username', '').strip()
            email = request.form.get('email', '').strip() 
            name = request.form.get('name', '').strip()
            is_active = request.form.get('is_active') == 'on'

            # Update user
            cursor.execute("""
                UPDATE normal_users 
                SET email = %s, name = %s, is_active = %s
                WHERE id = %s
            """, (email, name, is_active, user_id))

            connection.commit()

            # Log activity
            log_admin_activity(session['admin_id'], 'EDIT_USER', 'normal', user_id,
                             {'name': name, 'email': email, 'is_active': is_active})

            cursor.close()
            connection.close()

            flash('User updated successfully!', 'success')
            return redirect(url_for('admin_normal_users'))

        cursor.close()
        connection.close()

        return render_template('admin/edit_normal_user.html', user=user)

    except Exception as e:
        print(f"Edit normal user error: {e}")
        flash('Error updating user.', 'error')
        return redirect(url_for('admin_normal_users'))

@app.route('/admin/normal-users/<int:user_id>/ban', methods=['POST'])
@admin_required
def admin_ban_normal_user(user_id):
    """Ban normal user for custom time"""
    ban_duration = request.form.get('ban_duration', type=int)
    ban_unit = request.form.get('ban_unit', 'days')
    ban_reason = request.form.get('ban_reason', '').strip()

    if not ban_duration or ban_duration <= 0:
        flash('Invalid ban duration.', 'error')
        return redirect(url_for('admin_normal_users'))

    # Calculate ban end time
    if ban_unit == 'hours':
        banned_until = datetime.now() + timedelta(hours=ban_duration)
    elif ban_unit == 'days':
        banned_until = datetime.now() + timedelta(days=ban_duration)
    elif ban_unit == 'weeks':
        banned_until = datetime.now() + timedelta(weeks=ban_duration)
    elif ban_unit == 'months':
        banned_until = datetime.now() + timedelta(days=ban_duration * 30)
    else:
        flash('Invalid ban unit.', 'error')
        return redirect(url_for('admin_normal_users'))

    connection = get_db_connection()
    if connection:
        try:
            cursor = connection.cursor()

            cursor.execute("""
                UPDATE normal_users 
                SET banned_until = %s, ban_reason = %s 
                WHERE id = %s
            """, (banned_until, ban_reason, user_id))

            connection.commit()

            # Log activity
            log_admin_activity(session['admin_id'], 'BAN_USER', 'normal', user_id,
                             {'banned_until': banned_until.isoformat(), 'reason': ban_reason})

            cursor.close()
            connection.close()

            flash(f'User banned until {banned_until.strftime("%Y-%m-%d %H:%M")}.', 'success')
        except Exception as e:
            print(f"Ban user error: {e}")
            flash('Error banning user.', 'error')

    return redirect(url_for('admin_normal_users'))

@app.route('/admin/normal-users/<int:user_id>/unban', methods=['POST'])
@admin_required
def admin_unban_normal_user(user_id):
    """Unban normal user"""
    connection = get_db_connection()
    if connection:
        try:
            cursor = connection.cursor()

            cursor.execute("""
                UPDATE normal_users 
                SET banned_until = NULL, ban_reason = NULL 
                WHERE id = %s
            """, (user_id,))

            connection.commit()

            # Log activity
            log_admin_activity(session['admin_id'], 'UNBAN_USER', 'normal', user_id, {})

            cursor.close()
            connection.close()

            flash('User unbanned successfully.', 'success')
        except Exception as e:
            print(f"Unban user error: {e}")
            flash('Error unbanning user.', 'error')

    return redirect(url_for('admin_normal_users'))

@app.route('/admin/normal-users/<int:user_id>/delete', methods=['POST'])
@admin_required
def admin_delete_normal_user(user_id):
    """Delete normal user"""
    if session.get('admin_role') != 'super_admin':
        flash('Only super admin can delete users.', 'error')
        return redirect(url_for('admin_normal_users'))

    connection = get_db_connection()
    if connection:
        try:
            cursor = connection.cursor(dictionary=True)

            # Get user info for logging
            cursor.execute("SELECT name, email FROM normal_users WHERE id = %s", (user_id,))
            user = cursor.fetchone()

            if user:
                # Delete user
                cursor.execute("DELETE FROM normal_users WHERE id = %s", (user_id,))
                connection.commit()

                # Log activity
                log_admin_activity(session['admin_id'], 'DELETE_USER', 'normal', user_id,
                                 {'name': user['name'], 'email': user['email']})

                flash('User deleted successfully.', 'success')
            else:
                flash('User not found.', 'error')

            cursor.close()
            connection.close()

        except Exception as e:
            print(f"Delete user error: {e}")
            flash('Error deleting user.', 'error')

    return redirect(url_for('admin_normal_users'))

# Doctor User Management Routes (Similar structure)
@app.route('/admin/doctor-users')
@admin_required
def admin_doctor_users():
    """Manage doctor users with verification status"""
    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', '')
    status_filter = request.args.get('status', 'all')
    verification_filter = request.args.get('verification', 'all')

    connection = get_db_connection()
    if not connection:
        flash('Database connection error.', 'error')
        return redirect(url_for('admin_dashboard'))

    try:
        cursor = connection.cursor(dictionary=True)

        # Build query with filters
        where_clauses = []
        params = []

        if search:
            where_clauses.append("(name LIKE %s OR email LIKE %s)")
            params.extend([f"%{search}%", f"%{search}%"])

        if status_filter == 'active':
            where_clauses.append("is_active = TRUE AND (banned_until IS NULL OR banned_until < NOW())")
        elif status_filter == 'inactive':
            where_clauses.append("is_active = FALSE")
        elif status_filter == 'banned':
            where_clauses.append("banned_until > NOW()")

        if verification_filter in ['pending', 'verified', 'rejected']:
            where_clauses.append("verification_status = %s")
            params.append(verification_filter)

        where_sql = " WHERE " + " AND ".join(where_clauses) if where_clauses else ""

        # Get doctors with pagination
        limit = 20
        offset = (page - 1) * limit

        cursor.execute(f"""
            SELECT id, name, email, is_active, banned_until, 
                   ban_reason, verification_status, verified_at, created_at, last_login
            FROM doctor_users 
            {where_sql}
            ORDER BY created_at DESC
            LIMIT %s OFFSET %s
        """, params + [limit, offset])

        doctors = cursor.fetchall()

        # Get total count for pagination
        cursor.execute(f"""
            SELECT COUNT(*) as total FROM doctor_users {where_sql}
        """, params)

        total_doctors = cursor.fetchone()['total']
        total_pages = (total_doctors + limit - 1) // limit

        cursor.close()
        connection.close()

        return render_template('admin/doctor_users.html', 
                             doctors=doctors,
                             current_page=page,
                             total_pages=total_pages,
                             search=search,
                             status_filter=status_filter,
                             verification_filter=verification_filter)

    except Exception as e:
        print(f"Admin doctor users error: {e}")
        flash('Error loading doctors.', 'error')
        return redirect(url_for('admin_dashboard'))
    
@app.route('/admin/doctor-users/add', methods=['GET', 'POST'])
@admin_required
def admin_add_doctor_user():
    """Add new doctor user - CORRECTED VERSION"""
    if request.method == 'POST':
        # Get form data - MATCH YOUR HTML FORM FIELDS
        email = request.form.get('email', '').strip()
        full_name = request.form.get('full_name', '').strip()  # Changed from 'name' to 'full_name'
        password = request.form.get('password', '').strip()
        specialty = request.form.get('specialty', '').strip()  # Added specialty field
        qualification = request.form.get('qualification', '').strip()  # Added qualification field

        # Validation - CHECK ALL REQUIRED FIELDS
        if not all([email, full_name, password, specialty, qualification]):
            flash('All fields are required.', 'error')
            return render_template('admin/add_doctor_user.html')

        if len(password) < 6:
            flash('Password must be at least 6 characters long.', 'error')
            return render_template('admin/add_doctor_user.html')

        connection = get_db_connection()
        if connection:
            try:
                cursor = connection.cursor()

                # Check if email already exists
                cursor.execute("SELECT id FROM doctor_users WHERE email = %s", (email,))
                if cursor.fetchone():
                    flash('Email already exists.', 'error')
                    cursor.close()
                    connection.close()
                    return render_template('admin/add_doctor_user.html')

                # Create password hash
                from werkzeug.security import generate_password_hash
                password_hash = generate_password_hash(password)

                # Insert doctor with ALL required fields
                cursor.execute("""
                    INSERT INTO doctor_users (
                        name, email, password, specialty, qualification,
                        is_active, created_by_admin, verification_status, created_at
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (
                    full_name, email, password_hash, specialty, qualification,
                    True, True, 'pending', datetime.now()
                ))

                connection.commit()

                # Log activity
                try:
                    log_admin_activity(session['admin_id'], 'ADD_DOCTOR', 'doctor', 
                                     cursor.lastrowid, {
                                         'email': email, 
                                         'name': full_name,
                                         'specialty': specialty
                                     })
                except Exception as log_error:
                    print(f"Log activity error: {log_error}")

                cursor.close()
                connection.close()

                flash('Doctor user created successfully!', 'success')
                return redirect(url_for('admin_doctor_users'))

            except Exception as e:
                print(f"Add doctor user error: {e}")
                flash('Error creating doctor user. Please try again.', 'error')

    return render_template('admin/add_doctor_user.html')

@app.route('/admin/doctor-users/<int:doctor_id>/edit', methods=['GET', 'POST'])
@admin_required
def admin_edit_doctor_user(doctor_id):
    """Edit doctor user"""
    connection = get_db_connection()
    if not connection:
        flash('Database connection error.', 'error')
        return redirect(url_for('admin_doctor_users'))

    try:
        cursor = connection.cursor(dictionary=True)

        # Get doctor user data
        cursor.execute("""
            SELECT * FROM doctor_users WHERE id = %s
        """, (doctor_id,))

        user = cursor.fetchone()
        if not user:
            flash('Doctor not found.', 'error')
            return redirect(url_for('admin_doctor_users'))

        if request.method == 'POST':
            email = request.form.get('email', '').strip()
            name = request.form.get('name', '').strip()
            qualification = request.form.get('qualification', '').strip()
            is_active = request.form.get('is_active') == 'on'
            verification_status = request.form.get('verification_status', 'pending')


            # Update doctor user
            cursor.execute("""
                UPDATE doctor_users 
                SET 
                    email = %s, 
                    name = %s, 
                    qualification = %s,
                    is_active = %s,
                    verification_status = %s,
                    verified_at = %s
                WHERE id = %s
            """, (
                email, name, qualification,
                is_active, verification_status,
                datetime.now() if verification_status == 'verified' and user['verification_status'] != 'verified' else user.get('verified_at'),
                doctor_id
            ))

            connection.commit()

            # Log admin activity
            log_admin_activity(session['admin_id'], 'EDIT_DOCTOR', 'doctor', doctor_id,
                             {
                                 'name': name, 
                                 'email': email, 
                                 'is_active': is_active,
                                 'verification_status': verification_status
                             })

            cursor.close()
            connection.close()

            flash('Doctor updated successfully!', 'success')
            return redirect(url_for('admin_doctor_users'))

        cursor.close()
        connection.close()

        return render_template('admin/edit_doctor_user.html', user=user)

    except Exception as e:
        print(f"Edit doctor user error: {e}")
        flash('Error updating doctor.', 'error')
        return redirect(url_for('admin_doctor_users'))

@app.route('/admin/doctor-users/<int:doctor_id>/verify', methods=['POST'])
@admin_required
def admin_verify_doctor(doctor_id):
    """Verify doctor user"""
    connection = get_db_connection()
    if connection:
        try:
            cursor = connection.cursor()

            cursor.execute("""
                UPDATE doctor_users 
                SET verification_status = 'verified', 
                    verified_at = %s, 
                    verified_by = %s
                WHERE id = %s
            """, (datetime.now(), session['admin_id'], doctor_id))

            connection.commit()

            # Log activity
            log_admin_activity(session['admin_id'], 'VERIFY_DOCTOR', 'doctor', doctor_id, {})

            cursor.close()
            connection.close()

            flash('Doctor verified successfully!', 'success')
        except Exception as e:
            print(f"Verify doctor error: {e}")
            flash('Error verifying doctor.', 'error')

    return redirect(url_for('admin_doctor_users'))

@app.route('/admin/doctor-users/<int:doctor_id>/reject', methods=['POST'])
@admin_required
def admin_reject_doctor(doctor_id):
    """Reject doctor verification"""
    connection = get_db_connection()
    if connection:
        try:
            cursor = connection.cursor()

            cursor.execute("""
                UPDATE doctor_users 
                SET verification_status = 'rejected'
                WHERE id = %s
            """, (doctor_id,))

            connection.commit()

            # Log activity
            log_admin_activity(session['admin_id'], 'REJECT_DOCTOR', 'doctor', doctor_id, {})

            cursor.close()
            connection.close()

            flash('Doctor verification rejected.', 'success')
        except Exception as e:
            print(f"Reject doctor error: {e}")
            flash('Error rejecting doctor.', 'error')

    return redirect(url_for('admin_doctor_users'))

def log_admin_activity(admin_id, action, target_user_type, target_user_id, details):
    """Log admin activity"""
    try:
        connection = get_db_connection()
        if connection:
            cursor = connection.cursor()
            cursor.execute("""
                INSERT INTO admin_activity_logs (admin_id, action, target_user_type, target_user_id, details)
                VALUES (%s, %s, %s, %s, %s)
            """, (admin_id, action, target_user_type, target_user_id, json.dumps(details)))
            connection.commit()
            cursor.close()
            connection.close()
    except Exception as e:
        print(f"Activity logging error: {e}")

from flask import send_from_directory
import os

# Add after your Flask app creation

from datetime import datetime

@app.route('/admin/doctor-users/<int:doctor_id>/view', methods=['GET', 'POST'])
@admin_required
def admin_view_doctor_user(doctor_id):
    """View doctor details and handle verification"""
    connection = get_db_connection()
    if not connection:
        flash('Database connection error.', 'error')
        return redirect(url_for('admin_doctor_users'))

    try:
        cursor = connection.cursor(dictionary=True)

        # ✅ FIXED: Get doctor data first (avoids JOIN issues)
        cursor.execute("SELECT * FROM doctor_users WHERE id = %s", (doctor_id,))
        doctor = cursor.fetchone()
        
        if not doctor:
            flash('Doctor not found.', 'error')
            return redirect(url_for('admin_doctor_users'))

        # ✅ FIXED: Get profile data separately
        cursor.execute("SELECT * FROM doctor_user_profiles WHERE user_id = %s", (doctor_id,))
        profile = cursor.fetchone()
        
        # ✅ Merge profile data into doctor dict
        if profile:
            doctor['qualification_proof'] = profile.get('qualification_proof')
            doctor['profile_photo'] = profile.get('profile_photo')
            doctor['city'] = profile.get('city')
            doctor['state'] = profile.get('state')
            doctor['mobile_number'] = profile.get('mobile_number')
            doctor['home_address'] = profile.get('address')
        else:
            doctor['qualification_proof'] = None
            doctor['profile_photo'] = None

        if request.method == 'POST':
            verification_status = request.form.get('verification_status', '').strip()
            verification_reason = request.form.get('verification_reason', '').strip()

            if not verification_status:
                flash('Please select a verification decision.', 'error')
                return redirect(url_for('admin_view_doctor_user', doctor_id=doctor_id))

            # Update verification status
            cursor.execute("""
                UPDATE doctor_users 
                SET 
                    verification_status = %s,
                    verification_reason = %s,
                    verified_by = %s,
                    verified_at = %s
                WHERE id = %s
            """, (
                verification_status,
                verification_reason if verification_status == 'rejected' else None,
                session['admin_id'],
                datetime.now() if verification_status == 'verified' else None,
                doctor_id
            ))

            connection.commit()

            # Log admin activity
            log_admin_activity(
                session['admin_id'], 
                f'DOCTOR_VERIFICATION_{verification_status.upper()}', 
                'doctor', 
                doctor_id,
                {
                    'verification_status': verification_status,
                    'reason': verification_reason
                }
            )

            flash(f'Doctor verification status updated to {verification_status}!', 'success')
            return redirect(url_for('admin_doctor_users'))

        cursor.close()
        connection.close()

        return render_template('admin/view_doctor_user.html', doctor=doctor)

    except Exception as e:
        print(f"View doctor user error: {e}")
        flash('Error loading doctor details.', 'error')
        return redirect(url_for('admin_doctor_users'))

@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    """Serve uploaded files from uploads folder and subdirectories"""
    try:
        return send_from_directory('uploads', filename)
    except FileNotFoundError:
        from flask import abort
        abort(404)

# Ensure your directory exists
os.makedirs('uploads/doctor_profiles/profile_photos', exist_ok=True)

@app.route('/find_doctor', methods=['GET', 'POST'])
@login_required
def find_doctor():
    """Find Ayurvedic doctors - Show ALL doctors by default, filter on search"""
    if session.get('user_type') != 'normal':
        flash('Access denied. This feature is only for normal users.', 'error')
        return redirect(url_for('index'))

    location = ''
    pincode = ''
    search_performed = False

    if request.method == 'POST':
        location = request.form.get('location', '').strip()
        pincode = request.form.get('pincode', '').strip()
        search_performed = True

        # Validate pincode format if provided
        if pincode and (not pincode.isdigit() or len(pincode) != 6):
            flash('Please enter a valid 6-digit pincode.', 'error')
            # Still get all doctors even with validation error
            doctors = get_all_registered_doctors()
            return render_template('find_doctor.html', 
                                 doctors=doctors, 
                                 location=location, 
                                 pincode=pincode,
                                 search_performed=False)

        # Search for doctors if search criteria provided
        if location or pincode:
            doctors = search_registered_doctors(location, pincode)

            if not doctors:
                flash(f'No doctors found for your search criteria. Showing all available doctors.', 'info')
                doctors = get_all_registered_doctors()
        else:
            # No search criteria provided, show all doctors
            doctors = get_all_registered_doctors()
    else:
        # GET request - show all doctors by default
        doctors = get_all_registered_doctors()

    return render_template('find_doctor.html', 
                         doctors=doctors, 
                         location=location, 
                         pincode=pincode,
                         search_performed=search_performed)

def get_all_registered_doctors():
    """Get ALL registered verified doctors for default display"""
    connection = get_db_connection()
    if not connection:
        return []

    try:
        cursor = connection.cursor(dictionary=True)

        # Get all verified active doctors
        cursor.execute("""
            SELECT DISTINCT
                du.id,
                du.name as doctor_name,
                du.email,
                du.specialty,
                du.qualification,
                du.experience_years,
                du.consultation_fee,
                du.clinic_name,
                du.clinic_address,
                du.bio,
                du.available_days,
                du.available_hours,
                du.profile_image,
                dp.city,
                dp.state,
                dp.country,
                dp.pincode,
                dp.address as home_address,
                dp.mobile_number,
                dp.profile_photo,
                dp.full_name,
                dp.consultant_fee,
                dp.experience as profile_experience,
                dp.specialty as profile_specialty
            FROM doctor_users du
            LEFT JOIN doctor_user_profiles dp ON du.id = dp.user_id
            WHERE du.verification_status = 'verified' 
            AND du.is_active = TRUE
            ORDER BY 
                CASE 
                    WHEN du.experience_years IS NOT NULL THEN du.experience_years
                    WHEN dp.experience IS NOT NULL THEN dp.experience
                    ELSE 0
                END DESC,
                du.name ASC
            LIMIT 50
        """)

        doctors = cursor.fetchall()

        # Process doctor data for display
        processed_doctors = []
        for doctor in doctors:
            processed_doctor = process_doctor_data(doctor)
            processed_doctors.append(processed_doctor)

        cursor.close()
        connection.close()

        return processed_doctors

    except Exception as e:
        print(f"Get all doctors error: {e}")
        return []

def search_registered_doctors(location, pincode):
    """Search for registered verified doctors by location/pincode"""
    connection = get_db_connection()
    if not connection:
        return []

    try:
        cursor = connection.cursor(dictionary=True)

        # Build search query for verified doctors
        where_clauses = ["du.verification_status = 'verified'", "du.is_active = TRUE"]
        params = []

        # Add location search - search in multiple fields
        if location:
            where_clauses.append("""
                (du.address LIKE %s OR 
                 dp.city LIKE %s OR 
                 dp.state LIKE %s OR
                 du.clinic_address LIKE %s OR
                 du.clinic_name LIKE %s OR
                 dp.address LIKE %s)
            """)
            location_param = f"%{location}%"
            params.extend([location_param] * 6)

        # Add pincode search
        if pincode:
            where_clauses.append("dp.pincode = %s")
            params.append(pincode)

        where_sql = " AND ".join(where_clauses)

        # Enhanced query with all doctor details
        cursor.execute(f"""
            SELECT DISTINCT
                du.id,
                du.name as doctor_name,
                du.email,
                du.specialty,
                du.qualification,
                du.experience_years,
                du.consultation_fee,
                du.clinic_name,
                du.clinic_address,
                du.bio,
                du.available_days,
                du.available_hours,
                du.profile_image,
                dp.city,
                dp.state,
                dp.country,
                dp.pincode,
                dp.address as home_address,
                dp.mobile_number,
                dp.profile_photo,
                dp.full_name,
                dp.consultant_fee,
                dp.experience as profile_experience,
                dp.specialty as profile_specialty
            FROM doctor_users du
            LEFT JOIN doctor_user_profiles dp ON du.id = dp.user_id
            WHERE {where_sql}
            ORDER BY 
                CASE 
                    WHEN du.experience_years IS NOT NULL THEN du.experience_years
                    WHEN dp.experience IS NOT NULL THEN dp.experience
                    ELSE 0
                END DESC,
                du.consultation_fee ASC,
                du.name ASC
            LIMIT 50
        """, params)

        doctors = cursor.fetchall()

        # Process doctor data
        processed_doctors = []
        for doctor in doctors:
            processed_doctor = process_doctor_data(doctor)
            processed_doctors.append(processed_doctor)

        cursor.close()
        connection.close()

        return processed_doctors

    except Exception as e:
        print(f"Search doctors error: {e}")
        return []

def process_doctor_data(doctor):
    """Process raw doctor data for display - FIXED DOUBLE PREFIX"""
    # Determine best name
    doctor['display_name'] = doctor['full_name'] or doctor['doctor_name'] or 'Unknown'

    # CORRECTED: Photo path processing
    profile_photo = doctor['profile_photo'] or doctor['profile_image']
    
    if profile_photo:
        # Simple logic to avoid double /uploads/ prefix
        if profile_photo.startswith('uploads/'):
            doctor['display_photo'] = f"/{profile_photo}"  # Just add leading slash
        elif profile_photo.startswith('/uploads/'):
            doctor['display_photo'] = profile_photo  # Already has full path
        else:
            doctor['display_photo'] = f"/uploads/{profile_photo}"  # Add full prefix
    else:
        doctor['display_photo'] = None

    # Format consultation fee
    consultation_fee = doctor['consultation_fee'] or doctor['consultant_fee']
    if consultation_fee and consultation_fee > 0:
        doctor['formatted_fee'] = f"₹{consultation_fee:.0f}"
    else:
        doctor['formatted_fee'] = "Contact for fees"

    # Format experience
    experience = doctor['experience_years'] or doctor['profile_experience']
    if experience and experience > 0:
        doctor['formatted_experience'] = f"{experience} years"
    else:
        doctor['formatted_experience'] = "New practitioner"

    # Format specialty
    specialty = doctor['specialty'] or doctor['profile_specialty']
    doctor['formatted_specialty'] = specialty or 'Ayurveda'

    # CORRECTED: Initials generation
    name = doctor['display_name']
    if name.startswith('Dr. '):
        name = name[4:]
    name_parts = name.split()
    if len(name_parts) >= 2:
        doctor['initials'] = f"{name_parts[0][0]}{name_parts[1][0]}".upper()
    elif len(name_parts) == 1:
        doctor['initials'] = f"{name_parts[0][0]}D".upper()
    else:
        doctor['initials'] = "DR"

    # Format clinic info
    doctor['clinic_info'] = doctor['clinic_name'] or 'Private Practice'

    # Format location
    if doctor['city'] and doctor['state']:
        doctor['location_display'] = f"{doctor['city']}, {doctor['state']}"
    elif doctor['city']:
        doctor['location_display'] = doctor['city']
    else:
        doctor['location_display'] = "Location not specified"

    # Format availability
    if doctor['available_days']:
        try:
            import json
            days = json.loads(doctor['available_days'])
            if isinstance(days, list) and days:
                doctor['availability'] = ', '.join(days[:3])
            else:
                doctor['availability'] = 'Contact for availability'
        except:
            doctor['availability'] = 'Contact for availability'
    else:
        doctor['availability'] = 'Contact for availability'

    return doctor

@app.route('/api/doctor-location/<int:doctor_id>')
@login_required
def api_doctor_location(doctor_id):
    """API to get doctor location for maps"""
    if session.get('user_type') != 'normal':
        return jsonify({'error': 'Access denied'}), 403

    connection = get_db_connection()
    if not connection:
        return jsonify({'error': 'Database error'}), 500

    try:
        cursor = connection.cursor(dictionary=True)

        cursor.execute("""
            SELECT 
                du.name as doctor_name,
                du.clinic_name,
                du.clinic_address,
                du.consultation_fee,
                dp.city,
                dp.state,
                dp.pincode,
                dp.address
            FROM doctor_users du
            LEFT JOIN doctor_user_profiles dp ON du.id = dp.user_id
            WHERE du.id = %s AND du.verification_status = 'verified'
        """, (doctor_id,))

        doctor = cursor.fetchone()
        cursor.close()
        connection.close()

        if doctor:
            return jsonify({
                'name': doctor['doctor_name'],
                'clinic': doctor['clinic_name'],
                'address': doctor['clinic_address'] or doctor['address'],
                'city': doctor['city'],
                'state': doctor['state'],
                'pincode': doctor['pincode'],
                'fee': doctor['consultation_fee']
            })
        else:
            return jsonify({'error': 'Doctor not found'}), 404

    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Keep existing doctor_details and book_appointment routes unchanged
@app.route('/doctor-details/<int:doctor_id>')
@login_required
def doctor_details(doctor_id):
    """View detailed doctor profile"""
    if session.get('user_type') != 'normal':
        flash('Access denied.', 'error')
        return redirect(url_for('index'))

    connection = get_db_connection()
    if not connection:
        flash('Database connection error.', 'error')
        return redirect(url_for('find_doctor'))

    try:
        cursor = connection.cursor(dictionary=True)

        cursor.execute("""
            SELECT 
                du.*,
                dp.*,
                du.name as doctor_name,
                dp.full_name as profile_name
            FROM doctor_users du
            LEFT JOIN doctor_user_profiles dp ON du.id = dp.user_id
            WHERE du.id = %s AND du.verification_status = 'verified'
        """, (doctor_id,))

        doctor = cursor.fetchone()
        cursor.close()
        connection.close()

        if not doctor:
            flash('Doctor not found.', 'error')
            return redirect(url_for('find_doctor'))

        return render_template('doctor_details.html', doctor=doctor)

    except Exception as e:
        print(f"Doctor details error: {e}")
        flash('Error loading doctor details.', 'error')
        return redirect(url_for('find_doctor'))

@app.route('/book-appointment/<int:doctor_id>')
@login_required
def book_appointment(doctor_id):
    """Book appointment with doctor"""
    if session.get('user_type') != 'normal':
        flash('Access denied.', 'error')
        return redirect(url_for('index'))

    # For now, redirect to a placeholder or implement booking logic
    flash(f'Appointment booking with doctor ID {doctor_id} - Feature coming soon!', 'info')
    return redirect(url_for('find_doctor'))

@app.route('/debug-photos')
def debug_photos():
    """Debug doctor photos in database"""
    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)
    
    cursor.execute("""
        SELECT 
            du.id, du.name, du.profile_image,
            dp.profile_photo
        FROM doctor_users du
        LEFT JOIN doctor_user_profiles dp ON du.id = dp.user_id
        WHERE du.verification_status = 'verified'
        LIMIT 5
    """)
    
    doctors = cursor.fetchall()
    cursor.close()
    connection.close()
    
    result = "<h2>Doctor Photos in Database:</h2>"
    for doc in doctors:
        photo = doc['profile_image'] or doc['profile_photo']
        expected_url = f"/uploads/doctor_profiles/profile_photos/{photo}" if photo and '/' not in photo else f"/uploads/{photo}" if photo else "No photo"
        
        result += f"""
        <p><strong>ID:</strong> {doc['id']}</p>
        <p><strong>Name:</strong> {doc['name']}</p>
        <p><strong>DB Photo Path:</strong> {photo or 'None'}</p>
        <p><strong>Expected URL:</strong> {expected_url}</p>
        <hr>
        """
    
    return result


@app.route('/buy-medicines')
@login_required
def buy_medicines():
    """Display medicines in card format"""
    connection = get_db_connection()
    if not connection:
        flash('Database connection error.', 'error')
        return redirect(url_for('normal_dashboard'))

    try:
        cursor = connection.cursor(dictionary=True)

        # Get search and filter parameters
        search = request.args.get('search', '').strip()
        category = request.args.get('category', '')
        sort_by = request.args.get('sort', 'name')  # name, price, stock
        page = int(request.args.get('page', 1))
        per_page = 12

        # Build query with filters
        where_conditions = ["is_active = TRUE"]
        params = []

        if search:
            where_conditions.append("(name LIKE %s OR manufacturer LIKE %s OR generic_name LIKE %s)")
            search_term = f"%{search}%"
            params.extend([search_term, search_term, search_term])

        if category:
            where_conditions.append("category = %s")
            params.append(category)

        where_clause = " AND ".join(where_conditions)

        # Sorting
        order_by = {
            'name': 'name ASC',
            'price_low': 'price ASC',
            'price_high': 'price DESC',
            'stock': 'stock_quantity DESC'
        }.get(sort_by, 'name ASC')

        # Count total medicines
        cursor.execute(f"SELECT COUNT(*) as total FROM medicines WHERE {where_clause}", params)
        total_medicines = cursor.fetchone()['total']

        # Calculate pagination
        offset = (page - 1) * per_page
        total_pages = (total_medicines + per_page - 1) // per_page

        # Get medicines with pagination
        cursor.execute(f"""
            SELECT 
                id, name, manufacturer, price, stock_quantity, 
                medicine_image, category, prescription_required,
                generic_name, description
            FROM medicines 
            WHERE {where_clause}
            ORDER BY {order_by}
            LIMIT %s OFFSET %s
        """, params + [per_page, offset])

        medicines = cursor.fetchall()

        # Get categories for filter dropdown
        cursor.execute("SELECT DISTINCT category FROM medicines WHERE category IS NOT NULL AND is_active = TRUE ORDER BY category")
        categories = [row['category'] for row in cursor.fetchall()]

        # Get user's cart count
        cursor.execute("SELECT COUNT(*) as cart_count FROM shopping_cart WHERE user_id = %s", (session['user_id'],))
        cart_count = cursor.fetchone()['cart_count']

        cursor.close()
        connection.close()

        return render_template('buy_medicines.html', 
                             medicines=medicines,
                             categories=categories,
                             current_category=category,
                             search=search,
                             sort_by=sort_by,
                             page=page,
                             total_pages=total_pages,
                             total_medicines=total_medicines,
                             cart_count=cart_count)

    except Exception as e:
        print(f"Buy medicines error: {e}")
        flash('Error loading medicines.', 'error')
        return redirect(url_for('normal_dashboard'))

### **2. Medicine Details Page**
@app.route('/medicine/<int:medicine_id>')
@login_required
def medicine_details(medicine_id):
    """Display detailed medicine information"""
    connection = get_db_connection()
    if not connection:
        flash('Database connection error.', 'error')
        return redirect(url_for('buy_medicines'))

    try:
        cursor = connection.cursor(dictionary=True)

        # Get medicine details
        cursor.execute("""
            SELECT * FROM medicines 
            WHERE id = %s AND is_active = TRUE
        """, (medicine_id,))

        medicine = cursor.fetchone()
        if not medicine:
            flash('Medicine not found.', 'error')
            return redirect(url_for('buy_medicines'))

        # Check if medicine is in user's cart
        cursor.execute("""
            SELECT quantity FROM shopping_cart 
            WHERE user_id = %s AND medicine_id = %s
        """, (session['user_id'], medicine_id))

        cart_item = cursor.fetchone()
        in_cart = bool(cart_item)
        cart_quantity = cart_item['quantity'] if cart_item else 0

        # Get related medicines (same category or manufacturer)
        cursor.execute("""
            SELECT id, name, manufacturer, price, medicine_image, stock_quantity
            FROM medicines 
            WHERE (category = %s OR manufacturer = %s) 
            AND id != %s AND is_active = TRUE 
            LIMIT 6
        """, (medicine['category'], medicine['manufacturer'], medicine_id))

        related_medicines = cursor.fetchall()

        cursor.close()
        connection.close()

        return render_template('medicine_details.html',
                             medicine=medicine,
                             in_cart=in_cart,
                             cart_quantity=cart_quantity,
                             related_medicines=related_medicines)

    except Exception as e:
        print(f"Medicine details error: {e}")
        flash('Error loading medicine details.', 'error')
        return redirect(url_for('buy_medicines'))

### **3. Add to Cart**
@app.route('/add-to-cart', methods=['POST'])
@login_required
def add_to_cart():
    """Add medicine to shopping cart"""
    medicine_id = int(request.form.get('medicine_id'))
    quantity = int(request.form.get('quantity', 1))

    connection = get_db_connection()
    if not connection:
        return jsonify({'success': False, 'message': 'Database connection error'})

    try:
        cursor = connection.cursor(dictionary=True)

        # Check if medicine exists and has stock
        cursor.execute("SELECT name, stock_quantity FROM medicines WHERE id = %s AND is_active = TRUE", (medicine_id,))
        medicine = cursor.fetchone()

        if not medicine:
            return jsonify({'success': False, 'message': 'Medicine not found'})

        if medicine['stock_quantity'] < quantity:
            return jsonify({'success': False, 'message': f'Only {medicine["stock_quantity"]} items available'})

        # Check if item already in cart
        cursor.execute("SELECT quantity FROM shopping_cart WHERE user_id = %s AND medicine_id = %s", 
                      (session['user_id'], medicine_id))
        existing_item = cursor.fetchone()

        if existing_item:
            # Update quantity
            new_quantity = existing_item['quantity'] + quantity
            if new_quantity > medicine['stock_quantity']:
                return jsonify({'success': False, 'message': 'Not enough stock available'})

            cursor.execute("""
                UPDATE shopping_cart 
                SET quantity = %s, added_at = NOW() 
                WHERE user_id = %s AND medicine_id = %s
            """, (new_quantity, session['user_id'], medicine_id))
        else:
            # Add new item
            cursor.execute("""
                INSERT INTO shopping_cart (user_id, medicine_id, quantity) 
                VALUES (%s, %s, %s)
            """, (session['user_id'], medicine_id, quantity))

        connection.commit()

        # Get updated cart count
        cursor.execute("SELECT COUNT(*) as count FROM shopping_cart WHERE user_id = %s", (session['user_id'],))
        cart_count = cursor.fetchone()['count']

        cursor.close()
        connection.close()

        return jsonify({
            'success': True, 
            'message': f'{medicine["name"]} added to cart successfully!',
            'cart_count': cart_count
        })

    except Exception as e:
        print(f"Add to cart error: {e}")
        return jsonify({'success': False, 'message': 'Error adding to cart'})

### **4. Buy Now (Direct Order)**
@app.route('/buy-now', methods=['POST'])
@login_required
def buy_now():
    """Direct purchase of medicine"""
    medicine_id = int(request.form.get('medicine_id'))
    quantity = int(request.form.get('quantity', 1))

    # Add to cart first
    connection = get_db_connection()
    try:
        cursor = connection.cursor(dictionary=True)

        # Check stock and add to cart
        cursor.execute("SELECT stock_quantity FROM medicines WHERE id = %s", (medicine_id,))
        medicine = cursor.fetchone()

        if not medicine or medicine['stock_quantity'] < quantity:
            flash('Not enough stock available.', 'error')
            return redirect(request.referrer)

        # Clear cart and add this item
        cursor.execute("DELETE FROM shopping_cart WHERE user_id = %s", (session['user_id'],))
        cursor.execute("""
            INSERT INTO shopping_cart (user_id, medicine_id, quantity) 
            VALUES (%s, %s, %s)
        """, (session['user_id'], medicine_id, quantity))

        connection.commit()
        cursor.close()
        connection.close()

        # Redirect to checkout
        return redirect(url_for('checkout'))

    except Exception as e:
        print(f"Buy now error: {e}")
        flash('Error processing purchase.', 'error')
        return redirect(request.referrer)

### **5. Shopping Cart View**
@app.route('/cart')
@login_required
def view_cart():
    """Display user's shopping cart"""
    connection = get_db_connection()
    if not connection:
        flash('Database connection error.', 'error')
        return redirect(url_for('normal_dashboard'))

    try:
        cursor = connection.cursor(dictionary=True)

        # Get cart items with medicine details
        cursor.execute("""
            SELECT 
                sc.id as cart_id,
                sc.quantity,
                m.id as medicine_id,
                m.name,
                m.manufacturer,
                m.price,
                m.stock_quantity,
                m.medicine_image,
                (sc.quantity * m.price) as subtotal
            FROM shopping_cart sc
            JOIN medicines m ON sc.medicine_id = m.id
            WHERE sc.user_id = %s AND m.is_active = TRUE
            ORDER BY sc.added_at DESC
        """, (session['user_id'],))

        cart_items = cursor.fetchall()

        # Calculate totals
        total_amount = sum(item['subtotal'] for item in cart_items)
        total_items = sum(item['quantity'] for item in cart_items)

        cursor.close()
        connection.close()

        return render_template('cart.html',
                             cart_items=cart_items,
                             total_amount=total_amount,
                             total_items=total_items)

    except Exception as e:
        print(f"Cart view error: {e}")
        flash('Error loading cart.', 'error')
        return redirect(url_for('normal_dashboard'))


@app.route('/update-cart', methods=['POST'])
@login_required
def update_cart():
    """Update cart item quantity"""
    cart_id = int(request.form.get('cart_id'))
    quantity = int(request.form.get('quantity'))

    connection = get_db_connection()
    try:
        cursor = connection.cursor(dictionary=True)

        if quantity <= 0:
            # Remove item from cart
            cursor.execute("DELETE FROM shopping_cart WHERE id = %s AND user_id = %s", (cart_id, session['user_id']))
        else:
            # Update quantity
            cursor.execute("UPDATE shopping_cart SET quantity = %s WHERE id = %s AND user_id = %s", (quantity, cart_id, session['user_id']))

        connection.commit()
        return jsonify({'success': True})

    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/remove-from-cart/<int:cart_id>')
@login_required
def remove_from_cart(cart_id):
    """Remove item from cart"""
    connection = get_db_connection()
    try:
        cursor = connection.cursor()
        cursor.execute("DELETE FROM shopping_cart WHERE id = %s AND user_id = %s", (cart_id, session['user_id']))
        connection.commit()
        flash('Item removed from cart.', 'success')
    except Exception as e:
        flash('Error removing item.', 'error')

    return redirect(url_for('view_cart'))

### **2. Search & Filter Enhancement**
@app.route('/api/medicines/search')
def search_medicines_api():
    """API endpoint for live search"""
    query = request.args.get('q', '').strip()

    if len(query) < 2:
        return jsonify([])

    connection = get_db_connection()
    try:
        cursor = connection.cursor(dictionary=True)
        cursor.execute("""
            SELECT id, name, manufacturer, price 
            FROM medicines 
            WHERE (name LIKE %s OR manufacturer LIKE %s OR generic_name LIKE %s) 
            AND is_active = TRUE 
            LIMIT 10
        """, (f"%{query}%", f"%{query}%", f"%{query}%"))

        results = cursor.fetchall()
        return jsonify(results)

    except Exception as e:
        return jsonify([])

@app.route('/test-medicines-debug')
def test_medicines_debug():
    """Debug medicines table structure"""
    connection = get_db_connection()
    if not connection:
        return "<h2>❌ Database connection failed</h2>"
    
    try:
        cursor = connection.cursor(dictionary=True)
        
        # Test 1: Current database
        cursor.execute("SELECT DATABASE() as current_db")
        current_db = cursor.fetchone()
        
        # Test 2: Check if medicines table exists
        cursor.execute("SHOW TABLES LIKE 'medicines'")
        table_exists = cursor.fetchone()
        
        # Test 3: Get table structure
        cursor.execute("DESCRIBE medicines")
        columns = cursor.fetchall()
        
        # Test 4: Check for is_active specifically
        cursor.execute("SHOW COLUMNS FROM medicines WHERE Field = 'is_active'")
        is_active_column = cursor.fetchone()
        
        # Test 5: Try simple count
        cursor.execute("SELECT COUNT(*) as total FROM medicines")
        total_count = cursor.fetchone()
        
        # Test 6: Try with is_active (this might fail)
        try:
            cursor.execute("SELECT COUNT(*) as active FROM medicines WHERE is_active = 1")
            active_count = cursor.fetchone()
        except Exception as e:
            active_count = f"ERROR: {str(e)}"
        
        cursor.close()
        connection.close()
        
        return f"""
        <h1>🔍 Medicines Table Debug</h1>
        <h3>Database Info:</h3>
        <p><strong>Current DB:</strong> {current_db}</p>
        <p><strong>Table Exists:</strong> {'✅ YES' if table_exists else '❌ NO'}</p>
        
        <h3>Table Structure:</h3>
        <table border="1" style="border-collapse: collapse;">
            <tr><th>Field</th><th>Type</th><th>Null</th><th>Key</th><th>Default</th></tr>
            {''.join([f"<tr><td>{col['Field']}</td><td>{col['Type']}</td><td>{col['Null']}</td><td>{col['Key']}</td><td>{col['Default']}</td></tr>" for col in columns])}
        </table>
        
        <h3>is_active Column Check:</h3>
        <p>{is_active_column if is_active_column else '❌ is_active column NOT FOUND'}</p>
        
        <h3>Query Tests:</h3>
        <p><strong>Total Medicines:</strong> {total_count['total'] if total_count else 'FAILED'}</p>
        <p><strong>Active Medicines:</strong> {active_count if isinstance(active_count, dict) else active_count}</p>
        """
        
    except Exception as e:
        return f"<h2>❌ Debug Error:</h2><p>{str(e)}</p>"



if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
