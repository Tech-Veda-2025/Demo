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
    """Doctor profile page with View/Edit mode and file upload support"""
    if session.get('user_type') != 'doctor':
        flash('Access denied. This page is only for doctors.', 'error')
        return redirect(url_for('index'))

    connection = get_db_connection()
    if not connection:
        flash('Database connection error. Please try again.', 'error')
        return redirect(url_for('doctor_dashboard'))

    try:
        cursor = connection.cursor(dictionary=True)

        # Get or create doctor profile
        cursor.execute("""
            SELECT * FROM doctor_user_profiles 
            WHERE user_id = %s
        """, (session['user_id'],))

        profile = cursor.fetchone()

        if not profile:
            # Create default profile if doesn't exist
            cursor.execute("""
                INSERT INTO doctor_user_profiles (user_id, full_name, email_id, country) 
                VALUES (%s, %s, %s, %s)
            """, (session['user_id'], session['user_name'], session['user_email'], 'India'))

            connection.commit()

            # Fetch the newly created profile
            cursor.execute("""
                SELECT * FROM doctor_user_profiles 
                WHERE user_id = %s
            """, (session['user_id'],))

            profile = cursor.fetchone()

        cursor.close()
        connection.close()

        return render_template('doctor_profile.html', profile=profile)

    except mysql.connector.Error as err:
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



if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
