-- Ayurvedic Healthcare Portal Database Schema
-- Run this script in your MySQL server to create the database and tables

-- Create database
CREATE DATABASE IF NOT EXISTS ayurvedic_portal CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE ayurvedic_portal;

-- Table for Normal Users
CREATE TABLE IF NOT EXISTS normal_users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    google_id VARCHAR(100) DEFAULT NULL,
    phone VARCHAR(20) DEFAULT NULL,
    address TEXT DEFAULT NULL,
    date_of_birth DATE DEFAULT NULL,
    gender ENUM('Male', 'Female', 'Other') DEFAULT NULL,
    profile_image VARCHAR(255) DEFAULT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    email_verified BOOLEAN DEFAULT FALSE,
    last_login TIMESTAMP NULL DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    INDEX idx_email (email),
    INDEX idx_google_id (google_id),
    INDEX idx_created_at (created_at)
);

-- Table for Doctor Users
CREATE TABLE IF NOT EXISTS doctor_users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    specialty VARCHAR(100) NOT NULL,
    qualification VARCHAR(200) NOT NULL,
    google_id VARCHAR(100) DEFAULT NULL,
    phone VARCHAR(20) DEFAULT NULL,
    address TEXT DEFAULT NULL,
    date_of_birth DATE DEFAULT NULL,
    gender ENUM('Male', 'Female', 'Other') DEFAULT NULL,
    license_number VARCHAR(50) DEFAULT NULL,
    experience_years INT DEFAULT 0,
    consultation_fee DECIMAL(10,2) DEFAULT NULL,
    available_days JSON DEFAULT NULL, -- Store available days as JSON
    available_hours JSON DEFAULT NULL, -- Store available time slots as JSON
    profile_image VARCHAR(255) DEFAULT NULL,
    clinic_name VARCHAR(150) DEFAULT NULL,
    clinic_address TEXT DEFAULT NULL,
    bio TEXT DEFAULT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    is_verified BOOLEAN DEFAULT FALSE,
    email_verified BOOLEAN DEFAULT FALSE,
    last_login TIMESTAMP NULL DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    INDEX idx_email (email),
    INDEX idx_specialty (specialty),
    INDEX idx_google_id (google_id),
    INDEX idx_is_verified (is_verified),
    INDEX idx_created_at (created_at)
);

-- Table for Authentication Sessions
CREATE TABLE IF NOT EXISTS user_sessions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    user_type ENUM('normal', 'doctor') NOT NULL,
    session_token VARCHAR(255) NOT NULL UNIQUE,
    ip_address VARCHAR(45) DEFAULT NULL,
    user_agent TEXT DEFAULT NULL,
    expires_at TIMESTAMP NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    INDEX idx_session_token (session_token),
    INDEX idx_user_session (user_id, user_type),
    INDEX idx_expires_at (expires_at)
);

-- Table for Appointments (for future use)
CREATE TABLE IF NOT EXISTS appointments (
    id INT AUTO_INCREMENT PRIMARY KEY,
    patient_id INT NOT NULL,
    doctor_id INT NOT NULL,
    appointment_date DATE NOT NULL,
    appointment_time TIME NOT NULL,
    duration_minutes INT DEFAULT 30,
    consultation_type ENUM('online', 'in-person') DEFAULT 'in-person',
    status ENUM('scheduled', 'confirmed', 'cancelled', 'completed', 'no-show') DEFAULT 'scheduled',
    symptoms TEXT DEFAULT NULL,
    notes TEXT DEFAULT NULL,
    consultation_fee DECIMAL(10,2) DEFAULT NULL,
    payment_status ENUM('pending', 'paid', 'refunded') DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    FOREIGN KEY (patient_id) REFERENCES normal_users(id) ON DELETE CASCADE,
    FOREIGN KEY (doctor_id) REFERENCES doctor_users(id) ON DELETE CASCADE,

    INDEX idx_patient_id (patient_id),
    INDEX idx_doctor_id (doctor_id),
    INDEX idx_appointment_date (appointment_date),
    INDEX idx_status (status)
);

-- Table for Medical Records (for future use)
CREATE TABLE IF NOT EXISTS medical_records (
    id INT AUTO_INCREMENT PRIMARY KEY,
    patient_id INT NOT NULL,
    doctor_id INT NOT NULL,
    appointment_id INT DEFAULT NULL,
    diagnosis TEXT DEFAULT NULL,
    treatment_plan TEXT DEFAULT NULL,
    medications JSON DEFAULT NULL, -- Store medications as JSON
    vitals JSON DEFAULT NULL, -- Store vital signs as JSON
    allergies TEXT DEFAULT NULL,
    chronic_conditions TEXT DEFAULT NULL,
    family_history TEXT DEFAULT NULL,
    lifestyle_notes TEXT DEFAULT NULL,
    follow_up_date DATE DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    FOREIGN KEY (patient_id) REFERENCES normal_users(id) ON DELETE CASCADE,
    FOREIGN KEY (doctor_id) REFERENCES doctor_users(id) ON DELETE CASCADE,
    FOREIGN KEY (appointment_id) REFERENCES appointments(id) ON DELETE SET NULL,

    INDEX idx_patient_id (patient_id),
    INDEX idx_doctor_id (doctor_id),
    INDEX idx_appointment_id (appointment_id),
    INDEX idx_created_at (created_at)
);

-- Table for System Logs
CREATE TABLE IF NOT EXISTS system_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT DEFAULT NULL,
    user_type ENUM('normal', 'doctor', 'admin') DEFAULT NULL,
    action VARCHAR(100) NOT NULL,
    description TEXT DEFAULT NULL,
    ip_address VARCHAR(45) DEFAULT NULL,
    user_agent TEXT DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    INDEX idx_user_logs (user_id, user_type),
    INDEX idx_action (action),
    INDEX idx_created_at (created_at)
);

-- Insert sample data for testing
-- Sample Normal User (password is 'password123' hashed)
INSERT INTO normal_users (name, email, password, phone, gender) VALUES 
('John Doe', 'john@example.com', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewfKfVfLb4WRxYfS', '+1234567890', 'Male'),
('Jane Smith', 'jane@example.com', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewfKfVfLb4WRxYfS', '+1234567891', 'Female');

-- Sample Doctor User (password is 'password123' hashed)
INSERT INTO doctor_users (name, email, password, specialty, qualification, phone, experience_years, consultation_fee, is_verified) VALUES 
('Dr. Rajesh Kumar', 'dr.rajesh@example.com', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewfKfVfLb4WRxYfS', 'Ayurvedic Medicine', 'BAMS, MD (Ayurveda)', '+1234567892', 15, 500.00, TRUE),
('Dr. Priya Sharma', 'dr.priya@example.com', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewfKfVfLb4WRxYfS', 'Panchakarma', 'BAMS, MS (Panchakarma)', '+1234567893', 12, 600.00, TRUE);

-- Create indexes for better performance
CREATE INDEX idx_users_email_type ON normal_users(email);
CREATE INDEX idx_doctors_email_type ON doctor_users(email);
CREATE INDEX idx_appointments_date_status ON appointments(appointment_date, status);

-- Display table information
SELECT 'Database setup completed successfully!' as Status;
SELECT 'Tables created:' as Info;
SHOW TABLES;
