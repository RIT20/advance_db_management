-- schema.sql
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS donors;
DROP TABLE IF EXISTS hospitals;
DROP TABLE IF EXISTS blood_banks;
DROP TABLE IF EXISTS hospital_inventory;
DROP TABLE IF EXISTS blood_bank_inventory;
DROP TABLE IF EXISTS blood_requests;
DROP TABLE IF EXISTS transfers;

CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    user_type TEXT NOT NULL,
    organization_id INTEGER
);

CREATE TABLE donors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    blood_type TEXT,
    age INTEGER,
    gender TEXT,
    contact TEXT,
    address TEXT,
    medical_history TEXT,
    availability_type TEXT
);

CREATE TABLE hospitals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    location TEXT,
    contact TEXT
);

CREATE TABLE blood_banks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    location TEXT,
    contact TEXT
);

CREATE TABLE hospital_inventory (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hospital_id INTEGER,
    blood_type TEXT,
    units INTEGER,
    last_updated TIMESTAMP
);

CREATE TABLE blood_bank_inventory (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    blood_bank_id INTEGER,
    blood_type TEXT,
    units INTEGER,
    last_updated TIMESTAMP
);

CREATE TABLE blood_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hospital_id INTEGER,
    blood_type TEXT,
    units_needed INTEGER,
    urgency TEXT,
    patient_info TEXT,
    status TEXT,
    request_date TIMESTAMP
);

CREATE TABLE transfers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    from_donor_id INTEGER,
    from_hospital_id INTEGER,
    from_blood_bank_id INTEGER,
    to_hospital_id INTEGER,
    to_blood_bank_id INTEGER,
    blood_type TEXT,
    units INTEGER,
    transfer_date TIMESTAMP
);
