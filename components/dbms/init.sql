-- Crazione schema ZTA Database

CREATE TABLE policies (
    id SERIAL PRIMARY KEY,
    device_ip VARCHAR(15) UNIQUE NOT NULL,
    device_name VARCHAR(50) NOT NULL,
    trust_score DECIMAL(3,2) DEFAULT 0.50,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE access_logs (
    id SERIAL PRIMARY KEY,
    device_ip VARCHAR(15),
    endpoint VARCHAR(100),
    action VARCHAR(10),
    reason TEXT,
    timestamp TIMESTAMP DEFAULT NOW()
);

INSERT INTO policies (device_ip, device_name, trust_score) VALUES
('172.20.0.10', 'employee-alice', 0.85),
('172.20.0.11', 'branch-kiosk', 0.50),
('172.20.0.12', 'employee-bob', 0.80);
