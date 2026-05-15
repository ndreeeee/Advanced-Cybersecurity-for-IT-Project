// =========================================================
// ZTA Policy Store — MongoDB Initialization
// =========================================================

db = db.getSiblingDB('zta_policy');

// Create collections
db.createCollection('policies');
db.createCollection('access_logs');
db.createCollection('trust_history');

// Create indexes
db.policies.createIndex({ "device_ip": 1 }, { unique: true });
db.access_logs.createIndex({ "timestamp": -1 });
db.trust_history.createIndex({ "device_ip": 1, "timestamp": -1 });

// Initial device data
db.policies.insertMany([
  {
    device_ip: '172.20.0.10',
    device_name: 'employee-alice',
    trust_score: 0.85,
    created_at: new Date(),
    updated_at: new Date()
  },
  {
    device_ip: '172.20.0.11',
    device_name: 'branch-kiosk',
    trust_score: 0.50,
    created_at: new Date(),
    updated_at: new Date()
  },
  {
    device_ip: '172.20.0.12',
    device_name: 'employee-bob',
    trust_score: 0.80,
    created_at: new Date(),
    updated_at: new Date()
  }
]);

print('✅ ZTA MongoDB initialized successfully.');
