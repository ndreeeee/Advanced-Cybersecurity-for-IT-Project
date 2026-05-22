// ==============================================================================
// ZTA 2026 - MongoDB: dati clinici + Policy Store (trust / identità)
// ==============================================================================

db = db.getSiblingDB('hospital_db');

db.createUser({
  user: 'zta_service_user',
  pwd: 'ZtaSuperSecurePassword2026!',
  roles: [{ role: 'readWrite', db: 'hospital_db' }],
});

// --- Dati clinici ---
db.createCollection('patients');
db.patients.insertMany([
  {
    patient_id: 'P-1001',
    name: 'Mario Rossi',
    age: 45,
    ward: 'Cardiologia',
    blood_type: 'A+',
    sensitive_notes: 'Paziente sieropositivo (HIV+). Prestare attenzione.',
    treatment: 'Betabloccanti',
  },
  {
    patient_id: 'P-1002',
    name: 'Giulia Bianchi',
    age: 32,
    ward: 'Psichiatria',
    blood_type: '0-',
    sensitive_notes: 'Tentativo di suicidio recente. Monitoraggio a vista.',
    treatment: 'Antidepressivi',
  },
  {
    patient_id: 'P-1003',
    name: 'Luca Verdi',
    age: 68,
    ward: 'Ortopedia',
    blood_type: 'B+',
    sensitive_notes: 'Nessuna nota sensibile di rilievo.',
    treatment: 'Fisioterapia',
  },
]);

// --- Policy Store ZTA (identità + trust score) ---
db.createCollection('identities');
db.identities.createIndex({ principal: 1 }, { unique: true });
db.identities.createIndex({ device_name: 1 });

db.identities.insertMany([
  {
    principal: 'spiffe://zta.hospital/ns/default/sa/client-alice',
    device_name: 'alice',
    role: 'medico',
    trust_score: 0.85,
    trust_baseline: 0.85,
    last_network_ip: '',
    updated_at: new Date(),
  },
  {
    principal: 'spiffe://zta.hospital/ns/default/sa/client-bob',
    device_name: 'bob',
    role: 'suspect',
    trust_score: 0.80,
    trust_baseline: 0.80,
    last_network_ip: '',
    updated_at: new Date(),
  },
]);

db.createCollection('trust_history');
db.trust_history.createIndex({ principal: 1, timestamp: -1 });

print('=== ZTA hospital_db initialized (patients + identities + trust_history) ===');
