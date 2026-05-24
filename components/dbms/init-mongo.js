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
      sensitive_notes: 'Paziente sieropositivo (HIV+). Seguire protocolli di sicurezza per rischio biologico.',
      treatment: 'Betabloccanti, Terapia Antiretrovirale (ART)'
    },
    {
      patient_id: 'P-1002',
      name: 'Giulia Bianchi',
      age: 32,
      ward: 'Psichiatria',
      blood_type: '0-',
      sensitive_notes: 'Recente tentativo di autolesionismo. Necessita di monitoraggio visivo a intervalli di 15 minuti. Rischio di fuga.',
      treatment: 'Antidepressivi SSRI, Terapia cognitivo-comportamentale'
    },
    {
      patient_id: 'P-1003',
      name: 'Luca Verdi',
      age: 68,
      ward: 'Ortopedia',
      blood_type: 'B+',
      sensitive_notes: 'Nessuna nota sensibile di rilievo. Paziente collaborativo.',
      treatment: 'Fisioterapia intensiva post-operatoria, Analgesici al bisogno'
    },
    {
      patient_id: 'P-1004',
      name: 'Elena Neri',
      age: 27,
      ward: 'Ginecologia',
      blood_type: 'AB+',
      sensitive_notes: 'Interruzione volontaria di gravidanza (IVG). Massima riservatezza richiesta dal paziente verso i familiari.',
      treatment: 'Antibiotici profilattici, Supporto psicologico'
    },
    {
      patient_id: 'P-1005',
      name: 'Alessandro Conti',
      age: 54,
      ward: 'Oncologia',
      blood_type: 'A-',
      sensitive_notes: 'Diagnosi terminale. La famiglia non è ancora stata informata completamente per volontà del paziente.',
      treatment: 'Chemioterapia palliativa, Gestione del dolore (Morfina)'
    },
    {
      patient_id: 'P-1006',
      name: 'Sofia Esposito',
      age: 19,
      ward: 'Malattie Infettive',
      blood_type: '0+',
      sensitive_notes: 'Infezione da Neisseria gonorrhoeae (Gonorrea). Paziente minorenne al momento del contagio, possibile situazione di abuso domestico da indagare.',
      treatment: 'Ceftriaxone, Segnalazione ai servizi sociali pendente'
    },
    {
      patient_id: 'P-1007',
      name: 'Marco Ricci',
      age: 41,
      ward: 'Neurologia',
      blood_type: 'B-',
      sensitive_notes: 'Paziente affetto da SLA in fase avanzata. Ha depositato DAT (Disposizioni Anticipate di Trattamento) per rifiuto accanimento terapeutico.',
      treatment: 'Riluzolo, Supporto respiratorio non invasivo'
    },
    {
      patient_id: 'P-1008',
      name: 'Francesca Romano',
      age: 82,
      ward: 'Geriatria',
      blood_type: 'A+',
      sensitive_notes: 'Demenza senile avanzata. Episodi di aggressività improvvisa verso il personale sanitario.',
      treatment: 'Neurolettici a basso dosaggio, Assistenza continua'
    },
    {
      patient_id: 'P-1009',
      name: 'Matteo Colombo',
      age: 35,
      ward: 'Terapia Intensiva',
      blood_type: 'AB-',
      sensitive_notes: 'Coinvolto in grave incidente stradale. Positività a cocaina e oppiacei nel sangue al momento del ricovero. Possibili complicanze legali in corso.',
      treatment: 'Coma farmacologico indotto, Ventilazione meccanica'
    },
    {
      patient_id: 'P-1010',
      name: 'Chiara Ferrari',
      age: 50,
      ward: 'Chirurgia Generale',
      blood_type: '0+',
      sensitive_notes: 'Nessuna nota sensibile di rilievo. Intervento di appendicectomia eseguito senza complicazioni.',
      treatment: 'Monitoraggio post-operatorio, Dimissioni previste in 48h'
    }
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
