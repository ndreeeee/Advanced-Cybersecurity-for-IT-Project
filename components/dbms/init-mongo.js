// ==============================================================================
// ZTA 2026 - MONGODB INITIALIZATION SCRIPT (Dominio Ospedaliero)
// Questo script popola il database al primo avvio del container
// ==============================================================================

// 1. Creiamo il database
db = db.getSiblingDB('hospital_db');

// 2. Creiamo un utente di servizio per le connessioni
db.createUser({
  user: "zta_service_user",
  pwd: "ZtaSuperSecurePassword2026!",
  roles: [
    { role: "readWrite", db: "hospital_db" }
  ]
});

// 3. Popoliamo la collezione dei pazienti
db.createCollection('patients');

db.patients.insertMany([
  {
    patient_id: "P-1001",
    name: "Mario Rossi",
    age: 45,
    ward: "Cardiologia",          // Dato a basso rischio (Infermieri)
    blood_type: "A+",
    sensitive_notes: "Paziente sieropositivo (HIV+). Prestare attenzione.", // Dato ad alto rischio (Solo Medici)
    treatment: "Betabloccanti"
  },
  {
    patient_id: "P-1002",
    name: "Giulia Bianchi",
    age: 32,
    ward: "Psichiatria",
    blood_type: "0-",
    sensitive_notes: "Tentativo di suicidio recente. Monitoraggio a vista.",
    treatment: "Antidepressivi"
  },
  {
    patient_id: "P-1003",
    name: "Luca Verdi",
    age: 68,
    ward: "Ortopedia",
    blood_type: "B+",
    sensitive_notes: "Nessuna nota sensibile di rilievo.",
    treatment: "Fisioterapia"
  }
]);

print("=== ZTA HOSPITAL DATABASE INITIALIZED SUCCESSFULLY ===");