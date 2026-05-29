import csv
import random

def generate_dataset(filename="simulated_traffic.csv", num_records=10000):
    """
    Genera un dataset di traffico simulato per l'addestramento del modello
    GradientBoostingRegressor su Splunk MLTK.

    Il dataset include le 6 dimensioni ZTA originali (u, s, d, n, a, r) più
    6 feature comportamentali aggiuntive per la Continuous Evaluation:
      - failed_logins:    Tentativi di autenticazione falliti nelle ultime 24h
      - hour_of_day:      Ora della richiesta (0-23)
      - is_night:         Flag booleano per accesso notturno (22:00-06:00)
      - session_freq:     Numero di sessioni dell'utente nell'ultima ora
      - sensitivity_level: Livello di sensibilità della risorsa (1=bassa, 3=alta)
      - days_inactive:    Giorni dall'ultima autenticazione riuscita dell'utente

    Il campo 'rischio' è calcolato deterministicamente come somma pesata
    dei fattori di rischio, non più assegnato casualmente.
    """
    print("Inizio generazione del dataset di traffico simulato (v2 - Comportamentale)...")

    # === DEFINIZIONI DEGLI UTENTI E DEI PROFILI ===

    # Utenti legittimi del dominio ospedaliero
    legit_users = ["alice.medico", "mario.rossi", "luigi.verdi"]
    # Utenti sospetti / anomali
    suspect_users = ["admin", "anonymous", "hacker", "mario.rossi"]

    # Software fidati (fingerprint JA3 noti)
    legit_software = ["e7afb57c_cert", "mozilla_firefox_112", "chrome_115"]
    # Software sospetti (tool di attacco o script custom)
    suspect_software = ["curl_7.68", "nmap", "custom_python_script"]

    # Dispositivi con attestazione hardware (TPM / Secure Enclave)
    legit_devices = ["1.3.6.1.4.1.311.21.9", "tpm_enclave_88"]
    # Dispositivi senza attestazione hardware
    suspect_devices = ["unknown", "missing_tpm"]

    # Reti interne ospedaliere
    internal_ips = ["10.0.0.15", "192.168.1.50"]
    # Reti esterne (Smart Working, Wi-Fi pubblico, IP sconosciuti)
    external_ips = ["93.44.12.1", "1.2.3.4", "8.8.8.8"]

    # Azioni normali vs distruttive
    legit_actions = ["find", "insert", "update", "authenticate"]
    suspect_actions = ["delete", "drop", "find"]

    # Risorse e i loro livelli di sensibilità
    resource_sensitivity = {
        "utenti": 1,              # Bassa sensibilità
        "pazienti": 2,            # Media sensibilità
        "cartelle_cliniche": 3,   # Alta sensibilità
        "system_logs": 2,         # Media sensibilità
        "config_db": 3,           # Alta sensibilità
    }
    legit_resources = ["utenti", "pazienti", "cartelle_cliniche"]
    suspect_resources = ["system_logs", "config_db", "pazienti"]

    with open(filename, mode='w', newline='') as file:
        writer = csv.writer(file)
        # Intestazione con le 12 feature + target
        writer.writerow([
            "user", "software", "device", "network", "action", "resource",
            "failed_logins", "hour_of_day", "is_night",
            "session_freq", "sensitivity_level", "days_inactive",
            "rischio"
        ])

        for _ in range(num_records):
            # ============================================================
            # L'80% del traffico è "Normale" (basso rischio)
            # ============================================================
            if random.random() > 0.2:
                u = random.choice(legit_users)
                s = random.choice(legit_software)
                d = random.choice(legit_devices)
                n = random.choice(internal_ips)
                a = random.choice(legit_actions)
                r = random.choice(legit_resources)

                # Feature comportamentali tipiche di un utente legittimo
                failed_logins = random.choices(
                    [0, 1, 2],
                    weights=[0.80, 0.15, 0.05]
                )[0]
                hour_of_day = random.choices(
                    list(range(7, 20)),   # Orario lavorativo 07:00-19:00
                    weights=[2, 5, 8, 10, 10, 8, 10, 10, 8, 5, 3, 2, 1]
                )[0]
                is_night = 0  # Mai di notte per traffico normale
                session_freq = random.randint(1, 10)  # Attività moderata
                days_inactive = random.choices(
                    [0, 1, 2, 3, 5, 7],
                    weights=[0.50, 0.20, 0.10, 0.10, 0.05, 0.05]
                )[0]

            # ============================================================
            # Il 20% del traffico è "Anomalo/Attacco" (alto rischio)
            # ============================================================
            else:
                u = random.choice(suspect_users)
                s = random.choice(suspect_software)
                d = random.choice(suspect_devices)
                n = random.choice(external_ips)
                a = random.choice(suspect_actions)
                r = random.choice(suspect_resources)

                # Feature comportamentali tipiche di un attaccante
                failed_logins = random.choices(
                    [3, 5, 7, 10],
                    weights=[0.30, 0.30, 0.25, 0.15]
                )[0]
                hour_of_day = random.choices(
                    [0, 1, 2, 3, 4, 5, 22, 23],  # Orari notturni
                    weights=[0.15, 0.15, 0.15, 0.15, 0.10, 0.10, 0.10, 0.10]
                )[0]
                is_night = 1  # Accesso notturno
                session_freq = random.choices(
                    [15, 20, 30, 50],
                    weights=[0.20, 0.30, 0.30, 0.20]
                )[0]
                days_inactive = random.choices(
                    [30, 60, 90, 180, 365],
                    weights=[0.30, 0.25, 0.20, 0.15, 0.10]
                )[0]

            # ============================================================
            # CALCOLO DETERMINISTICO DEL RISCHIO (somma pesata)
            # ============================================================
            sensitivity_level = resource_sensitivity.get(r, 1)

            rischio = 0

            # 1. Dispositivo senza attestazione hardware TPM (+20)
            if d in suspect_devices:
                rischio += 20

            # 2. Rete esterna (+15)
            if n in external_ips:
                rischio += 15

            # 3. Login falliti: fino a +40 (8 punti per tentativo, cap a 40)
            rischio += min(failed_logins * 8, 40)

            # 4. Accesso notturno (+10)
            if is_night == 1:
                rischio += 10

            # 5. Frequenza sessioni anomala: se > 20 sessioni/ora (+5)
            if session_freq > 20:
                rischio += 5

            # 6. Sensibilità della risorsa: fino a +20
            rischio += 10 * (sensitivity_level - 1)

            # 7. Inattività prolungata: +5 ogni 30 giorni, fino a +15
            rischio += min((days_inactive // 30) * 5, 15)

            # 8. Azione distruttiva (+15)
            if a in ["delete", "drop"]:
                rischio += 15

            # 9. Software sospetto (+5)
            if s in suspect_software:
                rischio += 5

            # Cap massimo a 100
            rischio = min(rischio, 100)

            # Aggiunta di rumore gaussiano leggero (±3) per evitare valori identici
            # e rendere il modello più robusto a piccole variazioni
            rumore = int(random.gauss(0, 3))
            rischio = max(0, min(100, rischio + rumore))

            writer.writerow([
                u, s, d, n, a, r,
                failed_logins, hour_of_day, is_night,
                session_freq, sensitivity_level, days_inactive,
                rischio
            ])

    print(f"Completato! Dataset salvato in {filename} ({num_records} record generati).")
    print(f"Colonne: user, software, device, network, action, resource,")
    print(f"         failed_logins, hour_of_day, is_night, session_freq, sensitivity_level, days_inactive, rischio")
    print()
    print("Ora puoi caricare questo file CSV in Splunk e usare MLTK con il comando:")
    print('| fit GradientBoostingRegressor "rischio" from user, software, device, network, action, resource, failed_logins, hour_of_day, is_night, session_freq, sensitivity_level, days_inactive into trust_model')

if __name__ == "__main__":
    generate_dataset()
