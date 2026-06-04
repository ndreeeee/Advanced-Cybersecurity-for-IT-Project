import csv
import random
import math

def generate_dataset(filename="simulated_traffic.csv", num_records=50000):
    """
    Genera un dataset di traffico simulato per l'addestramento del modello
    GradientBoostingRegressor su Splunk MLTK.

    PROFILI UTENTE:
    ===============
    - Alice:   Dipendente legittimo, TPM verificato, rete INTERNA → rischio ~0-10
    - Bob:     Dipendente senza TPM, rete INTERNA, comportamento variabile → rischio ~30-50
    - Charlie: Dipendente legittimo in SMART WORKING, TPM verificato, rete ESTERNA
               → rischio moderato (~20-35) per via della rete, NON un attaccante
    - Attaccanti (hacker_x, intruder_7, script_kiddie, insider_threat, apt_agent):
               Profili di attacco realistici con combinazioni pericolose → rischio 60-100

    FORMULA DEL RISCHIO (v4 - Corretta):
    =====================================
    Il rischio è costruito su 3 livelli:
      A) INFRASTRUTTURALE: TPM (+30 se assente) + Rete (+18 se esterna)
         → La rete esterna da sola non è catastrofica (Charlie ha TPM!)
         → L'assenza di TPM è il fattore più grave
      B) COMPORTAMENTALE: login falliti, orario, frequenza sessioni, inattività,
         azione distruttiva, software sospetto
      C) MOLTIPLICATORE SENSIBILITÀ: amplifica il rischio comportamentale
         in base alla criticità della risorsa
    """
    print("Inizio generazione del dataset di traffico simulato (v4 - Corretta)...")

    # === DEFINIZIONI ===

    # Software fidati
    legit_software = ["chrome_115", "mozilla_firefox_112", "edge_120"]
    # Software sospetti
    suspect_software = ["curl_7.68", "nmap", "custom_python_script", "metasploit_6"]

    # Dispositivi con TPM
    tpm_devices = ["tpm_enclave_88", "tpm_enclave_42"]
    # Dispositivi senza TPM
    no_tpm_devices = ["unknown", "missing_tpm"]

    # Reti interne ospedaliere
    internal_ips = ["10.0.0.15", "10.0.0.22", "10.0.0.31", "10.0.0.48"]
    # Reti esterne (Smart Working, VPN casa, Wi-Fi pubblico)
    external_ips = ["93.44.12.1", "1.2.3.4", "8.8.8.8", "185.220.101.5"]

    # Azioni
    safe_actions = ["find", "authenticate"]
    moderate_actions = ["insert", "update"]
    dangerous_actions = ["delete", "drop"]

    # Risorse e sensibilità
    resource_sensitivity = {
        "utenti": 1,
        "pazienti": 2,
        "cartelle_cliniche": 3,
        "system_logs": 2,
        "config_db": 3,
    }

    # ============================================================
    # PROFILI UTENTE
    # ============================================================
    profiles = {

        # -------------------------------------------------------
        # ALICE: Dipendente legittimo, TPM, rete interna
        # Rischio atteso: 0-10 (bassissimo)
        # -------------------------------------------------------
        "alice": {
            "weight": 0.30,
            "software_pool":  legit_software,
            "device_pool":    tpm_devices,
            "network_pool":   internal_ips,
            "action_pool":    safe_actions + moderate_actions,
            "action_weights": [0.35, 0.15, 0.30, 0.20],
            "resource_pool":  ["utenti", "pazienti", "cartelle_cliniche"],
            "resource_weights": [0.30, 0.45, 0.25],
            "failed_logins":  {"min": 0, "max": 1, "weights": [0.92, 0.08]},
            "hour_pool":      list(range(7, 20)),
            "hour_weights":   [2, 5, 8, 10, 10, 8, 10, 10, 8, 5, 3, 2, 1],
            "session_freq":   {"min": 1, "max": 6},
            "days_inactive":  {"min": 0, "max": 2, "weights": [0.70, 0.20, 0.10]},
        },

        # -------------------------------------------------------
        # BOB: Dipendente senza TPM, rete interna
        # Rischio atteso: 30-50 (medio-alto, penalizzato dal no-TPM)
        # -------------------------------------------------------
        "bob": {
            "weight": 0.20,
            "software_pool":  legit_software + ["curl_7.68"],
            "device_pool":    no_tpm_devices,
            "network_pool":   internal_ips,
            "action_pool":    safe_actions + moderate_actions + ["delete"],
            "action_weights": [0.25, 0.15, 0.20, 0.15, 0.25],
            "resource_pool":  ["pazienti", "cartelle_cliniche", "system_logs"],
            "resource_weights": [0.40, 0.35, 0.25],
            "failed_logins":  {"min": 0, "max": 3, "weights": [0.35, 0.30, 0.20, 0.15]},
            "hour_pool":      list(range(6, 22)),
            "hour_weights":   [2, 4, 6, 8, 8, 7, 8, 8, 7, 6, 5, 4, 3, 3, 2, 2],
            "session_freq":   {"min": 2, "max": 15},
            "days_inactive":  {"min": 0, "max": 7, "weights": None},
        },

        # -------------------------------------------------------
        # CHARLIE: Dipendente legittimo in SMART WORKING
        # Ha il TPM (è un dipendente vero!), ma si collega da RETE ESTERNA.
        # Rischio atteso: 18-35 (moderato, penalizzato solo dalla rete)
        # -------------------------------------------------------
        "charlie": {
            "weight": 0.20,
            "software_pool":  legit_software,
            "device_pool":    tpm_devices,       # Charlie HA il TPM!
            "network_pool":   external_ips,       # Ma lavora da fuori
            "action_pool":    safe_actions + moderate_actions,
            "action_weights": [0.40, 0.15, 0.30, 0.15],
            "resource_pool":  ["utenti", "pazienti", "cartelle_cliniche"],
            "resource_weights": [0.35, 0.40, 0.25],
            "failed_logins":  {"min": 0, "max": 1, "weights": [0.85, 0.15]},
            "hour_pool":      list(range(8, 21)),
            "hour_weights":   [3, 6, 8, 9, 9, 8, 9, 9, 7, 5, 4, 3, 2],
            "session_freq":   {"min": 1, "max": 8},
            "days_inactive":  {"min": 0, "max": 3, "weights": [0.55, 0.25, 0.12, 0.08]},
        },

        # -------------------------------------------------------
        # ATTACCANTE LEGGERO (hacker_x): Script kiddie esterno
        # No TPM, rete esterna, pochi login falliti, azioni moderate
        # Rischio atteso: 55-75 (alto)
        # -------------------------------------------------------
        "hacker_x": {
            "weight": 0.08,
            "software_pool":  suspect_software,
            "device_pool":    no_tpm_devices,
            "network_pool":   external_ips,
            "action_pool":    safe_actions + moderate_actions + ["delete"],
            "action_weights": [0.25, 0.10, 0.20, 0.15, 0.30],
            "resource_pool":  ["pazienti", "system_logs", "config_db"],
            "resource_weights": [0.40, 0.30, 0.30],
            "failed_logins":  {"min": 1, "max": 4, "weights": [0.30, 0.30, 0.25, 0.15]},
            "hour_pool":      list(range(0, 24)),
            "hour_weights":   [5, 5, 4, 4, 3, 3, 3, 4, 5, 5, 5, 5,
                               5, 5, 5, 5, 4, 4, 4, 4, 4, 5, 5, 5],
            "session_freq":   {"min": 8, "max": 25},
            "days_inactive":  {"min": 10, "max": 60, "weights": None},
        },

        # -------------------------------------------------------
        # ATTACCANTE PESANTE (intruder_7): APT con credenziali rubate
        # No TPM, rete esterna, molti login falliti, azioni distruttive
        # Rischio atteso: 80-100 (critico)
        # -------------------------------------------------------
        "intruder_7": {
            "weight": 0.06,
            "software_pool":  ["metasploit_6", "custom_python_script", "nmap"],
            "device_pool":    no_tpm_devices,
            "network_pool":   external_ips,
            "action_pool":    dangerous_actions + ["find"],
            "action_weights": [0.35, 0.35, 0.30],
            "resource_pool":  ["config_db", "cartelle_cliniche", "system_logs"],
            "resource_weights": [0.40, 0.35, 0.25],
            "failed_logins":  {"min": 4, "max": 10, "weights": None},
            "hour_pool":      [0, 1, 2, 3, 4, 5, 22, 23],
            "hour_weights":   [15, 15, 15, 12, 10, 8, 12, 13],
            "session_freq":   {"min": 20, "max": 50},
            "days_inactive":  {"min": 30, "max": 180, "weights": None},
        },

        # -------------------------------------------------------
        # SCRIPT KIDDIE (script_kiddie): Attacco automatizzato leggero
        # No TPM, rete esterna, frequenza sessioni altissima
        # Rischio atteso: 60-85
        # -------------------------------------------------------
        "script_kiddie": {
            "weight": 0.06,
            "software_pool":  ["curl_7.68", "custom_python_script", "nmap"],
            "device_pool":    no_tpm_devices,
            "network_pool":   external_ips,
            "action_pool":    safe_actions + ["delete", "drop"],
            "action_weights": [0.20, 0.10, 0.35, 0.35],
            "resource_pool":  ["pazienti", "config_db", "system_logs"],
            "resource_weights": [0.35, 0.35, 0.30],
            "failed_logins":  {"min": 2, "max": 7, "weights": None},
            "hour_pool":      list(range(0, 24)),
            "hour_weights":   [6, 6, 5, 5, 5, 4, 3, 3, 4, 4, 4, 4,
                               4, 4, 4, 4, 4, 4, 4, 4, 4, 5, 6, 6],
            "session_freq":   {"min": 25, "max": 50},
            "days_inactive":  {"min": 0, "max": 90, "weights": None},
        },

        # -------------------------------------------------------
        # INSIDER THREAT (insider_threat): Dipendente corrotto
        # Ha il TPM (è un dipendente vero), rete INTERNA, ma fa azioni
        # sospette (delete, drop) con frequenza anomala
        # Rischio atteso: 20-55 (variabile, insidioso)
        # -------------------------------------------------------
        "insider_threat": {
            "weight": 0.05,
            "software_pool":  legit_software + ["custom_python_script"],
            "device_pool":    tpm_devices,       # È un dipendente con TPM
            "network_pool":   internal_ips,       # Lavora dall'ufficio
            "action_pool":    moderate_actions + dangerous_actions + ["find"],
            "action_weights": [0.10, 0.10, 0.30, 0.30, 0.20],
            "resource_pool":  ["cartelle_cliniche", "config_db", "system_logs"],
            "resource_weights": [0.35, 0.40, 0.25],
            "failed_logins":  {"min": 0, "max": 3, "weights": [0.30, 0.25, 0.25, 0.20]},
            "hour_pool":      [0, 1, 2, 3, 22, 23, 12, 13, 14],
            "hour_weights":   [14, 14, 12, 10, 14, 14, 8, 7, 7],
            "session_freq":   {"min": 5, "max": 30},
            "days_inactive":  {"min": 0, "max": 5, "weights": None},
        },

        # -------------------------------------------------------
        # APT AGENT (apt_agent): Attaccante avanzato persistente
        # No TPM, mix di rete interna/esterna (ha compromesso la VPN),
        # azioni furtive + burst distruttivi
        # Rischio atteso: 45-90
        # -------------------------------------------------------
        "apt_agent": {
            "weight": 0.05,
            "software_pool":  suspect_software + ["chrome_115"],
            "device_pool":    no_tpm_devices,
            "network_pool":   internal_ips + external_ips,
            "action_pool":    safe_actions + dangerous_actions,
            "action_weights": [0.20, 0.10, 0.35, 0.35],
            "resource_pool":  ["config_db", "cartelle_cliniche", "system_logs", "pazienti"],
            "resource_weights": [0.30, 0.30, 0.20, 0.20],
            "failed_logins":  {"min": 1, "max": 8, "weights": None},
            "hour_pool":      [0, 1, 2, 3, 4, 5, 11, 12, 13, 22, 23],
            "hour_weights":   [12, 12, 10, 10, 8, 8, 6, 6, 6, 10, 12],
            "session_freq":   {"min": 5, "max": 40},
            "days_inactive":  {"min": 5, "max": 120, "weights": None},
        },
    }

    # Prepara selezione pesata
    user_names = list(profiles.keys())
    user_weights = [profiles[u]["weight"] for u in user_names]

    with open(filename, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow([
            "user", "software", "device", "network", "action", "resource",
            "failed_logins", "hour_of_day", "is_night",
            "session_freq", "sensitivity_level", "days_inactive",
            "rischio"
        ])

        for _ in range(num_records):
            # Seleziona utente
            u = random.choices(user_names, weights=user_weights)[0]
            p = profiles[u]

            # Genera le 6 dimensioni ZTA
            s = random.choice(p["software_pool"])
            d = random.choice(p["device_pool"])
            n = random.choice(p["network_pool"])

            a_pool = p["action_pool"]
            a_w = p.get("action_weights")
            a = random.choices(a_pool, weights=a_w)[0] if a_w else random.choice(a_pool)

            r_pool = p["resource_pool"]
            r_w = p.get("resource_weights")
            r = random.choices(r_pool, weights=r_w)[0] if r_w else random.choice(r_pool)

            # Genera le 6 feature comportamentali
            fl_cfg = p["failed_logins"]
            fl_range = list(range(fl_cfg["min"], fl_cfg["max"] + 1))
            if fl_cfg.get("weights"):
                failed_logins = random.choices(fl_range, weights=fl_cfg["weights"])[0]
            else:
                failed_logins = random.randint(fl_cfg["min"], fl_cfg["max"])

            hour_of_day = random.choices(p["hour_pool"], weights=p["hour_weights"])[0]
            is_night = 1 if (hour_of_day >= 22 or hour_of_day < 6) else 0

            sf_cfg = p["session_freq"]
            session_freq = random.randint(sf_cfg["min"], sf_cfg["max"])

            di_cfg = p["days_inactive"]
            di_range = list(range(di_cfg["min"], di_cfg["max"] + 1))
            if di_cfg.get("weights"):
                days_inactive = random.choices(di_range, weights=di_cfg["weights"])[0]
            else:
                days_inactive = random.randint(di_cfg["min"], di_cfg["max"])

            sensitivity_level = resource_sensitivity[r]

            # ============================================================
            # CALCOLO DETERMINISTICO DEL RISCHIO (v4)
            # ============================================================
            #
            # ARCHITETTURA A 3 LIVELLI:
            #
            #   Livello A - INFRASTRUTTURALE (TPM + Rete)
            #     - Assenza TPM:     +30 (il fattore più grave)
            #     - Rete esterna:    +18 (grave, ma non catastrofico da solo)
            #     - Combo no TPM + esterna: +7 extra
            #
            #   Livello B - COMPORTAMENTALE (azioni, orari, frequenze)
            #     - Login falliti:   progressivo fino a +25
            #     - Accesso notturno: +5
            #     - Frequenza alta:  fino a +7
            #     - Inattività:      fino a +8
            #     - Azione distruttiva: +8
            #     - Software sospetto: +4
            #
            #   Livello C - MOLTIPLICATORE SENSIBILITÀ
            #     - Amplifica il rischio comportamentale (NON l'infrastrutturale)
            #     - Livello 1: x1.0 | Livello 2: x1.15 | Livello 3: x1.35
            #
            # RISULTATO ATTESO PER PROFILO:
            #   Alice   (TPM + interna + pulita):     ~0-10
            #   Charlie (TPM + esterna + pulita):     ~18-35
            #   Bob     (no TPM + interna + misto):   ~30-50
            #   Insider (TPM + interna + malevolo):   ~20-55
            #   hacker_x (no TPM + esterna + leggero): ~55-75
            #   script_kiddie (no TPM + esterna + auto): ~60-85
            #   apt_agent (no TPM + mix rete + furtivo): ~45-90
            #   intruder_7 (no TPM + esterna + pesante): ~80-100
            # ============================================================

            # --- A) RISCHIO INFRASTRUTTURALE ---
            rischio_infra = 0.0

            is_no_tpm = d in no_tpm_devices
            is_external = n in external_ips

            if is_no_tpm:
                rischio_infra += 30

            if is_external:
                rischio_infra += 18

            # Combo: entrambi anomali = minaccia critica
            if is_no_tpm and is_external:
                rischio_infra += 7

            # --- B) RISCHIO COMPORTAMENTALE ---
            rischio_comp = 0.0

            # B1. Login falliti (scala progressiva, max +25)
            if failed_logins > 0:
                rischio_comp += min(
                    failed_logins * 3.5 + math.log2(failed_logins + 1) * 2.5,
                    25
                )

            # B2. Accesso notturno (+5)
            if is_night:
                rischio_comp += 5

            # B3. Frequenza sessioni anomala (max +7)
            if session_freq > 30:
                rischio_comp += 7
            elif session_freq > 20:
                rischio_comp += 4
            elif session_freq > 10:
                rischio_comp += 2

            # B4. Inattività: +2 ogni 15 giorni (max +8)
            rischio_comp += min((days_inactive // 15) * 2, 8)

            # B5. Azione distruttiva (+8)
            if a in dangerous_actions:
                rischio_comp += 8

            # B6. Software sospetto (+4)
            if s in suspect_software:
                rischio_comp += 4

            # --- C) MOLTIPLICATORE SENSIBILITÀ ---
            # Amplifica SOLO il comportamentale.
            # Se il comportamento è pulito (~0), il moltiplicatore non cambia nulla.
            sensitivity_mult = 1.0 + (sensitivity_level - 1) * 0.175
            rischio_comp_amplificato = rischio_comp * sensitivity_mult

            # --- RISCHIO FINALE ---
            rischio = rischio_infra + rischio_comp_amplificato

            # Cap [0, 100]
            rischio = max(0.0, min(100.0, rischio))

            # Rumore gaussiano (±2) per robustezza
            rumore = random.gauss(0, 2)
            rischio = max(0, min(100, int(round(rischio + rumore))))

            writer.writerow([
                u, s, d, n, a, r,
                failed_logins, hour_of_day, is_night,
                session_freq, sensitivity_level, days_inactive,
                rischio
            ])

    print(f"Completato! Dataset salvato in {filename} ({num_records} record).")
    print()
    print("Distribuzione dei profili:")
    print("  alice          (30%): TPM + rete interna + pulita        -> rischio ~0-10")
    print("  bob            (20%): NO TPM + rete interna + misto     -> rischio ~30-50")
    print("  charlie        (20%): TPM + rete ESTERNA + pulita       -> rischio ~18-35")
    print("  insider_threat  (5%): TPM + rete interna + malevolo     -> rischio ~20-55")
    print("  hacker_x        (8%): NO TPM + rete esterna + leggero   -> rischio ~55-75")
    print("  script_kiddie   (6%): NO TPM + rete esterna + bot       -> rischio ~60-85")
    print("  apt_agent       (5%): NO TPM + mix rete + furtivo       -> rischio ~45-90")
    print("  intruder_7      (6%): NO TPM + rete esterna + pesante   -> rischio ~80-100")
    print()
    print("Riaddestrare il modello su Splunk:")
    print('| inputlookup simulated_traffic.csv')
    print('| fit GradientBoostingRegressor "rischio" from user, software, device, network,')
    print('  action, resource, failed_logins, hour_of_day, is_night, session_freq,')
    print('  sensitivity_level, days_inactive into trust_model')


if __name__ == "__main__":
    generate_dataset()
