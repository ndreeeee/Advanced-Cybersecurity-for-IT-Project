import csv
import random

def generate_dataset(filename="simulated_traffic.csv", num_records=10000):
    print("Inizio generazione del dataset di traffico simulato...")
    
    with open(filename, mode='w', newline='') as file:
        writer = csv.writer(file)
        # Intestazione coerente con la tupla (u, s, d, n, a, r) + rischio
        writer.writerow(["user", "software", "device", "network", "action", "resource", "rischio"])

        for _ in range(num_records):
            # L'80% del traffico è "Normale" (basso rischio)
            if random.random() > 0.2:
                u = random.choice(["alice.medico", "mario.rossi", "luigi.verdi"])
                s = random.choice(["e7afb57c_cert", "mozilla_firefox_112", "chrome_115"])
                d = random.choice(["1.3.6.1.4.1.311.21.9", "tpm_enclave_88"]) # OID validi
                n = random.choice(["10.0.0.15", "192.168.1.50"]) # IP Interni
                a = random.choice(["find", "insert", "update", "authenticate"])
                r = random.choice(["utenti", "pazienti", "cartelle_cliniche"])
                
                # Rischio basso per comportamenti normali
                rischio = random.randint(0, 30)
            else:
                # Il 20% del traffico è "Anomalo/Attacco" (alto rischio)
                u = random.choice(["admin", "anonymous", "hacker", "mario.rossi"])
                s = random.choice(["curl_7.68", "nmap", "custom_python_script"]) # Strumenti strani
                d = random.choice(["unknown", "missing_tpm"]) # No hardware identity
                n = random.choice(["93.44.12.1", "1.2.3.4", "8.8.8.8"]) # IP Esterni
                a = random.choice(["delete", "drop", "find"])
                r = random.choice(["system_logs", "config_db", "pazienti"])
                
                # Rischio alto per comportamenti sospetti
                rischio = random.randint(70, 100)

            writer.writerow([u, s, d, n, a, r, rischio])
            
    print(f"Completato! Dataset salvato in {filename} ({num_records} record generati).")
    print("Ora puoi caricare questo file CSV in Splunk e usare MLTK con il comando:")
    print('| fit RandomForestRegressor "rischio" from user, software, device, network, action, resource into trust_model')

if __name__ == "__main__":
    generate_dataset()
