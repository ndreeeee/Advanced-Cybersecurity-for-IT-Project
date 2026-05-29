# Struttura della Relazione: Zero Trust Architecture

Ecco la scaletta per la relazione finale del progetto. L'obiettivo è presentare il lavoro in modo chiaro, diretto e pratico, andando dritti al punto senza perdersi in troppi formalismi.

---

## 1. Introduzione
*Spieghiamo l'idea di base: perché abbiamo fatto questo progetto e a cosa serve.*
*   **1.1 Obiettivi:** Cosa prevedeva il tema d'esame e cosa abbiamo effettivamente realizzato.
*   **1.2 Perché Zero Trust?** I limiti delle reti classiche (es. le classiche VPN) e perché l'approccio "Zero Trust" (*Non fidarti mai, verifica sempre*) è più sicuro.
*   **1.3 Il Caso di Studio (Ospedale):** Il contesto pratico che abbiamo scelto: proteggere i dati medici e gestire chi si collega dall'ufficio o in smart working.

## 2. Come è fatta l'Architettura
*Una panoramica semplice di come è costruita la rete e degli strumenti utilizzati.*
*   **2.1 La Struttura della Rete:** Come abbiamo diviso il sistema in zone (Esterna, DMZ/Frontend, Controllo, Backend) per isolare i servizi.
*   **2.2 Gli Strumenti Principali:**
    *   *Envoy*: Il proxy che intercetta tutto il traffico.
    *   *OPA*: Il "cervello" che decide chi ha i permessi e chi no.
    *   *Splunk e Machine Learning*: Il sistema che analizza i comportamenti e valuta i rischi in tempo reale.
    *   *Firewall e NIDS*: Le difese di base della rete (NFTables e Snort).
*   **2.3 Cosa controlliamo (Le 6 Dimensioni):** Su cosa ci basiamo per dare l'accesso (chi è l'utente, che dispositivo usa, da dove si collega, ecc.).

## 3. L'Implementazione: Come funziona davvero
*Il cuore tecnico della relazione. Inseriremo alcuni pezzi di codice (snippet) per mostrare le configurazioni più interessanti.*
*   **3.1 Riconoscere Utenti e Dispositivi:**
    *   L'uso dei certificati (mTLS) per far parlare i servizi.
    *   Il controllo del chip TPM per essere sicuri che il dispositivo sia aziendale.
    *   Come capiamo quali app vengono usate (Fingerprinting JA3).
*   **3.2 Come diamo i permessi (Autorizzazione):**
    *   Come si parlano Envoy e OPA.
    *   Come calcoliamo il livello di rischio (*Trust Score*) usando il modello di Machine Learning.
*   **3.3 Guardare dentro i pacchetti (DPI):**
    *   Come filtriamo e blocchiamo il traffico HTTP e le query di MongoDB pericolose.

## 4. Test e Risultati
*I test concreti per dimostrare che il sistema funziona, accompagnati da diagrammi di flusso e screenshot.*
*   **4.1 Test 1 - Dispositivo non autorizzato:** Cosa succede se l'utente ha la password giusta, ma usa un PC personale senza TPM? (Spoiler: viene bloccato).
*   **4.2 Test 2 - Comportamento anomalo:** Un dipendente regolare prova a lanciare un attacco SQL. Il suo punteggio di rischio sale oltre la soglia e scatta il blocco.
*   **4.3 Test 3 - Tentativo di bypass:** Qualcuno cerca di saltare i controlli di Envoy e puntare dritto al database. I firewall di rete lo fermano.
*   **4.4 Test 4 - Smart Working:** Come cambiano le regole se ci si collega da casa rispetto a quando si è in ufficio.

## 5. Pro e Contro
*Un'analisi onesta dei risultati del progetto.*
*   **5.1 Prestazioni:** Tutti questi controlli rallentano la rete? Quanto pesa questo sistema in termini di latenza?
*   **5.2 Efficacia:** Da cosa ci protegge davvero questa architettura e quali sono i suoi limiti.
*   **5.3 Miglioramenti Futuri:** Idee per migliorare il progetto, come integrare un sistema per la gestione degli utenti (es. Keycloak).

## 6. Conclusioni
*   Breve riepilogo finale dei risultati ottenuti e di cosa abbiamo imparato implementando il paradigma Zero Trust.
