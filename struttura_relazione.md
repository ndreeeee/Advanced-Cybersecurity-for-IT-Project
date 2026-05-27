# Proposta di Struttura per la Relazione Accademica: Zero Trust Architecture

Di seguito è presentata una scaletta formale per la stesura della relazione finale del progetto. La struttura è stata ideata per mantenere un tono accademico, rigoroso e metodologico, ideale per una presentazione universitaria.

---

## 1. Introduzione
*Questa sezione definisce il contesto generale, illustrando le motivazioni teoriche che giustificano l'adozione del paradigma Zero Trust.*
*   **1.1 Contesto e Obiettivi del Progetto:** Definizione dei requisiti previsti dal tema d'esame (Anno 2026) e degli obiettivi primari raggiunti dall'implementazione.
*   **1.2 Dal Modello Perimetrale al Paradigma Zero Trust:** Analisi critica dei limiti intrinseci ai modelli di sicurezza basati sul perimetro (es. VPN tradizionali) e introduzione dei principi cardine del modello ZTA (*Never Trust, Always Verify*).
*   **1.3 Scenario Applicativo (Dominio Ospedaliero):** Descrizione del caso di studio adottato, focalizzato sulla protezione di dati clinici sensibili e sulla differenziazione degli accessi (personale interno vs. telelavoro).

## 2. Progettazione Architetturale
*In questo capitolo viene esposta la topologia del sistema e vengono definiti i ruoli dei vari nodi, fornendo una visione d'insieme prima di scendere nel dettaglio del codice.*
*   **2.1 Topologia di Rete e Micro-segmentazione:** Illustrazione della suddivisione logica dell'infrastruttura in compartimenti isolati (Rete Esterna, Rete Frontend/DMZ, Rete di Controllo, Rete Backend), giustificando le scelte di segregazione.
*   **2.2 Stack Tecnologico e Componenti di Sicurezza:**
    *   *Policy Enforcement Point (PEP)*: Il ruolo del proxy Envoy nell'intercettazione del traffico e nell'estrazione dei metadati.
    *   *Policy Decision Point (PDP)*: Il motore decisionale Open Policy Agent (OPA) e l'approccio basato su policy as code (Rego).
    *   *SIEM e Machine Learning*: L'impiego di Splunk (MLTK) per la valutazione dinamica e predittiva delle minacce.
    *   *Sicurezza di Rete Integrata*: Utilizzo congiunto di firewall L3/L4 (NFTables) e NIDS (Snort).
*   **2.3 Le Sei Dimensioni del Paradigma Zero Trust (ZTA 6D):** Formalizzazione teorica dei sei vettori di analisi utilizzati per la profilazione delle richieste: *User, Device, Software, Network, Action* e *Resource*.

## 3. Dettagli Implementativi e Flussi Operativi
*Questa sezione costituisce il nucleo tecnico dell'elaborato. Si consiglia di inserire brevi estratti di codice (snippet) per avvalorare le soluzioni ingegneristiche adottate.*
*   **3.1 Autenticazione Mutua (mTLS) e Gestione delle Identità:**
    *   Gestione infrastrutturale dei certificati crittografici.
    *   Validazione hardware dell'identità tramite l'estrazione dell'Object Identifier (OID) associato al modulo TPM.
    *   Riconoscimento passivo del software tramite l'algoritmo di fingerprinting JA3.
*   **3.2 Il Processo di Autorizzazione Adattiva:**
    *   Analisi del flusso di comunicazione RPC (Remote Procedure Call) tra Envoy e OPA.
    *   Algoritmo di calcolo dinamico del Livello di Rischio (*Trust Score*) tramite l'interfacciamento tra OPA e il modello di Machine Learning.
*   **3.3 Deep Packet Inspection (DPI) al Livello Applicativo (L7):**
    *   Esposizione delle metodologie adottate per l'ispezione avanzata dei payload, distinguendo l'approccio per il traffico HTTP e la soluzione implementata per filtrare nativamente il protocollo binario di MongoDB.

## 4. Scenari di Simulazione e Risultati Sperimentali
*Il capitolo empirico in cui si convalida l'architettura. In ogni sottoparagrafo andranno inseriti i relativi diagrammi di flusso (Flowchart Mermaid) precedentemente generati.*
*   **4.1 Scenario 1 - Identity & Device Verification:** Dimostrazione del blocco delle richieste provenienti da dispositivi privi di chip TPM, a parità di credenziali fornite.
*   **4.2 Scenario 2 - Rilevamento Anomalie e Insider Threat:** Simulazione di un attacco di tipo SQL Injection da parte di un utente legittimo e conseguente blocco dinamico generato dall'impennata del Trust Score.
*   **4.3 Scenario 3 - Prevenzione del Movimento Laterale:** Verifica della robustezza delle regole di rete a fronte di un tentativo di elusione del proxy (Bypass) volto a colpire direttamente i servizi di Backend.
*   **4.4 Scenario 4 - Accesso Condizionato Adattivo:** Dimostrazione dell'adattabilità delle policy di sicurezza in funzione del contesto ambientale (es. variazioni della soglia di tolleranza al rischio in caso di connessione da rete esterna).

## 5. Analisi Critica e Sviluppi Futuri
*Sezione dedicata all'esposizione di uno spirito critico e ingegneristico nei confronti del proprio lavoro.*
*   **5.1 Valutazione dell'Overhead Architetturale:** Discussione tecnica sull'impatto prestazionale (es. latenza introdotta dai molteplici passaggi di autorizzazione) derivante dall'implementazione del modello Zero Trust.
*   **5.2 Efficacia delle Misure di Sicurezza:** Sintesi del livello di mitigazione raggiunto contro vettori di attacco noti e minacce zero-day.
*   **5.3 Possibili Sviluppi Futuri:** Proposte per l'evoluzione del sistema, quali l'integrazione di sistemi di Identity and Access Management (es. Keycloak) o standard per l'emissione dinamica dei certificati (SPIFFE/SPIRE).

## 6. Conclusioni
*   Considerazioni conclusive sul raggiungimento degli obiettivi didattici e sulle potenzialità applicative dell'infrastruttura realizzata in contesti aziendali complessi.
