# 🏗️ Architettura Zero Trust (Requisiti 2026)

Basato sulle specifiche del Prof. L. Spalazzi per l'anno accademico 2026.

## 1. Componenti Obbligatori
L'architettura 2026 sostituisce i proxy tradizionali con un'infrastruttura Cloud-Native:
- **PEP (Policy Enforcement Point)**: Implementato tramite **Envoy Proxy**.
- **PDP (Policy Decision Point)**: Implementato tramite **OPA (Open Policy Agent)**.
- **SIEM**: **Splunk**, utilizzato per raccogliere statistiche e log.
- **Firewall di Rete**: **NFTables** (sostituisce IPTables).
- **IDS**: **Snort**, per l'analisi dei payload.
- **DBMS**: **MongoDB** (Policy Store).

## 2. Piani di Comunicazione
- **Control Plane**: OPA + Splunk + MongoDB.
- **Data Plane**: Envoy + NFTables + Snort.

## 3. Identità e Trust
La novità del 2026 è l'enfasi sulla **Device Identity**:
- **Hardware-backed**: Utilizzo di certificati legati al **TPM** (Intel) o **Secure Enclave** (Apple).
- **Software-backed**: Utilizzo del fingerprinting **JA3** per identificare il software client quando l'hardware non è disponibile.

---
*Riferimento: Adv-2026-Project.pdf (Slide 2-8)*
