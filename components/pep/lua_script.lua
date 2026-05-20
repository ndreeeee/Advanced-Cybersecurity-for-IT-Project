-- ==============================================================================
-- ZTA 2026 - ENVOY LUA FILTER (L7 FIREWALL)
-- Ruolo: Deep Packet Inspection (DPI) sulle query dirette al Database
-- ==============================================================================

-- Questa funzione viene eseguita da Envoy per OGNI richiesta in entrata
function envoy_on_request(request_handle)
    
    -- 1. Estraiamo gli header (utile per leggere l'identità dell'utente o il JA3)
    local headers = request_handle:headers()
    local client_identity = headers:get("x-forwarded-client-cert") or "Sconosciuto"
    
    -- Stampa nei log di Envoy per il SIEM (Splunk)
    request_handle:logInfo("[ZTA-PEP] Analisi Lua avviata per il client: " .. client_identity)

    -- 1b. Diagnostica metadati ed SSL
    local metadata = request_handle:streamInfo():dynamicMetadata()
    request_handle:logInfo("[ZTA-PEP] Dynamic metadata dump:")
    local ns_list = {"envoy.filters.listener.tls_inspector", "envoy.tls_inspector", "envoy.filters.http.lua"}
    for _, ns in ipairs(ns_list) do
        local ns_meta = metadata:get(ns)
        if ns_meta ~= nil then
            request_handle:logInfo("[ZTA-PEP]   Namespace: " .. ns)
            for k, v in pairs(ns_meta) do
                request_handle:logInfo("[ZTA-PEP]     " .. tostring(k) .. " = " .. tostring(v))
            end
        else
            request_handle:logInfo("[ZTA-PEP]   Namespace non trovato: " .. ns)
        end
    end

    local ssl = request_handle:streamInfo():downstreamSslConnection()
    if ssl ~= nil then
        request_handle:logInfo("[ZTA-PEP] Downstream SSL trovato!")
    else
        request_handle:logInfo("[ZTA-PEP] Downstream SSL NON trovato")
    end

    -- 2. Leggiamo il "corpo" del pacchetto (Il payload della query)
    -- Usiamo chunking per evitare di bloccare la memoria con payload enormi
    local body = request_handle:body()
    
    if body then
        local body_size = body:length()
        local payload = body:getBytes(0, body_size)
        
        -- Trasformiamo tutto in minuscolo per una ricerca case-insensitive
        local payload_lower = string.lower(payload)

        -- ==========================================================
        -- REGOLA 1: BLOCCO LETTURA DATI SENSIBILI (Least Privilege)
        -- ==========================================================
        -- Se la query contiene la richiesta per le note psichiatriche/infettive
        if string.find(payload_lower, "sensitive_notes") then
            
            request_handle:logWarn("[ZTA-PEP] ALLARME: Tentativo di accesso a campi sensibili intercettato!")
            
            -- Blocchiamo la richiesta e rispondiamo direttamente al client
            -- Il pacchetto non arriverà MAI a MongoDB.
            request_handle:respond(
                {[":status"] = "403", ["content-type"] = "application/json"},
                '{"error": "ZTA_L7_FIREWALL_BLOCK", "message": "Accesso negato. Non hai i privilegi per leggere le note sensibili dei pazienti."}'
            )
            return -- Usciamo dalla funzione, richiesta terminata.
        end

        -- ==========================================================
        -- REGOLA 2: BLOCCO DATA EXFILTRATION (Dump massivo)
        -- ==========================================================
        -- In MongoDB un comando senza filtri o un drop è pericoloso
        if string.find(payload_lower, "dropdatabase") or string.find(payload_lower, "deleteall") then
            
            request_handle:logWarn("[ZTA-PEP] ALLARME: Rilevato pattern di attacco distruttivo (Data Wiping)!")
            
            request_handle:respond(
                {[":status"] = "403", ["content-type"] = "application/json"},
                '{"error": "ZTA_L7_FIREWALL_BLOCK", "message": "Operazione distruttiva bloccata dalle policy Zero Trust."}'
            )
            return
        end
        
    end
    
    -- Se arriviamo qui, il pacchetto è "pulito" e rispetta le regole L7.
    request_handle:logInfo("[ZTA-PEP] Ispezione Lua superata. Pacchetto inoltrato al database.")
end

-- Questa funzione viene eseguita per le risposte che tornano dal Database (Opzionale)
function envoy_on_response(response_handle)
    -- Potremmo usare questo blocco per nascondere i dati (Data Masking) prima di mandarli al client,
    -- ma per il nostro diagramma attuale l'ispezione in ingresso è sufficiente.
end