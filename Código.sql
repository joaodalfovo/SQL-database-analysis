-- criação do banco
CREATE DATABASE security_lab;

-- conectar no banco (no psql)
-- \c security_lab


-- tabela de logs brutos
CREATE TABLE raw_logs (
    log_line TEXT
);


-- importar logs do sistema
-- antes disso, no linux:
-- sudo journalctl -u ssh > /tmp/auth_logs.txt

COPY raw_logs(log_line)
FROM '/tmp/auth_logs.txt';

-- SELECT para testar coleta de dados do raw_logs
SELECT 
    (regexp_matches(log_line, 'from ([0-9\.]+)'))[1] AS ip,
    COUNT(*) AS tentativas
FROM raw_logs
WHERE log_line ILIKE '%failed password%'
GROUP BY ip
ORDER BY tentativas DESC;

-- tentativas por usuário
SELECT 
    (regexp_matches(log_line, 'for (?:invalid user )?(\w+)'))[1] AS usuario,
    COUNT(*) AS tentativas
FROM raw_logs
WHERE log_line ILIKE '%failed password%'
GROUP BY usuario
ORDER BY tentativas DESC;

-- identificar eventos de limite de autenticação excedido
SELECT 
    (regexp_matches(log_line, 'authentication attempts exceeded for root from ([0-9\.]+)'))[1] AS ip_atacante,
    COUNT(*) AS quantidade
FROM raw_logs
GROUP BY ip_atacante
ORDER BY quantidade DESC;

-- análise temporal (eventos por segundo)
SELECT timestamp
FROM logs
LIMIT 20;

-- tabela estruturada
CREATE TABLE logs (
    timestamp TEXT,
    usuario TEXT,
    ip TEXT,
    status TEXT
);


-- parsing dos logs (extração de campos)
INSERT INTO logs (timestamp, usuario, ip, status)
SELECT 
    substring(log_line FROM '^[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}') AS timestamp,
    (regexp_matches(log_line, 'for (?:invalid user )?(\w+)'))[1] AS usuario,
    (regexp_matches(log_line, 'from ([0-9\.]+)'))[1] AS ip,
    CASE 
        WHEN log_line ILIKE '%failed password%' THEN 'FAILED'
        WHEN log_line ILIKE '%accepted%' THEN 'SUCCESS'
        ELSE 'OTHER'
    END AS status
FROM raw_logs
WHERE log_line ILIKE '%ssh%';



-- consultas usando a tabela estruturada
SELECT ip, COUNT(*) 
FROM logs
WHERE status = 'FAILED'
GROUP BY ip;

SELECT usuario, COUNT(*)
FROM logs
WHERE status = 'FAILED'
GROUP BY usuario;

SELECT timestamp, COUNT(*)
FROM logs
GROUP BY timestamp;
