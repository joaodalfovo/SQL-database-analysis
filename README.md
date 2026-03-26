# Análise de Logs de Segurança com PostgreSQL
## 🔐 Visão Geral

Este projeto demonstra a construção de um pipeline de análise de segurança utilizando PostgreSQL, onde logs reais de um sistema Linux são coletados, processados e analisados para identificar comportamentos suspeitos, como tentativas massivas de autenticação.

Os dados utilizados neste laboratório são provenientes de ataques previamente simulados em outro home lab (red-and-blue-team lab), permitindo uma análise baseada em eventos reais gerados durante atividades ofensivas controladas.

O projeto utiliza SQL com expressões regulares (regex) para extrair, estruturar e correlacionar informações relevantes diretamente dos logs, reproduzindo um cenário prático de investigação e detecção de incidentes.

## 🧠 Arquitetura do Lab
```
Logs do sistema (journalctl)
        ↓
PostgreSQL (security_lab)
        ↓
Análise com SQL
```

## 🧰 Tecnologias Utilizadas

PostgreSQL

Linux (Ubuntu/Kali)

SQL (queries avançadas + regex)

Logs do sistema (journalctl)

## 🏗️ Configuração do Banco de Dados
📌 Criação do banco
```
CREATE DATABASE security_lab;
```
📌 Tabela de logs brutos

Tabela criada para armazenar os logs exatamente como são gerados pelo sistema:
```
CREATE TABLE raw_logs (
    log_line TEXT
);
```
📥 Coleta e Ingestão de Logs
📌 Exportação dos logs

Os logs foram coletados diretamente do sistema utilizando:

sudo journalctl -u ssh > /tmp/auth_logs.txt

```
COPY raw_logs(log_line)
FROM '/tmp/auth_logs.txt';
```

<img width="1292" height="451" alt="image" src="https://github.com/user-attachments/assets/0c566264-562c-4791-90fa-05477feca9c2" />

Resultado: milhares de linhas de logs reais inseridas na tabela

<img width="1087" height="264" alt="image" src="https://github.com/user-attachments/assets/c67526cd-d322-4e39-8f20-e737db1e5fbe" />

## 🔍 Exploração inicial dos logs brutos

Antes de estruturar os dados, foi realizada uma análise direta na tabela raw_logs para entender o conteúdo dos logs e identificar padrões relevantes.

Foram utilizadas consultas com LIKE e regex para filtrar eventos específicos, como falhas de autenticação e origem dos acessos.

Exemplo de identificação de tentativas de login por IP:

<img width="628" height="223" alt="image" src="https://github.com/user-attachments/assets/531c4c5b-7452-4840-82aa-5dbd88d2e55f" />

Além disso, foi possível identificar eventos onde o sistema bloqueou tentativas excessivas de autenticação:

<img width="945" height="169" alt="image" src="https://github.com/user-attachments/assets/a23c7d98-9fdb-4762-b7eb-b58dcaa26db4" />

Essa análise permitiu identificar rapidamente comportamentos suspeitos, como múltiplas tentativas de autenticação originadas do mesmo endereço IP.

## 🧱 Estruturação dos Dados

Após a ingestão, foi criada uma segunda tabela para armazenar os dados de forma estruturada:
```
CREATE TABLE logs (
    timestamp TEXT,
    usuario TEXT,
    ip TEXT,
    status TEXT
);
```
🧠 Processamento e Parsing com SQL

Os dados foram extraídos da tabela bruta (raw_logs) utilizando regex diretamente no SQL:
```
INSERT INTO logs (timestamp, usuario, ip, status)
SELECT 
    substring(log_line FROM '^[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}') AS timestamp,
    (regexp_matches(log_line, 'for (?:invalid user )?(\w+)'))[1],
    (regexp_matches(log_line, 'from ([0-9\.]+)'))[1],
    CASE 
        WHEN log_line ILIKE '%failed password%' THEN 'FAILED'
        WHEN log_line ILIKE '%accepted%' THEN 'SUCCESS'
        ELSE 'OTHER'
    END
FROM raw_logs
WHERE log_line ILIKE '%ssh%';
```

## 🔍 Técnicas de Análise
Identificação de tentativas de autenticação falhas
```
SELECT ip, COUNT(*) AS tentativas
FROM logs
WHERE status = 'FAILED'
GROUP BY ip
ORDER BY tentativas DESC;
```
## Resultado

192.168.56.129 → mais de 2400 tentativas

<img width="611" height="259" alt="image" src="https://github.com/user-attachments/assets/5e24e596-7971-4ca3-9bad-faf0bbfd9671" />

Indício claro de comportamento automatizado

## 👤 Análise por usuário
```
SELECT usuario, COUNT(*) AS tentativas
FROM logs
WHERE status = 'FAILED'
GROUP BY usuario
ORDER BY tentativas DESC;
```
## Resultado

root → alvo principal

<img width="210" height="106" alt="image" src="https://github.com/user-attachments/assets/2787c870-7c2b-4f4c-ba03-d841696e456f" />

fakeuser → tentativa de enumeração de usuários

## ⏱️ Análise temporal
```
SELECT timestamp
FROM logs
LIMIT 20;
```

## 📊 Insight

Múltiplos eventos no mesmo segundo

<img width="276" height="453" alt="image" src="https://github.com/user-attachments/assets/ee5867d4-047b-428e-8234-3fad6e17a4cd" />

Alta frequência de tentativas

👉 Evidência de ataque automatizado

## 🔗 Correlação de Eventos

A análise permitiu correlacionar:

IP de origem

usuário alvo

tipo de evento

frequência

## 🚨 Resumo do Incidente

Tipo de ataque	- Força bruta
IP de origem	- 192.168.56.129
Usuário alvo	- root
Tentativas falhas -	2400+
Bloqueios (limite excedido) -	401
Comportamento	Automatizado


## 🧠 Habilidades Demonstradas

Ingestão de logs com SQL

Uso de regex em PostgreSQL

Estruturação de dados

Detecção de ataques

Análise temporal

Investigação de incidentes

## 💬 Conclusão

Este projeto demonstra como é possível utilizar apenas SQL para:

processar logs reais

extrair informações relevantes

identificar padrões maliciosos

detectar ataques de forma eficaz

A análise confirmou um ataque automatizado com milhares de tentativas de autenticação originadas de um único IP, evidenciando um cenário típico de força bruta.
