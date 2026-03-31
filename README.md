# Slack Community Threat-Intel (ATproto Edition) - Project Context

## Project Overview
This project is a Proof of Concept (POC) for a private, serverless threat intelligence network designed for slack members in a trusted community. For example a network of CISOs could use it to sponsor automated machine readers and writers that share threat indicators (IoCs) in real-time.

## Why
Realtime trusted threat intel is difficult to find. You need a trusted community, trusted sources and mechanisms to vet and share indicators. Usually the transport is via office documents (PDF, .docx. .xls) or one off messages in a chat platform. 

What if we gave a trusted community (any slack instance in this case), the means to sponsor and host their own threat intelligence feed? 

## How
Members login via a web portal using oauth tied to their slack identity. The system checks to see if they are in the slack 'team' (instance) matching the portal. 

Once in the portal, the member can create reader/writer API keys that can be subsequently used to produce or consume threat intel using the AT PROTO https://atproto.com/

## Architecture

See the [architecture spec](atproto-threat-intel-PRD.md)

## Example POC Sessions

Producer:

```shell

uv run producer_client.py jeffbryner.com URL  "Bad URL Hombre"
INFO:httpx:HTTP Request: POST http://localhost:8000/v1/submit "HTTP/1.1 200 OK"
INFO:__main__:✅ Submission successful: {'status': 'published', 'message_id': '19110516955299668'}
(atproto-threat-intel)  atproto-threat-intel % uv run producer_client.py 127.0.0.1 IP "Bad Hombre"
INFO:httpx:HTTP Request: POST http://localhost:8000/v1/submit "HTTP/1.1 200 OK"
INFO:__main__:✅ Submission successful: {'status': 'published', 'message_id': '18713718098346843'}
```

Consumer: 
```shell 
atproto-threat-intel % uv run consumer_client.py --since 1d
INFO:httpx:HTTP Request: GET http://localhost:8000/v1/public-key "HTTP/1.1 200 OK"
INFO:__main__:--- Syncing Historical Feed (Lookback: 1d, Limit: 50) ---
INFO:httpx:HTTP Request: GET http://localhost:8000/v1/indicators?limit=50&since=2026-03-30T18%3A36%3A28.448351%2B00%3A00 "HTTP/1.1 200 OK"
INFO:__main__:Verified History: [URL] jeffbryner.com - 2026-03-30T23:43:10.566095+00:00
INFO:__main__:Verified History: [IP] 127.0.0.1 - 2026-03-30T23:43:35.645614+00:00
INFO:__main__:--- Switching to Real-time Firehose ---
INFO:__main__:Connected to firehose at ws://localhost:8000/v1/firehose
```