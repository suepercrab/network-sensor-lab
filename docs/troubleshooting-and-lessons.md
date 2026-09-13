# Build Notes, Troubleshooting & Lessons Learned

The problems I hit building this were more instructive than the clean parts, so I'm documenting them honestly.

## 1. Zeek writes JSON, not TSV — `zeek-cut` returns nothing

Most Zeek tutorials read logs with `zeek-cut`. That silently fails on Security Onion, because SO configures Zeek to output **JSON**, and `zeek-cut` needs the TSV `#fields` header. Running `cat conn.log | zeek-cut ...` returned empty output and made it look like the sensor wasn't logging — it was however, I was just parsing it wrong.

**Fix:** parse with `jq` instead.

```bash
sudo cat /nsm/zeek/spool/logger/conn.log | jq '{ "orig": .["id.orig_h"], "resp": .["id.resp_h"], service, orig_bytes, resp_bytes }'
```

Note JSON keys with dots (`id.orig_h`) are literal keys, so in `jq` they're `.["id.orig_h"]`, not `.id.orig_h`.

## 2. `/nsm/zeek/logs/current/` rotates — the live logs are in `spool/logger/`

This is the one that cost me the most time, and it's the answer to *"why could I only see a detection in the web UI sometimes and not on the command line?"*

`/nsm/zeek/logs/current/` rotates every hour and on every container restart. After a rotation it's emptied and the logs move to a dated, compressed folder. So while verifying the payload retrieval, \cat /nsm/zeek/logs/current/files.log` would return` **"no such file or directory"** even though the data existed — because it had just rotated out, or the container had restarted. Meanwhile the **web UI still showed everything**, because Elasticsearch had already ingested the records. That's the whole "web UI works, command line doesn't" symptom: the console reads from Elasticsearch, the command line reads from a directory that rotates.

**Fix:** for live command line reads, use the spool path, which is where the running logger always writes:

```bash
sudo ls /nsm/zeek/spool/logger/
sudo cat /nsm/zeek/spool/logger/conn.log | jq .
```

Takeaway: the console and the raw logs are two different data paths. When they disagree, the console (Elasticsearch) is usually right and the raw `current/` directory has just rotated.

## 3. Zeek didn't carve the payload file — Suricata caught it instead

For payload retrieval I expected `files.log` to give me a SHA-256 of the transferred file. On my build, `files.log` returned no hash — SHA-256 file hashing is not guaranteed on by default in stock Zeek, and it wasn't producing one here. I confirmed the retrieval a different way: **Suricata** fired three signatures and its alert contained the **reconstructed HTTP GET request** with the filename. See [detections/03-payload-retrieval.md](../detections/03-payload-retrieval.md). Noticing the gap in one engine and pivoting to another is an analyst move.
