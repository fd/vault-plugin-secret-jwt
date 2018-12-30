

```
READ   /[mount]/config
WRITE  /[mount]/config idp_url=

LIST   /[mount]/roles/
READ   /[mount]/roles/[name]
WRITE  /[mount]/roles/[name] overrides=<JSON> defaults=<JSON> schema=<JSON> renewable=<BOOL> ttl=<DURATION> max_ttl=<DURATION>
DELETE /[mount]/roles/[name]

WRITE  /[mount]/sign/[role] claims=<JSON>
```
