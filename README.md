## Polycom VVX Default Credential Checker

Login checker for endpoints that use Basic Authentication on `/form-submit/auth.htm`.

The script tries two default credential combinations against each host/URL:
- Polycom:456
- User:123

It reports success only when the HTTP response body contains `lockparams|SUCCESS|0` and a cookie named `session` is set.

### Hosts file
Provide a file with one target per line. Each line may be an IP/hostname (scheme will default to `https`) or a full URL.

```text
https://10.10.97.23:443
https://10.10.97.24:443
https://10.10.96.7:443
```

### Usage

```bash
python3 PolycomVVX_defaultcredcheck.py --file hosts.txt

# Optional flags
#   --path /form-submit/auth.htm   # override endpoint path
#   --timeout 10                   # request timeout (seconds)
#   --verify                       # enable TLS verification (off by default)
```

### Output
For each host, the script prints one or more lines indicating the result for each credential pair until success or exhaustion:

```text
https://10.10.97.23:443	FAIL	Polycom:456	status=401
https://10.10.97.23:443	SUCCESS	User:123	session=abcd1234...
```

### Notes
- TLS verification is disabled by default to accommodate self-signed certs on IPs. Use `--verify` to enable verification.
- Exit code is `2` if the hosts file is empty or missing; `0` otherwise.
