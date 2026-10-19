# Phone lookup (jobs 1 and 4)

Local `phonenumbers` always. Numverify if keyed. Hudson Rock free username endpoint for E.164 (default job 4). DeHashed / LeakCheck / LeakRadar if keyed. No registration probing.

Secrets from `%LOCALAPPDATA%\PhoneLookup\secrets.json` or env, injected into Compose, never baked into the image. Squid sidecar on `172.36.0.0/24`. Passwords redacted in JSON by default.
