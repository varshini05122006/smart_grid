# Smart Grid Mutual Authentication (Ascon prototype) - backend core

Academic prototype. Meters are simulated; attack tests are local only. Not production-ready.

## Crypto status (read this)
No maintained library for NIST SP 800-232 **Ascon-AEAD128** was found on PyPI. The `ascon` package (0.0.9) implements the
Ascon v1.2 reference. This build uses its real **Ascon-128a** AEAD and **Ascon-Mac**. It is not interoperable with SP 800-232.
All crypto sits in `crypto.py`, so swapping libraries later is a one-file change.

## Protocol
1. Meter sends `Cm` (random). 2. Server returns session id + random `Cs`, valid `CHALLENGE_TTL_SECONDS`, single use.
3. Meter sends `Rm = Mac(K, "M"|ver|meter|sid|Cs|Cm)`; server verifies in constant time. 4. Server returns `Rs = Mac(K, "S"|...)`; meter verifies.
5. Session key `Ks = Mac(K, "K"|...)`. Session is `authenticated` only after step 3 succeeds.
Readings: Ascon-128a under `Ks`, nonce = strictly increasing sequence number, AAD = version|meter|session|seq. Tag checked before decrypt; seq <= last is a replay.

## Windows setup
    cd backend
    python -m venv venv && venv\Scripts\activate
    pip install -r requirements.txt
    python app.py create-admin admin YourStrongPassword
    uvicorn app:app --reload        (docs at http://localhost:8000/docs)
    python -m pytest -q

## Not done yet
React/Vite frontend (8 pages), login/auth rate limiting, meter PATCH/GET-by-id, readings/communication history, CSV export,
performance benchmark runner + page, DB migrations, MQTT, HTTPS. Keys are stored unencrypted in SQLite (prototype simplification).
