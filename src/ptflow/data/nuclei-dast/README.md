# PTFlow nuclei DAST pack

`stable/` contains the bundled PTFlow templates. Every template in this directory is executed in both
DAST passes; the passes differ only in their request corpus (observed surface vs discovered delta).

Template IDs must start with `ptflow-`. Every template must use request-part tags such as
`fuzzing-req-query`, have a bounded `max-request`, and live in a separate file for each fuzzing part:
`query`, `body`, `header`, or `cookie`. In-band rules require positive and negative coverage in
`tests/dast/test_custom_templates.py`; OAST rules require strict Interactsh correlation.
