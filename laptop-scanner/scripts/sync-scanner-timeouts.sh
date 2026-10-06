#!/bin/sh
# Keep gvmd's NVT timeout floors at the scanner profile.
# openvas.conf and task preferences are not what kills the Nmap NVT:
# plugin_timeout() uses nvt_preferences, and a feed sync can restore 60/90.
plugins="${PLUGINS_TIMEOUT_SEC:-320}"
scanner="${SCANNER_PLUGINS_TIMEOUT_SEC:-36000}"
echo "scanner timeout floor plugins_timeout=${plugins} scanner_plugins_timeout=${scanner}"
while true; do
  if psql -U gvmd -d gvmd -v ON_ERROR_STOP=1 \
      -v plugins="$plugins" -v scanner="$scanner" <<'SQL'
UPDATE nvt_preferences
   SET value = :'scanner'
 WHERE name = 'scanner_plugins_timeout'
   AND value ~ '^[0-9]+$'
   AND value::int < (:'scanner')::int;
UPDATE nvt_preferences
   SET value = :'plugins'
 WHERE name = 'plugins_timeout'
   AND value ~ '^[0-9]+$'
   AND value::int < (:'plugins')::int;
INSERT INTO nvt_preferences (name, value, pref_nvt, pref_id, pref_type, pref_name)
VALUES (
  '1.3.6.1.4.1.25623.1.0.14259:0:entry:timeout',
  :'scanner',
  '1.3.6.1.4.1.25623.1.0.14259',
  0,
  'entry',
  'timeout'
)
ON CONFLICT (name) DO UPDATE
  SET value = EXCLUDED.value
  WHERE nvt_preferences.value ~ '^[0-9]+$'
    AND nvt_preferences.value::int < (EXCLUDED.value)::int;
SQL
  then
    echo "timeout floor applied"
  else
    echo "timeout floor waiting for gvmd database"
  fi
  sleep 300
done
