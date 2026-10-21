\getenv app_password POSTGRES_APP_PASSWORD

CREATE ROLE trustvault_app LOGIN PASSWORD :'app_password';
