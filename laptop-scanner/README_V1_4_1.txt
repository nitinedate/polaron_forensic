Aetheris Laptop Scanner v1.4.1
Greenbone Full-and-fast feed readiness fix

Existing install:
  1. Apply the v1.4.1 hotfix.
  2. cd D:\laptop-scanner
  3. .\Repair-Greenbone-Feed.cmd
  4. docker compose exec -T scanner-agent python /app/check_greenbone_ready.py

Do not delete Docker volumes.
