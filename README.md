git clone https://github.com/daranett/project-radius.git
cd project-radius
docker compose up -d --build
docker compose ps
docker compose logs -f
jika sudah running semua bisa langsung akses dashboard
http://your.ip:5000
bisa juga via https,, recommend dengan traefik
