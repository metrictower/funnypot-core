FROM --platform=linux/amd64 php@sha256:172e13bc72d4fe6503db39b3ecad301406492ae661e1803138fa45eafc7491f2

ENV LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    HOME=/tmp/home \
    XDG_CONFIG_HOME=/tmp/config \
    XDG_CACHE_HOME=/tmp/cache \
    NO_COLOR=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates unzip \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /opt/reflector/bin /opt/reflector/downloads /opt/reflector/template /opt/reflector/notices \
    && chmod 0755 /opt/reflector /opt/reflector/bin /opt/reflector/downloads /opt/reflector/template /opt/reflector/notices

COPY tests/acceptance/reflector/versions.json /opt/reflector/versions.json
COPY tests/acceptance/reflector/download.php /opt/reflector/download.php
COPY tests/acceptance/reflector/template/reflected-xss.yaml /opt/reflector/template/reflected-xss.yaml
COPY tests/acceptance/reflector/notices/ /opt/reflector/notices/

RUN php /opt/reflector/download.php \
    && test "$(unzip -Z1 /opt/reflector/downloads/nuclei_3.11.1_linux_amd64.zip | grep -c '^nuclei$')" = 1 \
    && unzip -p /opt/reflector/downloads/nuclei_3.11.1_linux_amd64.zip nuclei > /opt/reflector/bin/nuclei \
    && test "$(tar -tzf /opt/reflector/downloads/dalfox-v3.2.2-linux-x86_64-musl.tar.gz | grep -c '^dalfox-v3.2.2-linux-x86_64-musl/dalfox$')" = 1 \
    && tar -xOzf /opt/reflector/downloads/dalfox-v3.2.2-linux-x86_64-musl.tar.gz dalfox-v3.2.2-linux-x86_64-musl/dalfox > /opt/reflector/bin/dalfox \
    && chmod 0555 /opt/reflector/bin/nuclei /opt/reflector/bin/dalfox \
    && rm -rf /opt/reflector/downloads /opt/reflector/download.php

WORKDIR /workspace
COPY src/ /workspace/src/
COPY resources/compiled/ /workspace/resources/compiled/
COPY tests/acceptance/reflector/ /workspace/tests/acceptance/reflector/

RUN find /workspace/src /workspace/resources/compiled -type f -print0 \
    | sort -z \
    | xargs -0 sha256sum \
    | sha256sum \
    | cut -d ' ' -f 1 > /opt/reflector/core-tree.sha256 \
    && cp /workspace/tests/acceptance/reflector/ReceiptVerifier.php /opt/reflector/ReceiptVerifier.php \
    && cp /workspace/tests/acceptance/reflector/collect.php /opt/reflector/collect.php \
    && chmod -R a-w /workspace /opt/reflector

ENTRYPOINT ["timeout", "--signal=TERM", "--kill-after=5", "480", "bash", "/workspace/tests/acceptance/reflector/execute.sh"]
