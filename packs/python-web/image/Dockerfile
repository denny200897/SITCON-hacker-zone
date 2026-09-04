# packs/python-web 映像（SPEC §17.10：v1 一律本地構建；digest 記錄 ~/.cache/aegis/images.json）
# 人類可讀 tag：aegis-python-web:3.12（tag 只用於發佈；manifest 與 runtime 必須記錄並使用 digest）
FROM python:3.12-slim

# nonroot user 65532（§7.1）；/aegis 目錄結構
RUN groupadd -g 65532 aegis && useradd -m -u 65532 -g 65532 aegis \
    && mkdir -p /aegis/pack /aegis/witness /aegis/out /aegis/wheels \
    && chown -R 65532:65532 /aegis

# pack 內容物（observer／entrypoint／模板／trace shim）
COPY sandbox/ /aegis/pack/
COPY templates/ /aegis/templates/

# 常用框架預裝層（§6.3）：python-web v1 首波涵蓋 Flask（FastAPI 由 requirements 隨 build 補）
RUN pip install --no-cache-dir "flask==3.0.3"

# /aegis/out 由 entrypoint chown 給 65532（§17.10）
RUN chmod +x /aegis/pack/entrypoint.py \
    && cp /aegis/pack/entrypoint.py /aegis/entrypoint.py

ENV PYTHONPATH=/aegis/pack \
    PYTHONDONTWRITEBYTECODE=1 \
    AEGIS_SQL_TRACE=/aegis/out/sql_trace.jsonl

USER 65532:65532
WORKDIR /aegis