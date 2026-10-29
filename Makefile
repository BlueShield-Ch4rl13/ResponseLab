# Atajos para Linux y macOS. En Windows, los mismos comandos de Python
# funcionan tal cual en PowerShell (ver README).
PY ?= python3

.PHONY: instalar comprobar lint validar compilar generado pruebas escenarios sincronizar servir docker lab \
        preparar servidor ca comprobar-servidor copia restaurar

instalar:            ## dependencias de desarrollo
	$(PY) -m pip install -r requirements-dev.txt

comprobar: lint validar generado pruebas escenarios   ## todo lo que ejecuta el CI

lint:
	ruff check .

validar:             ## catalogo, contratos con el ecosistema e invariantes
	$(PY) tools/validar.py

compilar:            ## regenera catalogo y artefactos de SOAR y SIEM
	$(PY) tools/compilar.py

generado:            ## falla si lo generado no coincide con las fuentes
	$(PY) tools/compilar.py --comprobar

pruebas:
	$(PY) -m pytest -q

escenarios:          ## los ataques de escenarios/ contra el motor
	$(PY) tools/simular.py

sincronizar:         ## trae los cambios del ecosistema
	$(PY) tools/sincronizar.py

servir:              ## motor en local (simulacion)
	RL_SIMULACION_GLOBAL=true $(PY) -m responselab servir --puerto 8080

docker:
	docker compose up -d --build

lab:                 ## motor en simulacion y escenarios contra el
	docker compose -f docker-compose.yml -f docker-compose.lab.yml up -d --build
	docker compose -f docker-compose.yml -f docker-compose.lab.yml run --rm escenarios

# ── Servidor del laboratorio (docs/SERVIDOR.md) ─────────────────────────────
MOTOR ?= 10.0.30.20
URL ?= https://$(MOTOR):8443

preparar:            ## servidor: .env con secretos y config para Wazuh, Splunk y pfSense (MOTOR=, DOMINIO=, TLS=)
	$(PY) tools/preparar_servidor.py --motor $(MOTOR) $(if $(DOMINIO),--dominio $(DOMINIO)) $(if $(TLS),--tls $(TLS))

servidor:            ## servidor: motor, proxy y copias (usa COMPOSE_FILE de .env)
	docker compose up -d --build --wait

ca:                  ## servidor: saca la CA del proxy (solo con RL_TLS=internal)
	docker compose cp proxy:/data/caddy/pki/authorities/local/root.crt ./responselab-ca.pem

comprobar-servidor:  ## servidor: comprueba el motor desplegado (URL=, CA=)
	$(PY) tools/comprobar_despliegue.py --url $(URL) $(if $(CA),--ca $(CA)) --conectividad

copia:               ## servidor: una copia verificada del estado, ahora
	docker compose exec -T copias python -m responselab copia --destino /copias

restaurar:           ## servidor: vuelve a una copia (COPIA=responselab-AAAAMMDDTHHMMSSZ.db)
	@test -n "$(COPIA)" || { echo "COPIA=responselab-....db (ls copias/)"; exit 1; }
	docker compose stop motor copias
	docker compose run --rm --no-deps -v "$(CURDIR)/copias:/copias:ro" --entrypoint sh motor -c \
	  'cp /copias/$(COPIA) /var/lib/responselab/responselab.db && rm -f /var/lib/responselab/responselab.db-wal /var/lib/responselab/responselab.db-shm'
	docker compose up -d --wait
