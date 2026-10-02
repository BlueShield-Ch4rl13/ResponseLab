# Atajos para Linux y macOS. En Windows, los mismos comandos de Python
# funcionan tal cual en PowerShell (ver README).
PY ?= python3

.PHONY: instalar comprobar lint validar compilar generado pruebas escenarios sincronizar servir docker lab

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
