REPOSITORY := authapi
include ~/pypi_creds
SHELL := /bin/bash

build:
	docker build --network=host \
	-f ./Dockerfile \
	--build-arg="PYPI_USER=${PYPI_USER}" \
	--build-arg="PYPI_PASS=${PYPI_PASS}" \
	--target production \
	-t ghcr.io/1ndistinct/$(REPOSITORY):latest \
	. 

up: 
	docker compose up -d --remove-orphans
	if [ "$(PGADMIN)" == "true" ]; then docker compose --profile pgadmin up -d; fi
	echo "sleeping to allow services to start up..."
	sleep 15
	export PGADMIN=$(PGADMIN) && bash ./scripts/browser.sh
	docker compose logs -f 

pgadmin: 
	docker compose --profile pgadmin up -d
	echo "sleeping to allow services to start up..."
	sleep 15
	export PGADMIN=true && \
	export DOCS=false && \
	bash ./scripts/browser.sh

debug:
	docker compose run -it $(REPOSITORY) bash

down: 
	docker compose --profile "*" down


push: build
	docker push ghcr.io/1ndistinct/$(REPOSITORY):latest

template:
	if [ ! -f secret_vals.yaml ]; then echo "secrets: {}" > secret_vals.yaml; fi
	helm template ./helm/$(REPOSITORY) -f secret_vals.yaml --debug > template.yaml

test: 
	docker run --rm -p 5431:5432 --name test-db --env POSTGRES_USER=postgres --env POSTGRES_DB=postgres --env POSTGRES_PASSWORD=postgres -d postgres:16
	sleep 0.2
	pytest -vv  tests  || :
	docker kill test-db

migrate:
	docker compose run --entrypoint "python -m alembic -c $(REPOSITORY)/database/alembic.ini revision --autogenerate -m '$(m)'" $(REPOSITORY)