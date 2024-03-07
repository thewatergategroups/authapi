REPOSITORY := authapi
include ~/pypi_creds

build:
	docker build --network=host \
	-f docker/Dockerfile \
	--build-arg="PYPI_USER=${PYPI_USER}" \
	--build-arg="PYPI_PASS=${PYPI_PASS}" \
	. -t $(REPOSITORY)

run: build up

api:
	docker compose run api 

up: 
	docker compose up -d --remove-orphans
	docker compose logs -f 

debug:
	docker compose run -it $(REPOSITORY) bash

down: 
	docker compose down


push: build
	docker tag $(REPOSITORY):latest ghcr.io/1ndistinct/$(REPOSITORY):latest
	docker push  ghcr.io/1ndistinct/$(REPOSITORY):latest

template:
	if [ ! -f secret_vals.yaml ]; then echo "secrets: {}" > secret_vals.yaml; fi
	helm template ./helm/$(REPOSITORY) -f secret_vals.yaml --debug > template.yaml

test: 
	docker run --rm -p 5431:5432 --name test-db --env POSTGRES_USER=postgres --env POSTGRES_DB=postgres --env POSTGRES_PASSWORD=postgres -d postgres:16
	sleep 0.2
	pytest tests || :
	docker kill test-db