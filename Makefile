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
	docker tag $(REPOSITORY):latest ghcr.io/1ndistinct/authapi:latest
	docker push  ghcr.io/1ndistinct/authapi:latest

template:
	if [ ! -f secret_vals.yaml ]; then echo "secrets: {}" > secret_vals.yaml; fi
	helm template ./helm/${PROJECT}-local -f secret_vals.yaml --debug > template.yaml
