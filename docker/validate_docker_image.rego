package docker

import rego.v1

# Lista de repositorios aprobados
approved_repos := ["registry.empresa.com/", "docker.io/empresa/"]

deny contains msg if {
	input.kind == "Dockerfile"
	not startswith(input.image, approved_repos)
	msg := sprintf("La imagen '%s' no proviene de un repositorio aprovado", [input.image])
}
