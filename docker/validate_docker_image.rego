package docker

import rego.v1

# Lista de repositorios aprobados
approved_repos := ["registry.empresa.com/", "docker.io/empresa/"]

deny contains msg if {
    input.kind == "Dockerfile"
    not approved(input.image)
    msg := sprintf("La imagen '%s' no proviene de un repositorio aprobado", [input.image])
}

approved(image) if {
    some i
    startswith(image, approved_repos[i])
}