package docker

import rego.v1

approved_repos := ["registry.empresa.com/", "docker.io/empresa/"]

# Valida imágenes en recursos tipo Deployment
deny contains msg if {
	input.kind == "Deployment"
	container := input.spec.template.spec.containers[_]
	not approved(container.image)
	msg := sprintf("La imagen '%s' no proviene de un repositorio aprobado (docker)", [container.image])
}

approved(image) if {
	some i
	startswith(image, approved_repos[i])
}
