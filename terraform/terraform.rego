package terraform

import future.keywords.contains
import future.keywords.if
import future.keywords.in

# Tipos de máquina permitidos
allowed_machine_types := ["e2-micro", "e2-small", "f1-micro"]

deny contains msg if {
	some resource in input.resource_changes

	# Validación 1: Siempre falla para instancias (regla de prueba)
	resource.type == "google_compute_instance"
	msg := sprintf("Siempre falla para la instancia %v", [resource.name])
}

deny contains msg if {
	some resource in input.resource_changes

	# Validación 2: Firewall abierto a 0.0.0.0/0
	resource.type == "google_compute_firewall"
	"0.0.0.0/0" in resource.change.after.source_ranges
	msg := "La regla de firewall no puede permitir el acceso desde 0.0.0.0/0"
}

deny contains msg if {
	some resource in input.resource_changes

	# Validación 3: VM sin label environment
	resource.type == "google_compute_instance"
	not resource.change.after.labels.environment
	msg := "La máquina virtual debe tener el label 'environment'"
}

deny contains msg if {
	some resource in input.resource_changes

	# Validación 4: VM sin label owner
	resource.type == "google_compute_instance"
	not resource.change.after.labels.owner
	msg := "La máquina virtual debe tener el label 'owner'"
}

deny contains msg if {
	some resource in input.resource_changes

	# Validación 5: Tipo de máquina no permitido
	resource.type == "google_compute_instance"
	not resource.change.after.machine_type in allowed_machine_types
	msg := sprintf("Tipo de máquina %v no permitido. Tipos permitidos: %v", [
		resource.change.after.machine_type,
		allowed_machine_types,
	])
}
