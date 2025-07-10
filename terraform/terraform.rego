package terraform

import future.keywords.contains
import future.keywords.if

deny contains msg if {
	some rc in input.resource_changes
	rc.type == "google_compute_instance"
	msg := sprintf("Siempre falla para la instancia %v", [rc.name])
}
