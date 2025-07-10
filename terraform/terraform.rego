package terraform

deny contains msg if {
	input.resource_changes[_].type == "null_resource"
	msg := "No se permite crear recursos de tipo null_resource."
}
