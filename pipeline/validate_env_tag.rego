package pipeline

deny contains msg if {
	input.kind == "Deployment"
	not input.metadata.labels.environment
	msg := "Falta la etiqueta 'environment' en metadata.labels"
}

deny contains msg if {
	input.kind == "Deployment"
	input.metadata.labels.environment != "produccion"
	msg := sprintf("La etiqueta 'environment' debe ser 'produccion', no '%s'", [input.metadata.labels.environment])
}
