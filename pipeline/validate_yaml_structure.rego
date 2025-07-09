package pipeline

deny contains msg if {
	not input.apiversion
	msg := "Falta el campo 'apiversion'"
}

deny contains msg if {
	not input.kind
	msg := "Falta el campo 'kind'"
}

deny contains msg if {
	not input.metadata.name
	msg := "Falta el campo 'metadata.name"
}
