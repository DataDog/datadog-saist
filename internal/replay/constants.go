package replay

const (
	ResultSchemaVersion = 4

	OutcomeConfirmed Outcome = "confirmed"
	OutcomeRejected  Outcome = "rejected"
	OutcomeAbstained Outcome = "abstained"
	OutcomeError     Outcome = "error"
)
