// Package cvss implements CVSS 3.1 base score calculation.
// Reference: https://www.first.org/cvss/v3.1/specification-document
package cvss

import "math"

// BaseMetrics holds CVSS 3.1 base metric inputs.
type BaseMetrics struct {
	AV string // Attack Vector:         N(etwork) A(djacent) L(ocal) P(hysical)
	AC string // Attack Complexity:     L(ow) H(igh)
	PR string // Privileges Required:   N(one) L(ow) H(igh)
	UI string // User Interaction:      N(one) R(equired)
	S  string // Scope:                 U(nchanged) C(hanged)
	C  string // Confidentiality:       N(one) L(ow) H(igh)
	I  string // Integrity:             N(one) L(ow) H(igh)
	A  string // Availability:          N(one) L(ow) H(igh)
}

// Calculate returns the CVSS 3.1 base score (0.0–10.0).
func Calculate(m BaseMetrics) float64 {
	av := avScore(m.AV)
	ac := acScore(m.AC)
	pr := prScore(m.PR, m.S)
	ui := uiScore(m.UI)

	// Impact sub-score
	iss := 1 - (1-impactScore(m.C))*(1-impactScore(m.I))*(1-impactScore(m.A))

	var impact float64
	if m.S == "U" {
		impact = 6.42 * iss
	} else {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	}

	if impact <= 0 {
		return 0
	}

	exploitability := 8.22 * av * ac * pr * ui

	var base float64
	if m.S == "U" {
		base = math.Min(impact+exploitability, 10)
	} else {
		base = math.Min(1.08*(impact+exploitability), 10)
	}

	// Round up to 1 decimal place (CVSS spec: ceiling)
	return math.Round(base*10) / 10
}

// Severity returns the qualitative severity rating for a CVSS score.
func Severity(score float64) string {
	switch {
	case score == 0:
		return "NONE"
	case score < 4.0:
		return "LOW"
	case score < 7.0:
		return "MEDIUM"
	case score < 9.0:
		return "HIGH"
	default:
		return "CRITICAL"
	}
}

// VectorString returns the CVSS 3.1 vector string representation.
func VectorString(m BaseMetrics) string {
	return "CVSS:3.1/AV:" + m.AV + "/AC:" + m.AC + "/PR:" + m.PR +
		"/UI:" + m.UI + "/S:" + m.S + "/C:" + m.C + "/I:" + m.I + "/A:" + m.A
}

func avScore(av string) float64 {
	switch av {
	case "N":
		return 0.85
	case "A":
		return 0.62
	case "L":
		return 0.55
	case "P":
		return 0.20
	default:
		return 0.85
	}
}

func acScore(ac string) float64 {
	if ac == "H" {
		return 0.44
	}
	return 0.77 // L
}

func prScore(pr, scope string) float64 {
	if scope == "C" {
		switch pr {
		case "N":
			return 0.85
		case "L":
			return 0.68
		case "H":
			return 0.50
		}
	}
	switch pr {
	case "N":
		return 0.85
	case "L":
		return 0.62
	case "H":
		return 0.27
	}
	return 0.85
}

func uiScore(ui string) float64 {
	if ui == "R" {
		return 0.62
	}
	return 0.85 // N
}

func impactScore(impact string) float64 {
	switch impact {
	case "H":
		return 0.56
	case "L":
		return 0.22
	default:
		return 0 // N
	}
}
