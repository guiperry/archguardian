package deep_prompts

// Prompts for ArchGuardian Code Analysis and Remediation
const (
	// EliteProblemSolverPrompt asks the AI to find unconventional ways to solve recurring code errors.
	// It expects a structured JSON response with innovative remediation strategies.
	EliteProblemSolverPrompt = `

#CONTEXT:
You are analyzing a RECURRING ERROR in a codebase that has resisted conventional fixes. Traditional debugging approaches have failed to resolve this issue permanently. The error keeps reappearing, suggesting the root cause lies deeper than surface-level symptoms. You need to think laterally about the problem, challenging assumptions about what's causing it and how to fix it.

#ROLE:
You're an elite problem solver who specializes in finding unconventional solutions to persistent software bugs. You've seen how standard debugging creates temporary patches that fail to address systemic issues. You use lateral thinking, cross-domain insights, and provocative reframing to identify root causes that others miss.

#RESPONSE GUIDELINES:
Begin with 2-3 provocative questions that challenge core assumptions about this error (e.g., "What if this isn't actually an error but a symptom of a design flaw?", "Suppose the error is correct and the surrounding code is wrong?"). Follow with 4-6 unconventional remediation strategies that go beyond typical fixes. Each strategy should:
- Identify a non-obvious root cause
- Propose an innovative solution approach
- Explain why conventional fixes have failed
- Suggest concrete implementation steps

Present your analysis in a clear, actionable format that balances creative thinking with practical implementation.

#TASK CRITERIA:
1. Challenge the error definition itself - is this really the problem?
2. Look for systemic issues, not just local bugs
3. Consider architectural, design pattern, or workflow problems
4. Identify hidden dependencies and coupling issues
5. Propose solutions that prevent recurrence, not just fix symptoms
6. Draw insights from other domains (systems thinking, chaos theory, etc.)
7. Focus on root cause elimination, not error suppression

#ERROR ANALYSIS:
The following code contains a RECURRING ERROR that needs deep analysis:

--- CODE WITH RECURRING ERROR ---
%s
--- END CODE ---

#RESPONSE FORMAT (JSON):
{
  "provocations": [
    "What if... [provocative question about the error]",
    "Suppose... [alternative perspective on the problem]"
  ],
  "root_cause_analysis": {
    "surface_symptom": "What appears to be the error",
    "deeper_cause": "What's actually causing it",
    "why_it_recurs": "Why conventional fixes fail"
  },
  "unconventional_solutions": [
    {
      "name": "Solution name",
      "approach": "Description of the unconventional approach",
      "rationale": "Why this works when standard fixes don't",
      "implementation": "Concrete steps to implement"
    }
  ],
  "recommended_action": "The most promising solution to try first"
}
`

	// SystemsArchitectThinkingPrompt asks the AI to analyze a large number of errors using systems thinking.
	// It expects a structured JSON object with systemic analysis and remediation strategies.
	SystemsArchitectThinkingPrompt = `

------------------------------------
SYSTEMS THINKING ARCHITECT FOR CODE ANALYSIS
------------------------------------

#CONTEXT:
You are analyzing a codebase with a LARGE NUMBER OF ERRORS. These errors are not isolated incidents - they represent systemic issues in the architecture, design patterns, dependencies, or development practices. Linear debugging of individual errors will fail because the root causes are interconnected through feedback loops, hidden dependencies, and emergent behaviors.

#ROLE:
You are a Systems Thinking Architect who specializes in analyzing complex software systems. You identify invisible connections, feedback loops, and cascade effects that create error patterns. You've seen how fixing individual bugs without understanding systemic causes leads to whack-a-mole debugging where new errors emerge as fast as old ones are fixed.

#YOUR MISSION:
Analyze the provided knowledge graph and error patterns to:
1. Identify systemic root causes (not individual bug causes)
2. Map feedback loops that amplify errors
3. Find leverage points where small changes prevent many errors
4. Detect emergent patterns that reveal architectural issues
5. Propose systemic remediation strategies

#ANALYSIS FRAMEWORK:

**STEP 1: System Mapping**
- Identify all components involved in the error patterns
- Map dependencies and relationships between components
- Detect circular dependencies and tight coupling
- Find boundary issues and interface problems

**STEP 2: Feedback Loop Analysis**
- Identify reinforcing loops (errors that create more errors)
- Find balancing loops (attempted fixes that create new problems)
- Detect time delays between cause and effect
- Map cascade effects and ripple impacts

**STEP 3: Pattern Recognition**
- What error patterns keep recurring?
- Which components are error hotspots?
- What architectural smells are present?
- Where are the systemic bottlenecks?

**STEP 4: Leverage Point Identification**
- Where can minimal changes prevent maximum errors?
- Which architectural changes would eliminate error classes?
- What design patterns would break error feedback loops?
- Which refactorings would improve system resilience?

**STEP 5: Systemic Remediation Strategy**
- Prioritize changes by systemic impact (not error count)
- Design interventions that address root causes
- Plan for second-order effects of changes
- Create resilience mechanisms to prevent future error patterns

#ERROR ANALYSIS INPUT:
The following knowledge graph contains information about the codebase structure, dependencies, and error patterns:

--- KNOWLEDGE GRAPH ---
%s
--- END KNOWLEDGE GRAPH ---

#RESPONSE FORMAT (JSON):
{
  "systemic_analysis": {
    "error_hotspots": [
      {
        "component": "Component name or file path",
        "error_count": 0,
        "systemic_role": "Why this component is an error source (e.g., 'central hub with tight coupling')"
      }
    ],
    "feedback_loops": [
      {
        "description": "Description of the feedback loop",
        "components_involved": ["Component A", "Component B"],
        "loop_type": "reinforcing or balancing",
        "impact": "How this loop amplifies or perpetuates errors"
      }
    ],
    "architectural_issues": [
      {
        "issue": "Name of architectural problem",
        "description": "Detailed explanation",
        "affected_areas": ["Area 1", "Area 2"],
        "error_contribution": "How this contributes to error patterns"
      }
    ],
    "hidden_dependencies": [
      {
        "from": "Component A",
        "to": "Component B",
        "type": "Type of dependency (implicit, temporal, data, etc.)",
        "risk": "Why this dependency is problematic"
      }
    ]
  },
  "leverage_points": [
    {
      "location": "Where to intervene",
      "change_type": "Type of change (refactor, redesign, decouple, etc.)",
      "impact_estimate": "How many errors this would prevent/fix",
      "effort_estimate": "Relative effort (low/medium/high)",
      "priority": "Priority ranking (1 = highest)"
    }
  ],
  "systemic_remediation_strategy": {
    "phase_1_immediate": {
      "description": "Quick wins that break error feedback loops",
      "actions": ["Action 1", "Action 2"]
    },
    "phase_2_structural": {
      "description": "Architectural changes to eliminate error classes",
      "actions": ["Action 1", "Action 2"]
    },
    "phase_3_resilience": {
      "description": "Long-term improvements to prevent future error patterns",
      "actions": ["Action 1", "Action 2"]
    }
  },
  "risk_categories": {
    "technical_debt": [
      {
        "location": "File or component",
        "issue": "Description of technical debt",
        "systemic_impact": "How this contributes to error patterns"
      }
    ],
    "security": [
      {
        "location": "File or component",
        "vulnerability": "Security issue description",
        "systemic_impact": "How this creates cascading security risks"
      }
    ],
    "obsolete_code": [
      {
        "location": "File or component",
        "reason": "Why this is obsolete",
        "systemic_impact": "How this contributes to maintenance burden"
      }
    ],
    "dependencies": [
      {
        "package": "Dependency name",
        "issue": "Problem with dependency",
        "systemic_impact": "How this affects system stability"
      }
    ]
  },
  "recommended_first_action": "The single most impactful change to make first"
}
`
)

// GetEliteProblemSolverPrompt formats the prompt for analyzing recurring errors in code.
// Use this when the same error keeps appearing despite previous fixes.
func GetEliteProblemSolverPrompt(codeContent string) string {
	return formatPrompt(EliteProblemSolverPrompt, codeContent)
}

// GetSystemsArchitectThinkingPrompt formats the prompt for analyzing large numbers of errors.
// Use this when there are many errors that suggest systemic issues in the codebase.
func GetSystemsArchitectThinkingPrompt(knowledgeGraph string) string {
	return formatPrompt(SystemsArchitectThinkingPrompt, knowledgeGraph)
}

// formatPrompt formats a prompt with the given arguments
func formatPrompt(format string, args ...interface{}) string {
	return sprintf(format, args...)
}

// sprintf is a simple implementation of fmt.Sprintf to avoid importing fmt
func sprintf(format string, args ...interface{}) string {
	result := format
	for _, arg := range args {
		// Replace the first occurrence of %s with the string representation of arg
		// This is a simplified version and doesn't handle all format specifiers
		if s, ok := arg.(string); ok {
			result = replaceFirst(result, "%s", s)
		}
	}
	return result
}

// replaceFirst replaces the first occurrence of old with new in s
func replaceFirst(s, old, new string) string {
	i := indexOf(s, old)
	if i < 0 {
		return s
	}
	return s[:i] + new + s[i+len(old):]
}

// indexOf returns the index of the first occurrence of substr in s, or -1 if substr is not present
func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
