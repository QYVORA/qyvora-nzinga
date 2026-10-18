# assess.qs — a runnable example of the shared QYVORA scripting engine driving
# nzinga's authorized intelligence pipeline.
#
#     nzinga script run examples/assess.qs
#
# nzinga runs against the built-in offline simulation dataset here: no network
# I/O, no authorization. Live collection requires an in-scope target.

# Use the offline simulation dataset (no network).
set assess.sim -> "true"

# Run the full intelligence pipeline: discover->collect->normalize->
# correlate->analyze->validate->report. A specific capability id (for example
# a source collection such as "nzinga.crtsh.collect") runs the same pipeline.
run assess

# Read live properties from the completed run via $(...).
echo -> "session     = $(session.id)"
echo -> "target      = $(session.target)"
echo -> "domains     = $(result.domains)"
echo -> "hostnames   = $(result.hostnames)"
echo -> "ips         = $(result.ips)"
echo -> "observations= $(result.observations)"
echo -> "claims      = $(result.claims)"
echo -> "findings    = $(result.findings)"
echo -> "risk        = $(result.risk_score)/100 ($(result.risk_level))"

# Show capability metadata and write a JSON session report.
show nzinga.analyze.correlate
report -> "nzinga-report.json"

echo -> "done"
