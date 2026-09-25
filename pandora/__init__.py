"""pandora — targeted data-exposure / breach monitoring for a single organisation.

This is NOT an internet crawler. It queries a set of well-defined OSINT and
threat-intelligence *sources* for mentions of YOUR organisation (name, domain,
keywords), deduplicates results across runs, and reports only what is NEW.

Scope it to data you are authorised to hunt for (your own org). Respect the
terms of service and rate limits of every source. The tool does that by
default (timeouts, polite delays, graceful skip when a source has no API key).
"""

__version__ = "1.0.0"
