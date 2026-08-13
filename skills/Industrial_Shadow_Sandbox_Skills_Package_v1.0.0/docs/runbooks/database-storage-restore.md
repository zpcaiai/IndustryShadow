# Database and object-storage restore

Restore the selected PostgreSQL custom dump into an isolated database, run
`pg_restore --list`, migrations, row-count checks, tenant-isolation probes, and audit/
Gold immutability checks. Restore the matching versioned object prefix and compare
snapshot/report/dataset hashes with database metadata. Never overwrite production in
place. Switch traffic only after a two-person review records RPO/RTO and integrity evidence.
