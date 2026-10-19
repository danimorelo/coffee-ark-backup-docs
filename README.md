# Coffee Ark Ubuntu Backups — information pages

Exactly three static documentation pages for a private, single-owner backup OAuth
integration. This is not the Coffee Ark pantry application or a public service.
There are no frameworks, scripts, forms, trackers, external assets or runtime
credentials in the published directory.

- `docs/index.html` — purpose, encrypted backup flow and restricted access scope.
- `docs/privacy.html` — data handling, protected credentials, retention and revocation.
- `docs/terms.html` — intended use, owner responsibilities and recovery limitations.
- `docs/styles.css` — shared warm, responsive, keyboard-accessible presentation.
- `docs/.nojekyll` — plain static hosting marker.
- `tools/check_site.py` — local structural/privacy-hygiene gate, not semantic acceptance.

Check locally with `python3 tools/check_site.py`. Independent semantic review is
required against the actual integration before publication. Do not add application
source, private endpoints, personal contacts, secrets, evidence artifacts or legal
compliance promises. Publishing and Google account changes are separate approved
operator steps; creating these files does not enable hosting or the backup job.
