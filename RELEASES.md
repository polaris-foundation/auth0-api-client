1.3.5
=====

- Remove sonarcube from build
- Update dependencies

1.3.4
=====

- Remove User Login Attempts limiter which was introduced in 1.3.3; Use Auth0 whitelisting instead

1.3.3
=====

- Improve 429 handler, add User Login Attempts limiter which limits user login requests to 20 p/m for each user and decreases down to 10 if a specific 429 response is received.

1.3.2
=====

- Catch 429 (Too Many Requests) and retry if it occurs when retrieving JWT

1.3.1
=====

- Allow groups to not contain any roles

1.3.0
=====

- Changed library to use paginated Auth0 API
- Made library typed

1.2.6
=====
- Require Python 3.8 again
- Use she-logging instead of dhoslib

1.2.5
=====

- Don't require python 3.8

1.2.4
=====

- Better request logging
- Update to python 3.8

1.2.3
=====

- Updated dependencies
- Stop logging JWTs

1.2.2
=====

- Fixed sonarqube analysis

1.2.1
=====

- Move static code analysis to SonarCloud

1.2.0
=====

- Add poetry to project
- Added type checking with mypy
- Changed config to use environs library

1.1.1
=====

- Added logging and timeouts to requests

1.1.0
=====

- Change to dhoslib logging
- Reviewed logging messages
