# Project Checklist EN

## 1. Architecture

* [x] 1.1 The repo contains a README with a description of the application architecture (frontend, backend, database).
* [x] 1.2 The repo contains an overview of the technologies used and their versions.
* [x] 1.3 The project has a clear folder structure (e.g., src, public, assets, components, api).
* [x] 1.4 Application logic is separated from the user interface.
* [x] 1.5 Static files (images, CSS, JS) are separated from the application logic.
* [x] 1.6 The project contains a configuration file for the production environment.
* [x] 1.7 Sensitive data (passwords, API keys) are not stored in the repository.

## 2. Dependencies

* [x] 2.1 The project contains a list of all external libraries and their versions.
* [x] 2.2 All dependencies are installed using a package manager (e.g., npm, pip).
* [ ] 2.3 The repo contains a lock file (e.g., package-lock.json).
* [ ] 2.4 The team regularly checks for dependency updates.
* [ ] 2.5 The team records the reason for using each external library.
* [ ] 2.6 Unused libraries have been removed from the project.

## 3. API

* [x] 3.1 The server returns correct HTTP status codes (200, 400, 403, 500).
* [x] 3.2 API endpoints are documented.
* [x] 3.3 Invalid requests return a comprehensible error.
* [x] 3.4 The server does not return internal error information to the user.
* [x] 3.5 The server correctly sets the Content-Type of the response.
* [x] 3.6 The API validates input data.
* [x] 3.7 Large server responses are compressed (GZIP).

## 4. Performance

* [ ] 4.1 Images are optimized and have an appropriate size.
* [ ] 4.2 Images use modern formats (e.g., WebP).
* [ ] 4.3 Unused CSS and JavaScript have been removed.
* [x] 4.4 JavaScript and CSS files are minified.
* [ ] 4.5 The number of HTTP requests upon page load has been analyzed.
* [ ] 4.6 Large files are loaded only when needed (lazy loading).
* [ ] 4.7 Static files are distributed via a CDN (Content Delivery Network).
* [x] 4.8 The server uses compression for transferred data.
* [ ] 4.9 Performance measurement was conducted using the Lighthouse tool.
* [ ] 4.10 The largest page element was optimized for fast loading (LCP: Largest Contentful Paint).

## 5. Optimization

* [x] 5.1 Static files have Cache-Control HTTP headers set.
* [x] 5.2 Cache is set for images, CSS, and JavaScript.
* [ ] 5.3 The team verified the cache functionality.
* [ ] 5.4 Cache invalidation occurs when files are changed.
* [ ] 5.5 CDN cache is correctly set for static files.

## 6. SEO & Accessibility

* [x] 6.1 The page has a set title.
* [x] 6.2 The page has a meta description.
* [x] 6.3 The page uses the correct heading structure.
* [ ] 6.4 Images have an alt attribute.
* [x] 6.5 The page is usable on mobile devices.

## 7. Security

* [x] 7.1 All user inputs are validated.
* [x] 7.2 The application is protected against XSS (Cross Site Scripting).
* [x] 7.3 The application is protected against CSRF (Cross Site Request Forgery).
* [x] 7.4 Database queries use parameterized queries.
* [x] 7.5 The server does not accept invalid or incomplete data.
* [x] 7.6 Cookies have Secure and HttpOnly attributes set.
* [x] 7.7 A check according to the OWASP Top 10 was performed.

## 8. Testing

* [ ] 8.1 The application was tested in multiple browsers.
* [ ] 8.2 The application was tested on a mobile device.
* [ ] 8.3 A test of invalid inputs was performed.
* [ ] 8.4 A test with multiple concurrent players was performed.
* [ ] 8.5 A basic performance test of the server was performed.
* [ ] 8.6 Found errors were recorded in the issue tracker.

## 9. Monitoring

* [x] 9.1 The application writes errors to a log.
* [x] 9.2 Logs contain the time of the error and the type of error.
* [ ] 9.3 Logs are available to the team for analysis.
* [ ] 9.4 The team monitors the number of players and games.
* [ ] 9.5 A traffic analytics tool is deployed.
* [ ] 9.6 A tool for checking website availability (uptime monitoring) is used.

## 10. Deployment

* [ ] 10.1 The application is deployed on a public server.
* [ ] 10.2 The application has a public URL.
* [x] 10.3 The production version runs without debug mode.
* [x] 10.4 The team has a prepared procedure for deploying a new version of the application.
* [x] 10.5 Bug fixes can be deployed without application downtime.

## 11. Management

* [ ] 11.1 The repo contains the commit history of all team members.
* [ ] 11.2 Every code change is assigned to a specific author.
* [ ] 11.3 The team uses an issue tracker for recording tasks and bugs.
* [ ] 11.4 CHANGELOG.md contains records of work by individual team members.
* [ ] 11.5 Every bug fix is linked to a specific commit.

## 12. Team Scrapes

* [ ] 12.1 A merge conflict occurred at the last minute and no one knew why.
* [ ] 12.2 A commit disappeared and the team spent time looking for it.
* [ ] 12.3 A member changed the configuration and others had to deal with a broken build.
* [ ] 12.4 A pull request passed review, but something broke upon deployment.
* [ ] 12.5 The project contained a "small change" that broke multiple parts of the application.
* [ ] 12.6 Everyone knew the solution to the problem only in their local environment.
* [ ] 12.7 The team realized that communication is just as important as code.