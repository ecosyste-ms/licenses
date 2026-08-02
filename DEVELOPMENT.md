# Development

## Setup

First things first, you'll need to fork and clone the repository to your local machine.

`git clone https://github.com/ecosyste-ms/licenses.git`

The project uses ruby on rails which have a number of system dependencies you'll need to install. 

- [ruby](https://www.ruby-lang.org/en/documentation/installation/)
- [postgresql 14](https://www.postgresql.org/download/)
- [redis 6+](https://redis.io/download/)
- [node.js 16+](https://nodejs.org/en/download/)
- [Go 1.25.6+](https://go.dev/doc/install) for the v2 preview service

Once you've got all of those installed, from the root directory of the project run the following commands:

```
bundle install
bundle exec rake db:setup
rails server
```

You can then load up [http://localhost:3000](http://localhost:3000) to access the service.

### Docker

Alternatively you can use the existing docker configuration files to run the app in a container.

Run this command from the root directory of the project to start the service.

`docker-compose up --build`

You can then load up [http://localhost:3000](http://localhost:3000) to access the service.

For access the rails console use the following command:

`docker-compose exec app rails console`

## Tests

The applications tests can be found in [test](test) and use the testing framework [minitest](https://github.com/minitest/minitest).

You can run all the tests with:

`rails test`

Run the Go v2 checks with:

```bash
gofmt -w cmd internal
go vet ./...
go test ./...
go build ./cmd/server
```

## Go v2 preview

The Go service is additive during the staged migration: it does not replace or
remove the Rails v1 application. Start it locally on port 5000:

```bash
go run ./cmd/server
```

Then request a scan from a public HTTP or HTTPS archive URL:

```bash
curl --get http://localhost:5000/api/v2/licenses \
  --data-urlencode 'url=https://example.test/package.tar.gz'
```

The service rejects private and loopback destinations in production, validates
redirects, and bounds download size, archive expansion, entries, path depth,
per-file scanning, attribution contents, request duration, and concurrent
scans. Configuration currently supported by the server process:

- `PORT` (default `5000`)
- `SCAN_TIMEOUT` (default `120s`)
- `MAX_CONCURRENT_SCANS` (default `4`)
- `OPENAPI_PATH` (default `openapi/api/v2/openapi.yaml`)
- `MAX_DOWNLOAD_BYTES` (default `104857600`)
- `MAX_ARCHIVE_ENTRIES` (default `10000`)
- `MAX_ARCHIVE_DEPTH` (default `64`)
- `MAX_ENTRY_BYTES` (default `33554432`)
- `MAX_EXPANDED_BYTES` (default `536870912`)
- `MAX_SCAN_FILES` (default `10000`)
- `MAX_SCAN_DEPTH` (default `32`)
- `MAX_SCAN_FILE_BYTES` (default `1048576`)
- `SCAN_WORKERS` (default up to `16`, bounded by available CPUs)
- `MAX_ATTRIBUTION_FILES` (default `64`)
- `MAX_ATTRIBUTION_BYTES` (default `4194304`)

Build the independent preview image without changing the Rails image:

```bash
docker build -f Dockerfile.v2 -t licenses-v2 .
docker run --rm -p 5000:5000 licenses-v2
```

## Background tasks 

Background tasks are handled by [sidekiq](https://github.com/mperham/sidekiq), the workers live in [app/sidekiq](app/sidekiq/).

To process the tasks run the following command:

`bundle exec sidekiq`

You can also view the status of the workers and their queues from the web interface http://localhost:3000/sidekiq

## Deployment

A container-based deployment is highly recommended, we use [dokku.com](https://dokku.com/).
