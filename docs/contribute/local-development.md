# Local development

How to run LogsTotal from a git checkout on your own machine, with live reload, to work on
the code.

## Path A: Local Development

You need everything in the Local development column of
[Prerequisites](../install/prerequisites.md#what-each-machine-needs): Python 3.11 or later,
Docker (Zircolite runs as a container, and Redis can too), and PDM, the project's dependency
manager. Install PDM with one of:

```bash
curl -sSL https://pdm-project.org/install-pdm.py | python3 -   # any platform, current release
brew install pdm                                              # macOS
sudo apt install python3-pdm                                  # Debian/Ubuntu
```

The distribution package is the quickest but lags behind upstream. If `./logstotal setup`
complains about the PDM version, use the installer.

Building the `tlsh` extension needs a C++ toolchain. On Debian or Ubuntu:

```bash
sudo apt update && sudo apt install -y build-essential g++ python3-dev
```

On ARM, you may need to point the build at the GNU compilers first:
`export CC=gcc CXX=g++`.

Clone the repository and set it up:

```bash
git clone https://github.com/wagga40/LogsTotal.git && cd LogsTotal
./logstotal setup
```

`./logstotal setup` installs the dependencies, creates `.env` with generated secrets
(the admin password is printed once) and `COOKIE_INSECURE=true` for plain HTTP, and creates
the database. To choose the admin credentials yourself:

```bash
ADMIN_EMAIL=you@example.com ADMIN_PASSWORD=<strong-password> ./logstotal setup
```

The admin is not created with the shipped default password (`changeme123`) or a password
shorter than 8 characters.

Start Redis, then the web server and the worker in two terminals:

```bash
./logstotal redis:docker   # Redis in Docker, detached (or: ./logstotal redis, a local redis-server)
./logstotal dev            # web server with live reload
./logstotal worker:watch   # worker, restarted when the code changes
```

Open `http://localhost:8000`. The admin pages are at `/admin`, and the login page at
`/auth/login`.

> [!NOTE]
> **Login does not stick over plain HTTP?** Set `DEBUG=true` or `COOKIE_INSECURE=true` in
> `.env` — see [Cookies over plain HTTP](../configuration.md#cookies-over-plain-http).

The dev server serves Tailwind from its in-browser bundle. To test the production
stylesheet, see [Production CSS](development.md#production-css-tailwind). Tests, linting
and the rest of the contributor workflow are in the [Development guide](development.md).
