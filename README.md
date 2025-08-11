# dcup

Find, list, and update Docker Compose services that have newer container images available.

`dcup` scans the current directory (recursively) for Compose files, detects services that reference images (not build-only services), checks whether newer images exist for your local platform without pulling them, and then updates and restarts only the services you choose. It works with both `docker compose` and legacy `docker-compose`.

## Features

- Recursively discovers Compose files: docker-compose.yml/.yaml and compose.yml/.yaml
- Parses services to find those that use the `image:` field
- Checks for updates per-image by comparing your local image digests to the remote manifest digest for your platform
- Interactive multi-select to choose which images/services to update
- Non-interactive mode with `--yes` to update all detected services
- Uses either `docker compose` or `docker-compose`, whichever is available

## Requirements

- Docker CLI installed. `docker compose` is preferred; if not available, `docker-compose` is used.
- Network access to the image registry used by your images.
- A project containing Docker Compose files with services that use the `image:` key.

## Install

Build from source (Rust 1.80+ recommended):

```bash
# Clone your repository or ensure you are in the project root
cargo build --release
# Binary will be at: target/release/dcup

# Optionally install into your Cargo bin directory
cargo install --path .
```

## Usage

From the root of your project:

```bash
# Interactive mode: scan, check updates, let you pick images/services
$ dcup

# Non-interactive: update all services without prompting
$ dcup --yes
```

What happens:
1. Discover Compose files under the current directory.
2. Parse services that have an `image:` defined.
3. For each image, detect if a newer image exists for your current platform (os/arch[/variant]) without pulling layers.
4. Prompt you to select which images/services to update (unless `--yes`).
5. For each affected Compose file, run:
   - Pull: `docker compose -f <file> pull <services>` (or `docker-compose ...`)
   - Recreate: `docker compose -f <file> up -d <services>`

## How update detection works (high level)

- Local: `docker image inspect` is used to get existing repo digests and your local platform.
- Remote: `docker manifest inspect --verbose` is used to find the digest matching your platform. If needed, it falls back to a non-verbose manifest query.
- If the platform-matching remote digest differs from your local digests, the image is considered "updated".

## Notes and limitations

- Services without an `image:` (e.g., `build:` only) are ignored.
- Images using unresolved environment substitutions like `${VAR}` are skipped to avoid false positives.
- If the local platform cannot be determined, or a platform-matching remote digest cannot be found, the image is treated as up-to-date to avoid accidental pulls.
- Only services belonging to selected images are pulled and recreated; other services are left untouched.

## Development

- See development-guidelines.md for project philosophy and workflow.
- Run tests: `cargo test`
- Build: `cargo build` or `cargo build --release`

## License

No license has been specified in Cargo.toml yet.
