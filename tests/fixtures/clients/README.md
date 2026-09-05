# Client fixtures

One server per client config format, all in one project. `clients_every_format_is_read` in `tests/cli.rs` scans this directory and asserts each server is found, so a parser that silently stops reading a format fails CI.
