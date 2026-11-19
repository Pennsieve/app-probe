# App Probe

A diagnostic Pennsieve app. Run it as a workflow step, or from "Try this app", to see
what a step gets at runtime, or put it in a workflow as a pass-through step.

## Modes

- **`inspect`** (default) writes `report.json` and `report.md` to the output, and a summary
  to the log.
- **`echo`** copies the inputs to the output unchanged. The report goes to the log only, so
  the output stays a clean copy.

The last log line is always `APP_PROBE_SUMMARY {...}`: compute type, run id, image digest,
release tag, input file count and exit code.

The probe has no version number of its own. A run is identified by its image digest,
which pins the exact build, and by the release tag when the image reference carries one
(App Store images are tagged `<hash>-<tag>`; a digest-pinned reference has no tag).

## What the report covers

- **Compute:** standard (Fargate), gpu (ECS on EC2), lambda, or the release sample runner,
  and how that was decided.
- **ECS task:** task ARN, family, launch type, availability zone, the other containers in
  the task, and the image, **image digest** and release tag the step ran.
- **Resources:** the CPU and memory the step actually gets (the smallest of the host's,
  the cgroup's and the ECS task's limits; "unknown" on Lambda, which doesn't show them to
  the app), GPU (`nvidia-smi`), free disk on
  `INPUT_DIR`, `OUTPUT_DIR`, `TMPDIR` and `/data`.
- **Process:** uid and gid, whether a passwd entry exists, working directory, and which
  folders are writable.
- **Inputs:** every file under `INPUT_DIR` with its size and SHA-256 (bounded), and the top
  level, which shows where each port was placed. A dataset view staged as input (its
  `.pennsieve/view.json`) is summarised: id, name, lifecycle, entry count and source.
- **Network:** DNS and HTTPS reach to the Pennsieve API, an AWS endpoint and the public
  internet, and the LLM proxy when present.
- **Environment:** the names of all environment variables.

### Secrets are never printed

A run's shared and user secrets are injected as environment variables under names their
owners choose, so they can't be recognised by name. The probe prints a variable's
**value** only when it is a known platform variable (`SHOWN_VARIABLES` in `probe.py`) or
one of the app's own parameters. Every other variable is listed by name only. Known
credentials (`SESSION_TOKEN`, `REFRESH_TOKEN`, AWS credentials, ...) are reported as
present or absent. Add a variable to `SHOWN_VARIABLES` only when its value can never be a
secret.

## Parameters

| Parameter | Default | What |
|---|---|---|
| `MODE` | `inspect` | `inspect` or `echo` |
| `SLEEP_SECONDS` | `0` | sleep before finishing, to test timeouts and cancelling |
| `EXIT_CODE` | `0` | exit with this code after writing the outputs |
| `LOG_LINES` | `0` | write this many numbered log lines |
| `WRITE_MB` | `0` | also write this many MB of random data to the output |
| `NETWORK_CHECKS` | `true` | run the network checks |
| `HASH_MAX_MB` | `64` | checksum input files up to this size |

## Variants

`cpu` (default), `gpu` (a GPU node) and `llm` (with the LLM governor proxy; no model is
called). All three are the same image.

## Developing

```sh
make test        # unit tests, plain python3
make run-local   # build the image and run it like a compute node; report in ./out
```

`probe.py` uses only the Python standard library.
