# Docker

Build the image from the repository root:

```sh
docker build -t piv-conformance .
```

The image build compiles all modules and runs the focused GUI packaging tests. Running the Swing application with a smart-card reader is supported only on a native Linux Docker host because Docker Desktop does not directly expose host USB or PC/SC devices.

On Linux, expose the X11 display, the host PC/SC socket, and a persistent data directory:

```sh
mkdir -p cct-docker-data
docker run --rm \
  -e DISPLAY \
  -e XAUTHORITY=/tmp/.Xauthority \
  -v "${XAUTHORITY:-$HOME/.Xauthority}:/tmp/.Xauthority:ro" \
  -v /tmp/.X11-unix:/tmp/.X11-unix:ro \
  -v /run/pcscd/pcscd.comm:/run/pcscd/pcscd.comm \
  -v "$PWD/cct-docker-data:/data" \
  piv-conformance
```

The container seeds `/data` with the required databases and configuration on first launch. Logs, artifacts, and generated review ZIPs remain in the mounted `cct-docker-data` directory.
