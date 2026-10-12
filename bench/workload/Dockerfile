# The Claim 1 workload: a realistic coding-agent workspace (BENCHMARKS.md §2).
# Both sides of every comparison are built from THIS file. The Docker
# baseline runs the image directly. The fork side imports `docker export` of
# the same image into a btrfs subvolume (bench/build_workload.sh). So both
# sides start from byte-identical content.
#
# Contents: Python runtime, a full-history git checkout of a real mid-size
# open-source project (pallets/flask at the 3.1.0 tag), and its test
# dependencies installed into a venv. The repo's test suite runs inside
# the sandbox (bench/build_workload.sh checks this), so the workspace is a
# working one, not just files on disk.
FROM python@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1

RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates \
 && rm -rf /var/lib/apt/lists/*

ARG FLASK_REF=2efaec117637fa51c6c53588899002def7eee37a
RUN git clone https://github.com/pallets/flask /workspace/flask \
 && git -C /workspace/flask checkout -q ${FLASK_REF} \
 && git -C /workspace/flask config user.email agent@example.invalid \
 && git -C /workspace/flask config user.name agent

RUN python -m venv /workspace/venv \
 && /workspace/venv/bin/pip install --no-cache-dir -q -r /workspace/flask/requirements/tests.txt \
 && /workspace/venv/bin/pip install --no-cache-dir -q -e /workspace/flask

WORKDIR /workspace/flask
CMD ["sleep", "infinity"]
