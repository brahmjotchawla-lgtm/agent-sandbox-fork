# Coding-agent workspace: Python runtime + a real mid-size repo checkout
# (Django, ~6.8k files) with its dependencies installed. Shared by both
# sides of the benchmark (BENCHMARKS.md §2, §3.1).
FROM python:3.12-slim
COPY context/wheels /tmp/wheels
COPY context/repo /workspace/repo
# Put the checkout on sys.path (what an editable install does, without
# needing setuptools in the image), then prove the workspace imports.
RUN pip install --no-cache-dir --no-index --find-links /tmp/wheels pytest asgiref sqlparse \
 && rm -rf /tmp/wheels \
 && echo /workspace/repo > "$(python3 -c 'import sysconfig; print(sysconfig.get_paths()["purelib"])')/workspace.pth" \
 && python3 -c "import django; print('django', django.get_version())"
WORKDIR /workspace/repo
