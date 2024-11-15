FROM python:3.12

RUN pip install pipenv

WORKDIR /app
COPY Dockerfile Pipfile Pipfile.lock pyproject.toml README.md ./
COPY semgrep_reporter ./semgrep_reporter

RUN pipenv install --system --deploy --ignore-pipfile

ENTRYPOINT [ "python", "-m", "semgrep_reporter" ]
CMD [ "--help" ]