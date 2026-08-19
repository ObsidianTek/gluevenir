FROM public.ecr.aws/lambda/python:3.12

COPY LICENSE README.md pyproject.toml ./
COPY src ./src

RUN python -m pip install --no-cache-dir .
RUN python -m pip install --no-cache-dir \
    https://github.com/explosion/spacy-models/releases/download/en_core_web_sm-3.8.0/en_core_web_sm-3.8.0-py3-none-any.whl

CMD ["gluevenir._demo_runtime.handler"]
