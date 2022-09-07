FROM python:3.9-slim

# Working directory is app
WORKDIR /install

# Install dependencies
ADD poetry.lock pyproject.toml ./
RUN pip install --upgrade pip poetry && \
    poetry config virtualenvs.create false && \
    poetry install -v

# Copy current directory contents to /app container
ADD . /install

# Create wheel for tox
RUN poetry build

# Install auth0-api-client in local environment
RUN pip install .
