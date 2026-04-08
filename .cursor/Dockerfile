FROM ruby:3.3.8-bookworm

ENV DEBIAN_FRONTEND=noninteractive \
    BUNDLE_FORCE_RUBY_PLATFORM=true \
    PIP_BREAK_SYSTEM_PACKAGES=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    autoconf \
    bash \
    bison \
    build-essential \
    ca-certificates \
    curl \
    git \
    graphviz \
    libffi-dev \
    libpcap-dev \
    libpq-dev \
    libreadline-dev \
    libsqlite3-dev \
    libssl-dev \
    libxml2-dev \
    libxslt1-dev \
    libyaml-dev \
    nmap \
    pkg-config \
    postgresql \
    postgresql-client \
    python3 \
    python3-dev \
    python3-pip \
    python3-venv \
    sqlite3 \
    sudo \
    zlib1g-dev \
 && rm -rf /var/lib/apt/lists/*

RUN gem update --system \
 && gem install bundler \
 && python3 -m pip install --upgrade pip setuptools wheel

WORKDIR /workspace
