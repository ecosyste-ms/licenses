FROM alpine:3.22 AS licenses

ARG LICENSES_VERSION=0.5.0
ARG TARGETOS
ARG TARGETARCH

RUN apk add --no-cache ca-certificates curl \
 && archive="licenses_${LICENSES_VERSION}_${TARGETOS}_${TARGETARCH}.tar.gz" \
 && release="https://github.com/git-pkgs/licenses/releases/download/v${LICENSES_VERSION}" \
 && curl -fsSL "${release}/${archive}" -o "/tmp/${archive}" \
 && curl -fsSL "${release}/checksums.txt" -o /tmp/checksums.txt \
 && cd /tmp \
 && grep " ${archive}$" checksums.txt | sha256sum -c - \
 && tar -xzf "${archive}" licenses \
 && install -m 0755 licenses /usr/local/bin/licenses

FROM ruby:4.0.6-slim

ENV APP_ROOT=/usr/src/app
ENV DATABASE_PORT=5432
WORKDIR $APP_ROOT

COPY --from=licenses /usr/local/bin/licenses /usr/local/bin/licenses

# * Setup system
# * Install Ruby dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    git \
    nodejs \
    libpq-dev \
    tzdata \
    curl \
    libyaml-dev \
    libcurl4-openssl-dev \
    libgit2-dev \
    cmake \
    pkg-config \
    libjemalloc2 \
    file \
    libarchive-tools \
 && rm -rf /var/lib/apt/lists/* \
 && ln -sf $(find /usr/lib -name 'libjemalloc.so.2' -print -quit) /usr/local/lib/libjemalloc.so.2

ENV RUBY_YJIT_ENABLE=1

# Will invalidate cache as soon as the Gemfile changes
COPY Gemfile Gemfile.lock .ruby-version $APP_ROOT/

RUN bundle config --global frozen 1 \
 && bundle config set without 'test' \
 && bundle install --jobs 2

# ========================================================
# Application layer

# Copy application code
COPY . $APP_ROOT

RUN bundle exec bootsnap precompile --gemfile app/ lib/

# Precompile assets for a production environment.
# This is done to include assets in production images on Dockerhub.
RUN SECRET_KEY_BASE=1 RAILS_ENV=production bundle exec rake assets:precompile

# Set LD_PRELOAD for runtime (not build time)
ENV LD_PRELOAD=/usr/local/lib/libjemalloc.so.2

# Startup
CMD ["bin/docker-start"]
