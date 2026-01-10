FROM ubuntu:22.04

WORKDIR /MOSAC

# install dependency
RUN apt-get update
RUN apt-get install -y gcc g++ cmake nasm iproute2 npm ninja-build git

# install bazelisk
RUN npm install -g @bazel/bazelisk
RUN alias bazel='bazelisk'

# copy source code
COPY . /MOSAC

# It would complie and run all unit-test
# RUN bazel test -c opt //...
