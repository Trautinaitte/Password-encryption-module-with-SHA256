# Get the latest base image for python
FROM python:latest
# Put files at the image '/server/' folder.
RUN apt-get update && \
    apt-get install -y protobuf-compiler && \
    apt-get install -y curl gnupg && \
    curl -fsSL https://bazel.build/bazel-release.pub.gpg | gpg --dearmor > bazel.gpg && \
    mv bazel.gpg /etc/apt/trusted.gpg.d/ && \
    echo "deb [arch=amd64] https://storage.googleapis.com/bazel-apt stable jdk1.8" | \
    tee /etc/apt/sources.list.d/bazel.list && \
    apt-get update && \
    apt-get install -y bazel=6.4.0 && \
    pip3 install tink

ADD ipc_server.py /server/
# '/server/' is base directory
WORKDIR /server/
# Expose port 9898 in the container
EXPOSE 9898
# execute the command
CMD [ "python3", "/server/ipc_server.py" ]

