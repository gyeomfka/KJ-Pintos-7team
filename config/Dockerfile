FROM ubuntu:22.04

# Install dependencies if needed
# install libc6-dev-i386 hence it provides /usr/include/bits/wordsize.h which is required building mdriver
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential \
    make systemd-coredump libc6-dev-i386 fzf vim telnet htop net-tools iproute2 \
    gdbserver \
    valgrind \
    qemu-system-x86

RUN echo "source /workspace/activate" >> ~/.bashrc
RUN echo "alias d='cd /workspace && gdbserver :1234 ./mdriver-debug'" >> ~/.bashrc
RUN echo "alias dd='pkill gdbserver'" >> ~/.bashrc
RUN echo "alias c='clear'" >> ~/.bashrc
RUN echo "alias h='htop'" >> ~/.bashrc
RUN echo "alias ..='cd ..'" >> ~/.bashrc
RUN echo "alias ...='cd ../..'" >> ~/.bashrc

# Set the working directory to /workspace
WORKDIR /workspace

# Keep container running
CMD ["tail", "-f", "/dev/null"]
