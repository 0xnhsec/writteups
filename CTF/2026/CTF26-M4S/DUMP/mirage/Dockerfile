# mirage (hardened) - PWN remote instance
# The flag lives in flag.txt on the server only; the handed-out binary
# carries a DECOY flag. The pinned loader+libc are shipped so gadget
# offsets are identical to what players exploit locally.
FROM ubuntu:22.04
RUN apt-get update && apt-get install -y socat && rm -rf /var/lib/apt/lists/*
RUN useradd -m ctf
WORKDIR /home/ctf
COPY dist/mirage                ./mirage
COPY dist/libc.so.6             ./libc.so.6
COPY dist/ld-linux-x86-64.so.2  ./ld-linux-x86-64.so.2
COPY src/flag.txt              ./flag.txt
RUN chmod 555 ./mirage ./ld-linux-x86-64.so.2 \
    && chmod 444 ./libc.so.6 ./flag.txt && chown -R root:ctf /home/ctf
USER ctf
EXPOSE 9007
CMD ["socat", "-T60", "TCP-LISTEN:9007,reuseaddr,fork", \
     "EXEC:./ld-linux-x86-64.so.2 --library-path . ./mirage,stderr"]
