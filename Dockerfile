FROM debian:bullseye-slim

RUN apt update -y && apt install --no-install-recommends -y 	\
	curl 							\
	make 							\
	clang 							\
	libkeyutils-dev 					&& \
	rm -rf /var/lib/apt/lists/*

WORKDIR /io
