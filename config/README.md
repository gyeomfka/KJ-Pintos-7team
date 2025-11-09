
- build and run

  ```bash
  docker build -t jg-c-w5 .
  docker run -d --name jg-c-w5 -v "$(git-root)/src:/workspace" --network=host jg-c-w5
  ```



- how to run debugger

  ```bash
  1. (가급적) remote에서 build

  2. 컨테이너에서 `gdbserver :<port> <executable>`
     ex) `gdbserver :1234 hello`

  3. 코드 보기: `(gdb) directory <src base path>`
     ex) `(gdb) directory /home/sy/my_project`
     ex) `(gdb) directory .`                          // while on correct path

  4. local에서 `(gdb) extended-remote <remote ip>:<remote port>`
     - localhost인 이유는 docker 컨테이너의 network를 host로 지정했으니까
     ex) `(gdb) target extended-remote localhost:1234`
  ```
