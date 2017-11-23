# light-man

This is a CLI tool for basic node management on a lighthouse instance. The source is written in Go, specifically version 1.8, however I imagine it could be compiled on much earlier versions. The only external dependency is `golang.org/x/crypto/ssh` which it uses for the ssh shell passthrough.

Currently implemented are the following commands:

```
configure - setup light-man with your lighthouse credentials. These are saved to a ~/.oglh file.
list - print out information to do with all nodes connected to the lighthouse.
add - add a node.
delete - delete a node.
delete-all - delete all nodes.
shell - gives you a pmshell connection on the lighthouse.
```

All username and password fields will default to root & default respectively if there were not specified in the command. If you try to run any commands before configuring light-man you'll be prompted to run configure first. This only needs to happen once if the lighthouse URL stays the same.

Latest version v0.1.2.

# Building light-man
Clone the git repo. Navigate to the repo, and run `make`. Copy the binary to somewhere in your $PATH. 
You'll [need Go installed](https://golang.org/doc/install) and your $GOPATH setup correctly to compile.

```
$ git clone git@github.com:fitzy101/light-man.git
Cloning into 'light-man'...
remote: Counting objects: 5, done.
remote: Compressing objects: 100% (4/4), done.
remote: Total 5 (delta 0), reused 5 (delta 0), pack-reused 0
Receiving objects: 100% (5/5), 5.70 KiB | 0 bytes/s, done.
Checking connectivity... done.
$ cd light-man
$ make
go get ./...
go build  -o light-man main.go
chmod +x light-man
$ ./light-man -c list
No config found, try running the 'configure' command first
```

## Examples

Usage:
```
$ light-man
Usage: light-man -c [COMMAND] [OPTIONS]...
        configure: set up light-man with your Lighthouse credentials
                -a: URL of the Lighthouse instance
                -u: user name for a Lighthouse user (default is 'root')
                -p: password for the Lighthouse user (default is 'default')
        add: add a new node to the Lighthouse
                -a: FQDN or IP Address of the node
                -u: user name for a Lighthouse user (default is 'root')
                -p: password for the Lighthouse user (default is 'default')
                -n: name of the node to add
                -no: indicates the node should NOT be auto-approved on enrollment
        list: list all nodes on the Lighthouse
                -g: the name of a smartgroup to filter the list command
        delete: delete a node from the Lighthouse
                -i: the identifier for a node - find with the list command
        delete-all: delete all nodes from the Lighthouse
		-g: the name of a smartgroup to filter the command
        shell: get a port manager shell on the Lighthouse
```

Unconfigured use of light-man:
```
$ light-man -c list
No config found, try running the 'configure' command first
```

Configure
```
$ light-man -c configure -a https://lh.fitzysite.com
config saved to /home/fitzy/.oglh
$ cat ~/.oglh
lighthouse_configuration:
  lighthouse: https://lh.fitzysite.com
  user: root
  password: default
```

List
```
$ light-man -c list
ID              Name            Model           Status          LHVPN.Address   FW.Version      Conn.Status     Errors
nodes-2         im7208-2-dac-lr IM7208-2-DAC-LR Enrolled        192.168.128.2   devbuild        connected
nodes-3         cm7148-2        CM7148-2        Enrolled        192.168.128.3   devbuild        connected
nodes-6         acm5508-2       ACM5508-2       Enrolled        192.168.128.6   devbuild        connected
nodes-8         imx4208         IMX4208         Enrolled        192.168.128.8   devbuild        connected
nodes-9         nodes-9         CM7196A-2       Enrolled        192.168.128.4   CI-1180         connected
nodes-10        nodes-10        ACM7004-5-LMR   Enrolled        192.168.128.5   4.1.0           connected
```

List (filtered by a smart group)
```
ID              Name            Model           Status          LHVPN.Address   FW.Version      Conn.Status     Errors
nodes-9         nodes-9         CM7196A-2       Enrolled        192.168.128.4   CI-1180         connected
nodes-10        nodes-10        ACM7004-5-LMR   Enrolled        192.168.128.5   4.1.0           connected
```

Add
```
$ light-man -c add -a 10.100.1.1 -n im7208
Node added successfully
$ light-man -c list
ID      Name    Model           Status          LHVPN.Address   FW.Version      Conn.Status     Errors
nodes-1 acm7004 ACM7004-5-LMR   Enrolled        192.168.128.2   devbuild        connected
nodes-2 cm7148  CM7148-2-DAC    Enrolled        192.168.128.3   devbuild        connected
nodes-3 cm7196  CM7196A-2-DAC   Enrolled        192.168.128.4   devbuild        connected
nodes-6 im7208                  Registering     192.168.128.5                   never seen
```

Delete
```
$ light-man -c delete -i nodes-6
Node deletion process started
```

Delete All
```
$ light-man -c delete-all
Node deletion process started for 4 node(s)
```

Delete All (filtered by a smart group)
```
$ light-man -c delete-all -g not-devbuild
Node deletion process started for 2 node(s)
```


Shell
```
$ light-man -c shell
 
 1: acm7004-master 
                   
 
Connect to remote > 1
 
10: im720
 
Connect to port > ^CShell session completed
```

## TODO
- Implement 'approve' to approve a node.
- Persist session tokens until they've timed out.
- Add support for third party nodes in the add command.
 
## Known issues
Please report any issues that you come across.

# License
light-man is licensed under the MIT license.
