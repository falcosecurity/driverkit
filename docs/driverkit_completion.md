## driverkit completion

Generates completion scripts.

### Synopsis

Generates completion scripts for the following shells: bash, zsh, fish.

There are two ways to configure your bash shell to load completions for each session.

1. Source the completion script in your ~/.bashrc file

    echo 'source <(driverkit completion bash)' >> ~/.bashrc

2. Add the completion script to /etc/bash_completion.d/ directory

    driverkit completion bash > /etc/bash_completion.d/driverkit


```
driverkit completion (bash|zsh|fish|help) [flags]
```

### Options

```
  -h, --help   help for completion
```

### SEE ALSO

* [driverkit](driverkit.md)	 - A command line tool to build Falco kernel modules.

