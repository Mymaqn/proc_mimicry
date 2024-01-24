# proc_mimicry
C library to mimic other processes by modifying /proc entries

## What is it?
A small library created to hide itself by disguising itself as another binary than what is running.

The idea is you can spawn this with something like memfd_create and make it look like a legitimate binary in almost all senses.

The problem with memfd_create is that when you spawn a process with it forensics experts can easily grab the original binary by accessing the process' /proc/pid/exe file.

Using this library that would not be possible, as we can point /proc/self/exe to point to any other binary on the system.

The template.c file has a simple example of disguising itself as the binary `/bin/sh`

You can compile the template.c file and call it whatever you would like, and it still figures as /bin/sh inside of the proc filesystem.

This also means processes like `ps` will not list the original binary name but instead list `sh`

The following is an example of the binary figuring inside of multiple parts of the /proc filesystem before and after using proc_mimicry:

### Before:
#### /proc/self/stat
```
46957 (main) S  ... [truncated]
```

#### /proc/self/status
```
Name:   main
Umask: ... [truncated]
```

#### /proc/self/cmdline
```
./main
```

#### /proc/self/exe
```
> ls -alh /proc/46957/exe
lrwxrwxrwx 1 root root 0 Jan 24 23:53 /proc/46957/exe -> /root/proc_mimicry/main
```

#### /proc/self/fd
```
dr-x------ 2 root root  0 Jan 24 23:56 .
dr-xr-xr-x 9 root root  0 Jan 24 23:56 ..
lrwx------ 1 root root 64 Jan 25 00:01 0 -> /dev/pts/5
lrwx------ 1 root root 64 Jan 25 00:01 1 -> /dev/pts/5
lrwx------ 1 root root 64 Jan 25 00:01 2 -> /dev/pts/5
```


### After
#### /proc/self/stat
```
47385 (sh) S  ... [truncated]
```

#### /proc/self/status
```
Name:   sh
Umask: ... [truncated]
```

#### /proc/self/cmdline
```
sh
```

#### /proc/self/exe
```
sudo ls -alh /proc/47385/exe
lrwxrwxrwx 1 root root 0 Jan 24 23:56 /proc/47385/exe -> /usr/bin/dash
```

#### /proc/self/fd
```
dr-x------ 2 root root  0 Jan 24 23:56 .
dr-xr-xr-x 9 root root  0 Jan 24 23:56 ..
lrwx------ 1 root root 64 Jan 25 00:01 0 -> /dev/pts/5
lrwx------ 1 root root 64 Jan 25 00:01 1 -> /dev/pts/5
lrwx------ 1 root root 64 Jan 25 00:01 2 -> /dev/pts/5
```

The binary needs root permissions to be able to disguise itself, as changing these things require root privileges. It is not possible to disguise a binary without root privileges.

## How to use
The library depends on python3 to take care of placeholders inside of template.c, I'll gladly take a PR which fixes it in the compile script, so python is not needed.

Otherwise to use, you just modify template.c after the `//Your code goes here` into what you would like the binary to do.

Then compile using the compile.sh script.

A main.c file should be generated along with a main binary. To test if it works, run the main binary as root and check the aforementioned /proc files if they've been modified correctly.

The only thing that the binary does not modify is the /proc/pid/cwd file, however it can easily be changed by you, by just running a chdir.

## Q/A
Q: I segfault when I try running it, what is going on?
A: Usually it happens if you're running the binary as non-root or you're trying to disguise the process as another binary which does not exist.
  Unfortunately because of how this works, there is no good way of giving error prompts to the user. I would recommend debugging to find the error.
