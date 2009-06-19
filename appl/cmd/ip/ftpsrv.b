implement Ftpsrv;

include "sys.m";
	sys: Sys;
	sprint: import sys;
include "draw.m";
include "arg.m";
include "bufio.m";
	bufio: Bufio;
	Iobuf: import bufio;
include "string.m";
	str: String;
include "lists.m";
	lists: Lists;
include "workdir.m";
	workdir: Workdir;
include "ip.m";
	ip: IP;
	IPaddr: import ip;
include "daytime.m";
	daytime: Daytime;
include "keyring.m";
include "security.m";
	random: Random;
include "encoding.m";
	base16: Encoding;

Ftpsrv: module {
	init:	fn(nil: ref Draw->Context, args: list of string);
};

dflag: int;
rflag: int;

stop := 0;
in: ref Iobuf;		# control input
out: ref Sys->FD;	# control output
datatype := "ascii";	# type, "ascii" or "image"
retroff := big 0;	# offset of next "get"
renamefrom: string;	# source file for next rename

datadialaddr: string;	# client address, to dial for data commands
dataannounce: ref Sys->Connection;	# local connection, client dials this for data commands
datafd: ref Sys->FD;	# connection to client
datapid := -1;		# prog doing i/o on datafd

dialc: chan of (string, chan of (ref Sys->FD, string));
announcec: chan of (string, chan of (ref Sys->Connection, int, string));
listenc: chan of (Sys->Connection, chan of (ref Sys->FD, string));
netpid := -1;

localip: IPaddr;
remoteip: IPaddr;

datacmds := array[] of {
"stor", "stou", "retr", "list", "nlst", "appe",
};
busycmds := array[] of {
"rein", "quit", "abor",
};

init(nil: ref Draw->Context, argv: list of string)
{
	sys = load Sys Sys->PATH;
	arg := load Arg Arg->PATH;
	bufio = load Bufio Bufio->PATH;
	str = load String String->PATH;
	lists = load Lists Lists->PATH;
	workdir = load Workdir Workdir->PATH;
	ip = load IP IP->PATH;
	ip->init();
	daytime = load Daytime Daytime->PATH;
	random = load Random Random->PATH;
	base16 = load Encoding Encoding->BASE16PATH;

	arg->init(argv);
	arg->setusage(arg->progname()+" [-dr] [root]");
	while((c := arg->opt()) != 0)
		case c {
		'd' =>	dflag++;
		'r' =>	rflag++;
		* =>	arg->usage();
		}
	argv = arg->argv();
	if(len argv > 1)
		arg->usage();
	if(argv != nil)
		root := hd argv;

	# find local & remote ip
	netdata := sys->fd2path(sys->fildes(0));
	netdir := str->splitstrr(netdata, "/").t0;
	err: string;
	(localip, err) = readip(netdir+"local");
	if(err == nil)
		(remoteip, err) = readip(netdir+"remote");
	if(err != nil)
		fail("finding local/remote ip: "+err);

	# spawn net prog, before binding away access to /net
	dialc = chan of (string, chan of (ref Sys->FD, string));
	announcec = chan of (string, chan of (ref Sys->Connection, int, string));
	listenc = chan of (Sys->Connection, chan of (ref Sys->FD, string));
	spawn net(pidc := chan of int);
	netpid = <-pidc;

	if(rflag) {
		fd := sys->open("/dev/user", Sys->OWRITE);
		if(fd == nil || sys->fprint(fd, "none") < 0)
			fail(sprint("failed to change to user none: %r"));
	}

	sys->pctl(Sys->FORKNS|Sys->NODEVS, nil);
	if(root != nil && sys->bind(root, "/", Sys->MREPL) < 0)
		fail(sprint("bind %q /: %r", root));
	if(sys->chdir("/") < 0)
		fail(sprint("chdir /: %r"));

	in = bufio->fopen(sys->fildes(0), Bufio->OREAD);
	out = sys->fildes(1);
	write("220 ip/ftpsrv ready, welcome");
	while(!stop)
		docmd();
	kill(netpid);
}

net(pidc: chan of int)
{
	pidc <-= sys->pctl(0, nil);
	for(;;) alt {
	(addr, rc) := <-dialc =>
		say("net: dialing "+addr);
		(ok, c) := sys->dial(addr, nil);
		if(ok < 0)
			rc <-= (nil, sprint("%r"));
		else
			rc <-= (c.dfd, nil);

	(addr, rc) := <-announcec =>
		say("net: announcing");
		(ok, c) := sys->announce(addr);
		if(ok < 0) {
			rc <-= (nil, 0, sprint("%r"));
		} else {
			(lport, err) := getlport(c);
			if(err != nil)
				rc <-= (nil, lport, err);
			else
				rc <-= (ref c, lport, nil);
		}

	(ac, rc) := <-listenc =>
		(ok, c) := sys->listen(ac);
		if(ok < 0) {
			rc <-= (nil, sprint("listen: %r"));
		} else {
			fd := sys->open(c.dir+"/data", Sys->ORDWR);
			if(fd == nil)
				rc <-= (nil, sprint("open data: %r"));
			else
				rc <-= (fd, nil);
		}
	}
}

netannounce(addr: string): (ref Sys->Connection, int, string)
{
	respc := chan of (ref Sys->Connection, int, string);
	announcec <-= (addr, respc);
	return <-respc;
}

netlisten(c: Sys->Connection): (ref Sys->FD, string)
{
	respc := chan of (ref Sys->FD, string);
	listenc <-= (c, respc);
	return <-respc;
}

netdial(addr: string): (ref Sys->FD, string)
{
	respc := chan of (ref Sys->FD, string);
	dialc <-= (addr, respc);
	return <-respc;
}

netclear()
{
	datafd = nil;
	datadialaddr = nil;
	dataannounce = nil;
}

iscmd(a: array of string, cmd: string): int
{
	for(i := 0; i < len a; i++)
		if(a[i] == cmd)
			return 1;
	return 0;
}

docmd()
{
	(cmd, args) := read();
	cmd = str->tolower(cmd);

	if(datapid >= 0 && !iscmd(busycmds, cmd))
		return write("501 busy");

	if(iscmd(datacmds, cmd)) {
		# xxx should do this in background, possibly timeout, but at least accept abort commands
		write("150 connecting...");
		err: string;
		if(datadialaddr != nil)
			(datafd, err) = netdial(datadialaddr);
		else if(dataannounce != nil)
			(datafd, err) = netlisten(*dataannounce);
		else
			err = "no connection parameters set";
		if(err != nil)
			return write("425 no connection: "+err);
		say("connected to remote");
	}

	case cmd {
	# login
	"user" or
	"pass" or
	"acct" =>
		write("230 anonymous login ok, no password/account info needed");
	"cwd" =>
		if(sys->chdir(args) < 0)
			write(sprint("501 CWD failed: %r"));
		else
			write("200 ok");
	"cdup" =>
		if(sys->chdir("..") < 0)
			write(sprint("501 CDUP failed: %r"));
		else
			write("200 ok");

	# logout
	"rein" =>
		# xxx wait for data transfer to finish
		datatype = "ascii";
		write("200 ok");
	"quit" =>
		# xxx wait for data transfer to finish
		write("221 quiting");
		kill(netpid);
		stop = 1;
		return;

	# transfer params
	"port" =>
		netclear();

		(ips, port, err) := parsehostport(args);
		if(err != nil) {
			write("500 bad host-port: "+err);
		} else if(ips != remoteip.text()) {
			write(sprint("501 not your ip, %s != %s", ips, remoteip.text()));
		} else {
			datadialaddr = sprint("tcp!%s!%d", ips, port);
			write("200 ok");
		}
	"pasv" =>
		netclear();

		lport: int;
		err: string;
		addr := sprint("net!%s!0", localip.text());
		(dataannounce, lport, err) = netannounce(addr);
		if(err != nil) {
			write("501 announce failed: "+err);
		} else {
			v := localip.v4();
			write(sprint("227 Entering Passive Mode (%d,%d,%d,%d,%d,%d).",
				int v[0], int v[1], int v[2], int v[3], (lport>>8)&255, (lport>>0)&255));
		}
	"mode" =>
		case args {
		"S" =>	write("200 ok");
		"B" =>	write("501 block mode not supported");
		"C" =>	write("501 compressed mode not supported");
		* =>	write(sprint("501 unrecognized mode %#q", args));
		}
	"type" =>
		case args {
		"A" or
		"AN" =>
			datatype = "ascii";
			write("200 ok");
		"I" =>
			datatype = "image";
			write("200 ok");
		"E" or
		"EN" or
		"ET" or
		"EC" =>
			write("501 type ebcdic not supported");
		"AT" or
		"AC" =>
			write("501 type ascii with 'telnet effectors'/'carriage control (asa)' not supported");
		* =>
			write(sprint("501 unrecognized mode %#q", args));
		}
	"stru" =>
		case args {
		"F" =>	write("200 ok");
		"R" =>	write("501 record structure not supported");
		"P" =>	write("501 page structure not supported");
		* =>	write(sprint("501 unrecognized structure %#q", args));
		}

	# file actions
	"allo" =>
		write("200 try me");
	"rest" =>
		rem: string;
		(retroff, rem) = str->tobig(args, 10);
		if(rem != nil) {
			retroff = big 0;
			return write(sprint("501 bad offset %#q", args));
		} else
			write("200 ok");
	"stor" =>
		ftpstor(args);
	"stou" =>
		ftpstou(args);
	"retr" =>
		ftpretr(args, datatype == "ascii");
	"list" =>
		ftplist(args);
	"nlst" =>
		ftpnlst(args);
	"appe" =>
		ftpappe(args);
	"rnfr" =>
		renamefrom = args;
		if(args == nil)
			write("501 empty source path");
		else
			write("350 ok, waiting for RNTO");
	"rnto" =>
		if(renamefrom == nil) {
			write("501 no preceding RNFR");
		} else if(args == nil) {
			write("501 empty destination path");
		} else {
			df := str->splitstrl(renamefrom, "/").t0;
			dt := str->splitstrl(args, "/").t0;
			if(df != dt)
				return write(sprint("501 cannot rename files in different directories, %q is not %q", df, dt));
			name := args[len dt:];
			if(len name <= 1)
				return write("501 new file name must not be empty");
			dir := sys->nulldir;
			dir.name = name[1:];
			if(sys->wstat(renamefrom, dir) < 0)
				return write(sprint("501 rename: %r"));
			write("200 ok");
			renamefrom = nil;
		}
	"dele" or
	"rmd" =>
		if(sys->remove(args) < 0)
			write(sprint("501 remove failed: %r"));
		else
			write("250 ok");
	"mkd" =>
		if(sys->create(args, Sys->OREAD, 8r777|Sys->DMDIR) != nil)
			write(sprint("501 mkdir failed: %r"));
		else
			write("257 ok");
	"pwd" =>
		write(sprint("257 %s", cwd()));
	"abor" =>
		if(datapid >= 0)
			kill(datapid);
		datapid = -1;
		write("200 ok");

	# informational
	"syst" =>
		write("215 UNIX inferno ftpsrv");
	"stat" =>
		if(args == nil) {
			lines := list of {
			"ftpsrv status:",
			sprint("type: %s, form: nonprint, structure: file, mode: stream", datatype),
			};
			writemulti("211", lines);
		} else {
			(lines, err) := stat(args);
			if(err != nil)
				write(sprint("501 stat error: %s", err));
			else
				writemulti("211", lines);
		}
	"help" =>
		write("211 see rfc959");

	# misc
	"site" =>
		write("502 SITE not implemented");
	"noop" =>
		write("200 ok");

	# all else unsupported
	* =>
		write(sprint("502 %s not implemented", str->toupper(cmd)));
	}
}

ftpstor(args: string)
{
	fd := sys->create(args, Sys->OWRITE|Sys->OTRUNC, 8r666);
	if(fd == nil)
		return write(sprint("501 create %q: %r", args));
	buf := array[Sys->ATOMICIO] of byte;
	for(;;) {
		n := sys->read(datafd, buf, len buf);
		if(n < 0)
			return write(sprint("501 read: %r"));
		if(n == 0)
			break;
		if(sys->write(fd, buf, n) != n)
			return write(sprint("501 write: %r"));
	}
	datafd = nil;
	write("226 done");
}

ftpstou(args: string)
{
	fbuf := random->randombuf(Random->NotQuiteRandom, 10);
	f := base16->enc(fbuf);
	fd := sys->create(args, Sys->OWRITE|Sys->OEXCL, 8r666);
	if(fd == nil)
		return write(sprint("451 create %q: %r", f));
	buf := array[Sys->ATOMICIO] of byte;
	for(;;) {
		n := sys->read(datafd, buf, len buf);
		if(n < 0)
			return write(sprint("451 read: %r"));
		if(n == 0)
			break;
		if(sys->write(fd, buf, n) != n)
			return write(sprint("451 write: %r"));
	}
	datafd = nil;
	write(sprint("226 %q created", f));
}

ftpappe(args: string)
{
	fd := sys->create(args, Sys->OWRITE|Sys->OEXCL, 8r666);
	if(fd == nil)
		fd = sys->open(args, Sys->OWRITE);
	if(fd == nil)
		return write(sprint("451 open %q: %r", args));
	sys->seek(fd, big 0, Sys->SEEKEND);
	buf := array[Sys->ATOMICIO] of byte;
	for(;;) {
		n := sys->read(datafd, buf, len buf);
		if(n < 0)
			return write(sprint("451 read: %r"));
		if(n == 0)
			break;
		if(sys->write(fd, buf, n) != n)
			return write(sprint("451 write: %r"));
	}
	datafd = nil;
	write("226 done");
}

ftpretr(args: string, ascii: int)
{
	fd := sys->open(args, Sys->OREAD);
	if(fd == nil)
		return write(sprint("451 open %q: %r", args));
	sys->seek(fd, retroff, Sys->SEEKSTART);
	retroff = big 0;
	buf := array[Sys->ATOMICIO] of byte;
	if(ascii)
		b := bufio->fopen(sys->fildes(1), Bufio->OWRITE);
	for(;;) {
		n := sys->read(fd, buf, len buf);
		if(n < 0)
			return write(sprint("451 read: %r"));
		if(n == 0)
			break;
		if(ascii) {
			o := 0;
			for(i := 0; i < n; i++) {
				if(buf[i] == byte '\n') {
					if(i != o)
						b.write(buf[o:], i-o);
					b.putc('\r');
					b.putc('\n');
					o = i+1;
				}
			}
			if(o < n)
				b.write(buf[o:], n-o);
		} else {
			if(sys->write(datafd, buf, n) != n)
				return write(sprint("451 write: %r"));
		}
	}
	if(ascii && b.flush() == Bufio->ERROR)
		return write(sprint("451 write: %r"));
	datafd = nil;
	write("226 done");
}

ftplist(args: string)
{
	if(args == nil)
		args = cwd();
	if(args == nil)
		return write("451 cannot find cwd");
	(ok, dir) := sys->stat(args);
	if(ok < 0)
		return write(sprint("451 stat %q: %r", args));

	now := daytime->now();
	isdir := dir.mode & Sys->DMDIR;
	if(!isdir) {
		if(sys->fprint(datafd, "%s\r\n", liststr(now, dir)) < 0)
			return write(sprint("451 write: %r"));
		datafd = nil;
		return write("226 done");
	}

	fd := sys->open(args, Sys->OREAD);
	if(fd == nil)
		return write(sprint("451 open %q: %r", args));
	b := bufio->fopen(datafd, Bufio->OWRITE);
	for(;;) {
		(n, d) := sys->dirread(fd);
		if(n < 0)
			return write(sprint("451 dirread: %r"));
		if(n == 0)
			break;
		for(i := 0; i < n; i++)
			b.puts(liststr(now, d[i])+"\r\n");
	}
	b.flush();
	datafd = nil;
	write("226 done");
}

liststr(now: int, d: Sys->Dir): string
{
	return sprint("%s %4d %-5s %-5s %7bd %12s %s",
		permstr(d), 0, "none", "none", d.length, daytime->filet(now, d.mtime), d.name);
}

permstr(d: Sys->Dir): string
{
	s := "----------";
	if(d.mode & Sys->DMDIR)
		s[0] = 'd';
	j := 1;
	for(i := 2; i >= 0; i--) {
		v := d.mode>>(i*3);
		if(v & 4) s[j+0] = 'r';
		if(v & 2) s[j+1] = 'w';
		if(v & 1) s[j+2] = 'x';
		j += 3;
	}
	return s;
}

ftpnlst(args: string)
{
	if(args == nil)
		args = cwd();
	fd := sys->open(args, Sys->OREAD);
	if(fd == nil)
		return write(sprint("451 open %q: %r", args));
	b := bufio->fopen(datafd, Bufio->OWRITE);
	for(;;) {
		(n, d) := sys->dirread(fd);
		if(n < 0)
			return write(sprint("451 dirread: %r"));
		if(n == 0)
			break;
		for(i := 0; i < n; i++)
			b.puts(sprint("%s\r\n", d[i].name));
	}
	b.flush();
	datafd = nil;
}

parsehostport(s: string): (string, int, string)
{
	t := sys->tokenize(s, ",").t1;
	if(len t != 6)
		return (nil, 0, "not 4+2 values");
	v := array[6] of int;
	i := 0;
	for(; t != nil; t = tl t) {
		rem: string;
		(v[i], rem) = str->toint(hd t, 10);
		if(rem != nil || v[i] < 0 || v[i] > 255)
			return (nil, 0, sprint("bad value %#q, not number or too low/high", hd t));
		i++;
	}
	ips := sprint("%d.%d.%d.%d", v[0], v[1], v[2], v[3]);
	port := (v[4]<<8)|(v[5]<<0);
	return (ips, port, nil);
}

stat(path: string): (list of string, string)
{
	fd := sys->open(path, Sys->OREAD);
	if(fd == nil)
		return (nil, sprint("open %q: %r", path));
	now := daytime->now();
	l: list of string;
	for(;;) {
		(n, d) := sys->dirread(fd);
		if(n < 0)
			return (nil, sprint("dirread: %r"));
		if(n == 0)
			break;
		for(i := 0; i < n; i++)
			l = liststr(now, d[i])::l;
	}
	return (lists->reverse(l), nil);
}

read(): (string, string)
{
	l := in.gets('\n');
	if(l == nil)
		fail("eof");
	if(len l == 1 || l[len l-2] != '\r')
		fail("missing carriage return before newline");  # or should we read up to read newline?
	l = l[:len l-2];
	say("> "+l);
	(cmd, args) := str->splitstrl(l, " ");
	if(args != nil)
		args = args[1:];
	return (cmd, args);
}

write(s: string)
{
	say("< "+s);
	buf := array of byte (s+"\r\n");
	if(sys->write(out, buf, len buf) != len buf)
		fail(sprint("write: %r"));
}

writemulti(code: string, l: list of string)
{
	if(l == nil)
		return write(code);
	if(len l == 1)
		return write(sprint("%s %s", code, hd l));
	write(sprint("%s-%s", code, hd l));
	for(l = tl l; tl l != nil; l = tl l)
		write(sprint(" %s", hd l));
	write(sprint("%s %s", code, hd l));
}

readip(f: string): (IPaddr, string)
{
	b := ip->noaddr;
	fd := sys->open(f, Sys->OREAD);
	if(fd == nil)
		return (b, sprint("open %q: %r", f));
	n := sys->read(fd, buf := array[128] of byte, len buf);
	if(n < 0)
		return (b, sprint("read %q: %r", f));
	addr := string buf[:n];
	ips := str->splitstrl(addr, "!").t0;
	(ok, ipa) := IPaddr.parse(ips);
	if(ok < 0 || !ipa.isv4())
		return (b, "bad v4 address");
	return (ipa, nil);
}

getlport(c: Sys->Connection): (int, string)
{
	f := c.dir+"/local";
	fd := sys->open(f, Sys->OREAD);
	if(fd == nil)
		return (0, sprint("open laddr: %r"));
	n := sys->read(fd, buf := array[128] of byte, len buf);
	if(n <= 0)
		return (0, sprint("read laddr: %r"));
	addr := string buf[:n];
	if(addr != nil && addr[len addr-1] == '\n')
		addr = addr[:len addr-1];
	s := str->splitstrl(addr, "!").t1;
	if(s == nil)
		return (0, sprint("bad laddr %#q", addr));
	(port, rem) := str->toint(s[1:], 10);
	if(rem != nil)
		return (0, sprint("bad laddr %#q", addr));
	return (port, nil);
}

cwd(): string
{
	return workdir->init();
}

kill(pid: int)
{
	f := sprint("/prog/%d/ctl", pid);
	fd := sys->open(f, Sys->OWRITE);
	if(fd != nil)
		sys->fprint(fd, "kill");
}

warn(s: string)
{
	sys->fprint(sys->fildes(2), "%s\n", s);
}

say(s: string)
{
	if(dflag)
		warn(s);
}

fail(s: string)
{
	kill(netpid);
	kill(datapid);
	warn(s);
	raise "fail:"+s;
}
