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

Asciisizemax:	con big (256*1024);

dflag: int;
rflag: int;

stop := 0;
in: ref Iobuf;		# control input
out: ref Sys->FD;	# control output
datatype := "ascii";	# type, "ascii" or "image"
retroff := big 0;	# offset of next "get"
renamefrom: string;	# source file for next rename
user: string;		# user we are running as
epsvonly := 0;		# only epsv accepted for data channel

datadialaddr: string;	# client address, to dial for data commands
dataannounce: ref Sys->Connection;	# local connection, client dials this for data commands
datafd: ref Sys->FD;	# connection to client
datapid := -1;		# prog doing i/o on datafd

cmdc: chan of (string, string, string);
donec: chan of string;

dialc: chan of (string, chan of (ref Sys->FD, string));
announcec: chan of (string, chan of (ref Sys->Connection, int, string));
listenc: chan of (Sys->Connection, chan of (ref Sys->FD, string));
netpid := -1;

localip: IPaddr;
remoteip: IPaddr;

datacmds := array[] of {
"stor", "stou", "retr", "list", "nlst", "appe", "mlsd",
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
	ufd := sys->open("/dev/user", Sys->OREAD);
	if(ufd != nil) {
		n := sys->read(ufd, buf := array[128] of byte, len buf);
		if(n >= 0)
			user = string buf[:n];
	}
	ufd = nil;

	sys->pctl(Sys->FORKNS|Sys->NODEVS, nil);
	if(root != nil && sys->bind(root, "/", Sys->MREPL) < 0)
		fail(sprint("bind %q /: %r", root));
	if(sys->chdir("/") < 0)
		fail(sprint("chdir /: %r"));

	in = bufio->fopen(sys->fildes(0), Bufio->OREAD);
	out = sys->fildes(1);

	cmdc = chan of (string, string, string);
	donec = chan of string;
	spawn cmdreader();

	write("220 ip/ftpsrv ready, welcome");

	while(!stop) alt {
	(cmd, args, rerr) := <-cmdc =>
		if(rerr != nil) {
			say("read cmd: "+rerr);
			stop = 1;
			break;
		}
		docmd(cmd, args);

	s := <-donec =>
		datafd = nil;
		datapid = -1;
		write(s);
	}
	kill(netpid);
}

net(pidc: chan of int)
{
	pidc <-= pid();

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
	datadialaddr = nil;
	dataannounce = nil;
}

cmdreader()
{
	for(;;) {
		l := in.gets('\n');
		if(l == nil) {
			cmdc <-= (nil, nil, "eof");
			return;
		}
		if(len l == 1 || l[len l-2] != '\r') {
			cmdc <-= (nil, nil, "missing carriage return before newline");  # or should we read up to read newline?
			return;
		}
		l = l[:len l-2];
		say("> "+l);
		(cmd, args) := str->splitstrl(l, " ");
		if(args != nil)
			args = args[1:];
		cmdc <-= (cmd, args, nil);
	}
}

iscmd(a: array of string, cmd: string): int
{
	for(i := 0; i < len a; i++)
		if(a[i] == cmd)
			return 1;
	return 0;
}

waitdone()
{
	s := <-donec;
	datapid = -1;
	datafd = nil;
	write(s);
}

connect(rc: chan of (ref Sys->FD, string), pidc: chan of int)
{
	pidc <-= pid();

	fd: ref Sys->FD;
	err: string;
	if(datadialaddr != nil)
		(fd, err) = netdial(datadialaddr);
	else if(dataannounce != nil)
		(fd, err) = netlisten(*dataannounce);
	else
		err = "no connection parameters set";
	rc <-= (fd, err);
}

docmd(cmd, args: string)
{
	cmd = str->tolower(cmd);

	if(datapid >= 0 && !iscmd(busycmds, cmd)) {
		waitdone();
		netclear();
	}

	if(iscmd(datacmds, cmd)) {
		write("150 connecting...");

		rc := chan of (ref Sys->FD, string);
		spawn connect(rc, pidc := chan of int);
		cpid := <-pidc;

		derr: string;
		alt {
		(datafd, derr) = <-rc =>
			if(derr != nil)
				return write("425 "+derr);
		(ncmd, nil, err) := <-cmdc =>
			if(err != nil) {
				say("read cmd error during connect: "+err);
				stop = 1;
				return;
			}
			if(str->tolower(ncmd) == "abor") {
				kill(cpid);
				return write("420 interrupted during connect");
			}
			return write(sprint("420 interrupted with non-abort command %#q during connect, new command dropped", ncmd));
		}
		say("connected to remote");
	}

	if(epsvonly)
		case cmd {
		"port" or
		"eprt" or
		"pasv" =>
			return write("520 only epsv allowed now");
		}

	case cmd {
	# login
	"user" or
	"pass" or
	"acct" =>
		write("230 anonymous login ok, no password/account info needed");
	"cwd" =>
		if(sys->chdir(args) < 0)
			write(sprint("550 CWD failed: %r"));
		else
			write(sprint("200 %q", cwd()));
	"cdup" =>
		if(sys->chdir("..") < 0)
			write(sprint("550 CDUP failed: %r"));
		else
			write(sprint("200 %q", cwd()));

	# logout
	"rein" =>
		retroff = big 0;
		renamefrom = nil;
		if(datapid >= 0)
			waitdone();
		write("200 ok");
		datatype = "ascii";
	"quit" =>
		stop = 1;
		if(datapid >= 0)
			waitdone();
		write("221 bye");

	# transfer params
	"port" or
	"eprt" =>
		netclear();

		(ips, port, err) := parsehostport(args, cmd);
		if(err != nil) {
			write(err);
		} else if(ips != remoteip.text()) {
			write(sprint("521 not your ip, %s != %s", ips, remoteip.text()));
		} else {
			datadialaddr = sprint("tcp!%s!%d", ips, port);
			write("200 ok");
		}
	"pasv" or
	"epsv" =>
		netclear();

		if(cmd == "pasv" && !localip.isv4())
			return write("520 non-ipv4 not supported in PASV");

		if(cmd == "epsv" && args != nil) {
			if(str->tolower(args) == "all") {
				epsvonly = 1;
				# xxx should this be all we do?
				return write("200 ok");
			} else {
				(v, rem) := str->toint(args, 10);
				if(rem != nil)
					return write(sprint("500 bad epsv parameter %#q", args));
				if(v == 1 && !remoteip.isv4())
					return write("520 mismatch requested and used address family");
				if(v == 2 && remoteip.isv4())
					return write("520 mismatch requested and used addres family");
				if(v != 1 && v != 2)
					return write("520 unsupported address family");
			}
		}

		lport: int;
		err: string;
		addr := sprint("net!%s!0", localip.text());
		(dataannounce, lport, err) = netannounce(addr);
		if(err != nil) {
			write("521 announce failed: "+err);
		} else {
			case cmd {
			"pasv" =>
				v := localip.v4();
				write(sprint("227 Entering Passive Mode (%d,%d,%d,%d,%d,%d).",
					int v[0], int v[1], int v[2], int v[3], (lport>>8)&255, (lport>>0)&255));
			"epsv" =>
				write(sprint("229 Entering Extended Passive Mode (|||%d|)", lport));
			}
		}
	"mode" =>
		case str->tolower(args) {
		"s" =>	write("200 ok");
		"b" =>	write("504 block mode not supported");
		"c" =>	write("504 compressed mode not supported");
		* =>	write(sprint("504 unrecognized mode %#q", args));
		}
	"type" =>
		case str->tolower(args) {
		"a" or
		"a n" =>
			datatype = "ascii";
			write("200 ok");
		"i" =>
			datatype = "image";
			write("200 ok");
		"e" or
		"e n" or
		"e t" or
		"e c" =>
			write("504 type ebcdic not supported");
		"a t" or
		"a c" =>
			write("504 type ascii with 'telnet effectors'/'carriage control (asa)' not supported");
		* =>
			write(sprint("504 unrecognized mode %#q", args));
		}
	"stru" =>
		case str->tolower(args) {
		"f" =>	write("200 ok");
		"r" =>	write("504 record structure not supported");
		"p" =>	write("504 page structure not supported");
		* =>	write(sprint("504 unrecognized structure %#q", args));
		}

	# file actions
	"allo" =>
		write("202 try me");
	"rest" =>
		rem: string;
		(retroff, rem) = str->tobig(args, 10);
		if(rem != nil) {
			retroff = big 0;
			return write(sprint("501 bad offset %#q", args));
		} else
			write("350 ok");
	"stor" =>
		spawn ftpstor(args, pidc := chan of int);
		datapid = <-pidc;
	"stou" =>
		spawn ftpstou(args, pidc := chan of int);
		datapid = <-pidc;
	"retr" =>
		spawn ftpretr(args, datatype == "ascii", pidc := chan of int);
		datapid = <-pidc;
	"list" =>
		spawn ftplist(args, pidc := chan of int);
		datapid = <-pidc;
	"nlst" =>
		spawn ftpnlst(args, pidc := chan of int);
		datapid = <-pidc;
	"appe" =>
		spawn ftpappe(args, pidc := chan of int);
		datapid = <-pidc;
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
				return write(sprint("550 rename: %r"));
			write("200 ok");
			renamefrom = nil;
		}
	"dele" or
	"rmd" =>
		if(sys->remove(args) < 0)
			write(sprint("550 remove failed: %r"));
		else
			write("250 ok");
	"mkd" =>
		if(sys->create(args, Sys->OREAD, 8r777|Sys->DMDIR) != nil)
			write(sprint("550 mkdir failed: %r"));
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
		write("211 see rfc959,rfc2428,rfc3659");

	# misc
	"site" =>
		write("502 SITE not implemented");
	"noop" =>
		write("200 ok");

	# extensions
	"mdtm" or
	"size" =>
		if(args == nil)
			return write("501 need a path");
		(ok, dir) := sys->stat(args);
		if(ok < 0)
			return write(sprint("550 stat %q: %r", args));
		case cmd {
		"mdtm" =>
			write(sprint("213 %s", mdtmstr(dir.mtime)));
		"size" =>
			length := dir.length;
			err: string;
			if(datatype == "ascii")
				(length, err) = asciisize(args, length);
			if(err != nil)
				return write("550 "+err);
			write(sprint("213 %bd", length));
		}
	"mlst" =>
		if(args == nil)
			args = cwd();
		(ok, dir) := sys->stat(args);
		if(ok < 0)
			return write(sprint("550 stat %q: %r", args));
		writemulti("250", list of {
			"begin",
			mlst(cwd(), args, dir),
			"end",
		});
	"mlsd" =>
		if(args == nil)
			args = cwd();
		spawn ftpmlsd(args, pidc := chan of int);
		datapid = <-pidc;
	"feat" =>
		writemulti("211", list of {
			"features",
			"MDTM",
			"SIZE",
			"REST STREAM",
			"MLST type*;size*;modify*;perm*;",
			"UTF8",
			"end",
		});
	"opts" =>
		case args {
		* =>
			write(sprint("504 no options for %#q", args));
		}

	# all else unsupported
	* =>
		write(sprint("502 %s not implemented", str->toupper(cmd)));
	}
}

done(s: string)
{
	donec <-= s;
}

ftpstor(args: string, pidc: chan of int)
{
	pidc <-= pid();

	fd := sys->create(args, Sys->OWRITE|Sys->OTRUNC, 8r666);
	if(fd == nil)
		return done(sprint("451 create %q: %r", args));
	buf := array[Sys->ATOMICIO] of byte;
	for(;;) {
		n := sys->read(datafd, buf, len buf);
		if(n < 0)
			return done(sprint("451 read: %r"));
		if(n == 0)
			break;
		if(sys->write(fd, buf, n) != n)
			return done(sprint("451 write: %r"));
	}
	return done("226 done");
}

ftpstou(args: string, pidc: chan of int)
{
	pidc <-= pid();

	fbuf := random->randombuf(Random->NotQuiteRandom, 10);
	f := base16->enc(fbuf);
	fd := sys->create(args, Sys->OWRITE|Sys->OEXCL, 8r666);
	if(fd == nil)
		return done(sprint("451 create %q: %r", f));
	buf := array[Sys->ATOMICIO] of byte;
	for(;;) {
		n := sys->read(datafd, buf, len buf);
		if(n < 0)
			return done(sprint("451 read: %r"));
		if(n == 0)
			break;
		if(sys->write(fd, buf, n) != n)
			return done(sprint("451 write: %r"));
	}
	return done(sprint("226 %q created", f));
}

ftpappe(args: string, pidc: chan of int)
{
	pidc <-= pid();

	fd := sys->create(args, Sys->OWRITE|Sys->OEXCL, 8r666);
	if(fd == nil)
		fd = sys->open(args, Sys->OWRITE);
	if(fd == nil)
		return done(sprint("451 open %q: %r", args));
	sys->seek(fd, big 0, Sys->SEEKEND);
	buf := array[Sys->ATOMICIO] of byte;
	for(;;) {
		n := sys->read(datafd, buf, len buf);
		if(n < 0)
			return done(sprint("451 read: %r"));
		if(n == 0)
			break;
		if(sys->write(fd, buf, n) != n)
			return done(sprint("451 write: %r"));
	}
	return done("226 done");
}

ftpretr(args: string, ascii: int, pidc: chan of int)
{
	pidc <-= pid();

	fd := sys->open(args, Sys->OREAD);
	if(fd == nil)
		return done(sprint("451 open %q: %r", args));
	sys->seek(fd, retroff, Sys->SEEKSTART);
	retroff = big 0;
	buf := array[Sys->ATOMICIO] of byte;
	if(ascii)
		b := bufio->fopen(sys->fildes(1), Bufio->OWRITE);
	for(;;) {
		n := sys->read(fd, buf, len buf);
		if(n < 0)
			return done(sprint("451 read: %r"));
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
				return done(sprint("451 write: %r"));
		}
	}
	if(ascii && b.flush() == Bufio->ERROR)
		return done(sprint("451 write: %r"));
	return done("226 done");
}

ftplist(args: string, pidc: chan of int)
{
	pidc <-= pid();

	if(args == nil)
		args = cwd();
	if(args == nil)
		return done("451 cannot find cwd");
	(ok, dir) := sys->stat(args);
	if(ok < 0)
		return done(sprint("451 stat %q: %r", args));

	now := daytime->now();
	isdir := dir.mode & Sys->DMDIR;
	if(!isdir) {
		if(sys->fprint(datafd, "%s\r\n", liststr(now, dir)) < 0)
			return done(sprint("451 write: %r"));
		return done("226 done");
	}

	fd := sys->open(args, Sys->OREAD);
	if(fd == nil)
		return done(sprint("451 open %q: %r", args));
	b := bufio->fopen(datafd, Bufio->OWRITE);
	for(;;) {
		(n, d) := sys->dirread(fd);
		if(n < 0)
			return done(sprint("451 dirread: %r"));
		if(n == 0)
			break;
		for(i := 0; i < n; i++)
			b.puts(liststr(now, d[i])+"\r\n");
	}
	b.flush();
	return done("226 done");
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

ftpnlst(args: string, pidc: chan of int)
{
	pidc <-= pid();

	if(args == nil)
		args = cwd();
	fd := sys->open(args, Sys->OREAD);
	if(fd == nil)
		return done(sprint("451 open %q: %r", args));
	b := bufio->fopen(datafd, Bufio->OWRITE);
	for(;;) {
		(n, d) := sys->dirread(fd);
		if(n < 0)
			return done(sprint("451 dirread: %r"));
		if(n == 0)
			break;
		for(i := 0; i < n; i++) {
			b.puts(d[i].name);
			b.puts("\r\n");
		}
	}
	if(b.flush() == Bufio->ERROR)
		return done(sprint("451 write: %r"));
	return done("226 done");
}

ftpmlsd(args: string, pidc: chan of int)
{
	pidc <-= pid();

	fd := sys->open(args, Sys->OREAD);
	if(fd == nil)
		return done(sprint("451 open %q: %r", args));

	c := cwd();
	b := bufio->fopen(datafd, Bufio->OWRITE);
	for(;;) {
		(n, d) := sys->dirread(fd);
		if(n < 0)
			return done(sprint("451 dirread: %r"));
		if(n == 0)
			break;
		for(i := 0; i < n; i++) {
			b.puts(mlst(c, args+"/"+d[i].name, d[i]));
			b.puts("\r\n");
		}
	}
	if(b.flush() == Bufio->ERROR)
		return done(sprint("451 write: %r"));
	return done("226 done");
}

mdtmstr(t: int): string
{
	tm := daytime->local(t);
	return sprint("%04d%02d%02d%02d%02d%02d", tm.year+1900, tm.mon+1, tm.mday, tm.hour, tm.min, tm.sec);
}

asciisize(p: string, length: big): (big, string)
{
	if(length > Asciisizemax)
		return (big -1, sprint("refusing to read through %bd (>%bd) bytes to count newlines", length, Asciisizemax));
	fd := sys->open(p, Sys->OREAD);
	if(fd == nil)
		return (big -1, sprint("open %q: %r", p));
	buf := array[Sys->ATOMICIO] of byte;
	size := big 0;
	for(;;) {
		n := sys->read(fd, buf, len buf);
		if(n < 0)
			return (big -1, sprint("read %q: %r", p));
		if(n == 0)
			break;
		for(i := 0; i < n; i++) {
			size++;
			if(buf[i] == byte '\n')
				size++;
		}
	}
	return (size, nil);
}

mlst(cwd, path: string, dir: Sys->Dir): string
{
	t := "file";
	if(dir.mode & Sys->DMDIR) {
		t = "dir";
		if(cwd == path)
			t = "cdir";
	}
	return sprint("type=%s;modify=%s;size=%bd;perm=%s; %s", t, mdtmstr(dir.mtime), dir.length, lstpermstr(dir), dir.name);
}

lstpermstr(dir: Sys->Dir): string
{
	mode := dir.mode&7;
	if(dir.uid == user)
		mode = dir.mode>>6;
	r := mode & 4;
	w := mode & 2;
	x := mode & 1;
	isdir := dir.mode & Sys->DMDIR;
	s := "";
	if(isdir) {
		if(w && x) s += "cmp";
		if(x) s += "e";
		if(r && x) s += "l";
	} else {
		if(w) s += "aw";
		if(r) s += "r";
	}
	return s;
}

parsehostport(s: string, cmd: string): (string, int, string)
{
	if(cmd == "pasv")
		return parsehostport0(s);
	return parsehostport1(s);
}

parsehostport0(s: string): (string, int, string)
{
	t := sys->tokenize(s, ",").t1;
	if(len t != 6)
		return (nil, 0, "501 not 4+2 values");
	v := array[6] of int;
	i := 0;
	for(; t != nil; t = tl t) {
		rem: string;
		(v[i], rem) = str->toint(hd t, 10);
		if(rem != nil || v[i] < 0 || v[i] > 255)
			return (nil, 0, sprint("501 bad value %#q, not number or too low/high", hd t));
		i++;
	}
	ips := sprint("%d.%d.%d.%d", v[0], v[1], v[2], v[3]);
	port := (v[4]<<8)|(v[5]<<0);
	return (ips, port, nil);
}

parsehostport1(s: string): (string, int, string)
{
	if(s == nil)
		return (nil, 0, "501 empty parameter");
	sep := s[0:1];
	af, addr, port: string;
	(af, s) = str->splitstrl(s[1:], sep);
	if(s == nil)
		return (nil, 0, "501 malformed parameter, after address family");
	(addr, s) = str->splitstrl(s[1:], sep);
	if(s == nil)
		return (nil, 0, "501 malformed parameter, after address");
	(port, s) = str->splitstrl(s[1:], sep);
	if(s == nil)
		return (nil, 0, "501 malformed parameter, after port");
	if(s != sep)
		return (nil, 0, "501 leftover text after parameter");
	(afn, rem) := str->toint(af, 10);
	if(rem != nil)
		return (nil, 0, sprint("501 bad address family %#q", af));
	if(afn != 1 && afn != 2)
		return (nil, 0, sprint("522 unsupported address family %d.  try (1,2)", afn));
	(ok, ipa) := IPaddr.parse(addr);
	if(ok < 0)
		return (nil, 0, sprint("501 bad ip address %#q", addr));
	portn: int;
	(portn, rem) = str->toint(port, 10);
	if(rem != nil)
		return (nil, 0, sprint("501 bad port %#q", port));
	return (ipa.text(), portn, nil);
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
	if(ok < 0)
		return (b, "bad address");
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

pid(): int
{
	return sys->pctl(0, nil);
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
