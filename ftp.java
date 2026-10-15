import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.*;
 
public class FtpServer {
    private static final int PORT = 2121;
    private static final int MAX_FAILED_LOGINS = 3;
    private static final Map<String, String> USERS = new HashMap<>();
    private static Path root;
 
    private static synchronized void log(String msg) {
        System.out.println(msg);
    }
 
    // One Session object handles one connected client (runs in its own thread)
    static class Session implements Runnable {
        private final Socket ctl;
        private final String ip;
        private BufferedReader in;
        private BufferedWriter out;
        private String pendingUser, user, renameFrom;
        private int failures = 0;
        private Path cwd = root;
        private ServerSocket pasv;
        private InetSocketAddress active;
 
        Session(Socket s) {
            ctl = s;
            ip = s.getInetAddress().getHostAddress();
        }
 
        private void reply(String line) throws IOException {
            out.write(line + "\r\n");
            out.flush();
        }
 
        // Real path -> virtual path shown to the client (root is "/")
        private String vpath(Path p) {
            return "/" + root.relativize(p).toString().replace(File.separatorChar, '/');
        }
 
        // Virtual path -> real path; null if it would leave the root folder
        private Path resolve(String arg) {
            Path p = arg.startsWith("/") ? root.resolve(arg.substring(1)) : cwd.resolve(arg);
            p = p.normalize();
            return p.startsWith(root) ? p : null;
        }
 
        private boolean hasData() { return pasv != null || active != null; }
 
        private Socket openData() throws IOException {
            Socket d;
            if (pasv != null) {
                pasv.setSoTimeout(10000);
                d = pasv.accept();
                pasv.close();
                pasv = null;
            } else {
                d = new Socket();
                d.connect(active, 10000);
                active = null;
            }
            return d;
        }
 
        private void sendStream(InputStream src) throws IOException {
            if (!hasData()) { reply("425 Use PASV or PORT first."); return; }
            reply("150 Opening data connection.");
            try (Socket d = openData(); OutputStream os = d.getOutputStream()) {
                byte[] buf = new byte[8192];
                int n;
                while ((n = src.read(buf)) > 0) os.write(buf, 0, n);
            } catch (IOException e) {
                reply("426 Transfer aborted.");
                return;
            }
            reply("226 Transfer complete.");
        }
 
        private String listLine(Path p) throws IOException {
            boolean dir = Files.isDirectory(p);
            String date = new SimpleDateFormat("MMM dd HH:mm", Locale.ENGLISH)
                    .format(new Date(Files.getLastModifiedTime(p).toMillis()));
            return String.format("%s 1 ftp ftp %12d %s %s", dir ? "drwxr-xr-x" : "-rw-r--r--",
                    dir ? 4096 : Files.size(p), date, p.getFileName());
        }
 
        public void run() {
            try {
                in = new BufferedReader(new InputStreamReader(ctl.getInputStream(), StandardCharsets.UTF_8));
                out = new BufferedWriter(new OutputStreamWriter(ctl.getOutputStream(), StandardCharsets.UTF_8));
                ctl.setSoTimeout(300000);
                log("[" + ip + "] Client connected");
                reply("220 GCET FTP Server ready.");
                String line;
                while ((line = in.readLine()) != null) {
                    String cmd = line, arg = "";
                    int sp = line.indexOf(' ');
                    if (sp > 0) { cmd = line.substring(0, sp); arg = line.substring(sp + 1).trim(); }
                    cmd = cmd.toUpperCase();
                    log("[" + ip + "] " + (cmd.equals("PASS") ? "PASS ****" : line));
                    if (!handle(cmd, arg)) break;
                }
            } catch (SocketTimeoutException e) {
                try { reply("421 Timeout. Closing connection."); } catch (IOException ignored) { }
            } catch (IOException e) {
                log("[" + ip + "] Connection error: " + e.getMessage());
            } finally {
                try { if (pasv != null) pasv.close(); ctl.close(); } catch (IOException ignored) { }
                log("[" + ip + "] Client disconnected");
            }
        }
 
        // Returns false when the session must end
        private boolean handle(String cmd, String arg) throws IOException {
            switch (cmd) {
                case "USER":
                    pendingUser = arg; user = null;
                    reply("331 Password required for " + arg + ".");
                    return true;
                case "PASS": {
                    String pw = USERS.get(pendingUser);
                    if (pw != null && samePassword(pw, arg)) {
                        user = pendingUser;
                        reply("230 Login successful.");
                    } else {
                        pendingUser = null;
                        if (++failures >= MAX_FAILED_LOGINS) {
                            reply("421 Too many failed logins. Closing connection.");
                            return false;
                        }
                        reply("530 Login incorrect.");
                    }
                    return true;
                }
                case "QUIT": reply("221 Goodbye."); return false;
                case "NOOP": reply("200 OK."); return true;
                case "SYST": reply("215 UNIX Type: L8"); return true;
                case "FEAT": reply("211-Features:\r\n SIZE\r\n PASV\r\n211 End"); return true;
                default: break;
            }
            if (user == null) { reply("530 Please login with USER and PASS."); return true; }
 
            switch (cmd) {
                case "PWD": case "XPWD":
                    reply("257 \"" + vpath(cwd) + "\" is the current directory.");
                    break;
                case "CWD": case "CDUP": {
                    Path p = resolve(cmd.equals("CDUP") ? ".." : arg);
                    if (p != null && Files.isDirectory(p)) { cwd = p; reply("250 Directory changed to " + vpath(cwd)); }
                    else reply("550 Directory not found or access denied.");
                    break;
                }
                case "TYPE": reply("200 Type set to " + arg.toUpperCase() + "."); break;
                case "MODE": case "STRU": reply("200 OK."); break;
                case "PASV": {
                    if (pasv != null) pasv.close();
                    active = null;
                    InetAddress la = ctl.getLocalAddress();
                    pasv = new ServerSocket(0, 1, la);
                    int port = pasv.getLocalPort();
                    String h = la.getHostAddress().replace('.', ',');
                    reply("227 Entering Passive Mode (" + h + "," + (port / 256) + "," + (port % 256) + ").");
                    break;
                }
                case "PORT": {
                    String[] f = arg.split(",");
                    if (f.length != 6) { reply("501 Invalid PORT argument."); break; }
                    try {
                        String host = f[0] + "." + f[1] + "." + f[2] + "." + f[3];
                        int port = Integer.parseInt(f[4].trim()) * 256 + Integer.parseInt(f[5].trim());
                        InetAddress a = InetAddress.getByName(host);
                        if (!a.equals(ctl.getInetAddress())) { reply("504 PORT address must match the client address."); break; }
                        if (pasv != null) { pasv.close(); pasv = null; }
                        active = new InetSocketAddress(a, port);
                        reply("200 PORT command successful.");
                    } catch (NumberFormatException e) {
                        reply("501 Invalid PORT argument.");
                    }
                    break;
                }
                case "LIST": case "NLST": {
                    String target = arg.startsWith("-") ? "" : arg;
                    Path p = target.isEmpty() ? cwd : resolve(target);
                    if (p == null || !Files.exists(p)) { reply("550 No such file or directory."); break; }
                    List<Path> items = new ArrayList<>();
                    if (Files.isDirectory(p)) {
                        try (DirectoryStream<Path> ds = Files.newDirectoryStream(p)) { for (Path x : ds) items.add(x); }
                        Collections.sort(items);
                    } else items.add(p);
                    StringBuilder sb = new StringBuilder();
                    for (Path x : items)
                        sb.append(cmd.equals("LIST") ? listLine(x) : x.getFileName().toString()).append("\r\n");
                    sendStream(new ByteArrayInputStream(sb.toString().getBytes(StandardCharsets.UTF_8)));
                    break;
                }
                case "RETR": {
                    Path p = resolve(arg);
                    if (p == null || !Files.isRegularFile(p)) { reply("550 File not found."); break; }
                    try (InputStream is = Files.newInputStream(p)) { sendStream(is); }
                    break;
                }
                case "STOR": {
                    Path p = resolve(arg);
                    if (p == null || Files.isDirectory(p) || !Files.isDirectory(p.getParent())) {
                        reply("553 Cannot create file."); break;
                    }
                    if (!hasData()) { reply("425 Use PASV or PORT first."); break; }
                    reply("150 Ready to receive data.");
                    try (Socket d = openData(); InputStream is = d.getInputStream()) {
                        Files.copy(is, p, StandardCopyOption.REPLACE_EXISTING);
                    } catch (IOException e) {
                        reply("426 Transfer aborted."); break;
                    }
                    reply("226 Transfer complete.");
                    break;
                }
                case "SIZE": {
                    Path p = resolve(arg);
                    if (p != null && Files.isRegularFile(p)) reply("213 " + Files.size(p));
                    else reply("550 File not found.");
                    break;
                }
                case "DELE": {
                    Path p = resolve(arg);
                    if (p != null && Files.isRegularFile(p)) { Files.delete(p); reply("250 File deleted."); }
                    else reply("550 File not found.");
                    break;
                }
                case "MKD": case "XMKD": {
                    Path p = resolve(arg);
                    try {
                        if (p == null) throw new IOException();
                        Files.createDirectory(p);
                        reply("257 \"" + vpath(p) + "\" directory created.");
                    } catch (IOException e) { reply("550 Cannot create directory."); }
                    break;
                }
                case "RMD": case "XRMD": {
                    Path p = resolve(arg);
                    try {
                        if (p == null || p.equals(root) || !Files.isDirectory(p)) throw new IOException();
                        Files.delete(p);
                        reply("250 Directory removed.");
                    } catch (IOException e) { reply("550 Cannot remove directory (not empty or not found)."); }
                    break;
                }
                case "RNFR": {
                    Path p = resolve(arg);
                    if (p != null && !p.equals(root) && Files.exists(p)) { renameFrom = arg; reply("350 Ready for RNTO."); }
                    else reply("550 File not found.");
                    break;
                }
                case "RNTO": {
                    Path from = renameFrom == null ? null : resolve(renameFrom), to = resolve(arg);
                    renameFrom = null;
                    try {
                        if (from == null || to == null) throw new IOException();
                        Files.move(from, to);
                        reply("250 Rename successful.");
                    } catch (IOException e) { reply("550 Rename failed."); }
                    break;
                }
                default:
                    reply("502 Command not implemented.");
            }
            return true;
        }
    }
 
    // Constant-time comparison of two passwords
    private static boolean samePassword(String a, String b) {
        return java.security.MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }
 
    // ---------------- Demo client (run: java FtpServer demo) ----------------
    private static String readReply(BufferedReader in) throws IOException {
        String l = in.readLine();
        System.out.println("S: " + l);
        if (l != null && l.length() > 3 && l.charAt(3) == '-') {
            String code = l.substring(0, 3);
            while ((l = in.readLine()) != null) {
                System.out.println("S: " + l);
                if (l.startsWith(code + " ")) break;
            }
        }
        return l;
    }
 
    private static String send(BufferedReader in, BufferedWriter out, String cmd) throws IOException {
        out.write(cmd + "\r\n");
        out.flush();
        System.out.println("C: " + cmd);
        return readReply(in);
    }
 
    private static Socket openPassive(BufferedReader in, BufferedWriter out) throws IOException {
        String r = send(in, out, "PASV");
        String[] f = r.substring(r.indexOf('(') + 1, r.indexOf(')')).split(",");
        int port = Integer.parseInt(f[4]) * 256 + Integer.parseInt(f[5]);
        return new Socket(f[0] + "." + f[1] + "." + f[2] + "." + f[3], port);
    }
 
    private static void demo() throws Exception {
        try (Socket s = new Socket("localhost", PORT)) {
            BufferedReader in = new BufferedReader(new InputStreamReader(s.getInputStream(), StandardCharsets.UTF_8));
            BufferedWriter out = new BufferedWriter(new OutputStreamWriter(s.getOutputStream(), StandardCharsets.UTF_8));
            readReply(in);
            System.out.println("\n--- Test 1: Wrong password ---");
            send(in, out, "USER admin");
            send(in, out, "PASS wrongpass");
            System.out.println("\n--- Test 2: Command before login ---");
            send(in, out, "PWD");
            System.out.println("\n--- Test 3: Login and directories ---");
            send(in, out, "USER admin");
            send(in, out, "PASS admin123");
            send(in, out, "PWD");
            send(in, out, "MKD docs");
            send(in, out, "CWD docs");
            System.out.println("\n--- Test 4: Upload a file (STOR) ---");
            Socket d = openPassive(in, out);
            send(in, out, "STOR hello.txt");
            d.getOutputStream().write("Hello from the FTP client!\r\n".getBytes(StandardCharsets.UTF_8));
            d.close();
            readReply(in);
            System.out.println("\n--- Test 5: List files and file size ---");
            d = openPassive(in, out);
            send(in, out, "LIST");
            BufferedReader dr = new BufferedReader(new InputStreamReader(d.getInputStream(), StandardCharsets.UTF_8));
            String l;
            while ((l = dr.readLine()) != null) System.out.println("D: " + l);
            d.close();
            readReply(in);
            send(in, out, "SIZE hello.txt");
            System.out.println("\n--- Test 6: Download a file (RETR) ---");
            d = openPassive(in, out);
            send(in, out, "RETR hello.txt");
            dr = new BufferedReader(new InputStreamReader(d.getInputStream(), StandardCharsets.UTF_8));
            while ((l = dr.readLine()) != null) System.out.println("D: " + l);
            d.close();
            readReply(in);
            System.out.println("\n--- Test 7: Path traversal and missing file ---");
            send(in, out, "CWD ../../..");
            send(in, out, "RETR ../../secret.txt");
            send(in, out, "RETR missing.txt");
            System.out.println("\n--- Test 8: Rename, delete and clean up ---");
            send(in, out, "RNFR hello.txt");
            send(in, out, "RNTO notes.txt");
            send(in, out, "DELE notes.txt");
            send(in, out, "CWD /");
            send(in, out, "RMD docs");
            send(in, out, "QUIT");
        }
    }
 
    public static void main(String[] args) throws Exception {
        if (args.length > 0 && args[0].equals("demo")) { demo(); return; }
        root = Paths.get(args.length > 0 ? args[0] : "ftp_root").toAbsolutePath().normalize();
        Files.createDirectories(root);
        USERS.put("admin", "admin123");
        USERS.put("student", "gcet@123");
        ExecutorService pool = Executors.newCachedThreadPool();
        try (ServerSocket server = new ServerSocket(PORT)) {
            log("FTP server started on port " + PORT);
            log("Root directory : " + root);
            while (true) pool.execute(new Session(server.accept()));
        }
    }
}
